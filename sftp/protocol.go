package sftp

import (
	"encoding/binary"
	"fmt"
	"sync"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
)

// ChunkSize is the size of the data chunks transfers are pipelined in. The
// larger the chunk, the fewer requests, protocol frames and per-chunk syscalls
// a transfer needs for a given amount of data. 128 KiB keeps the per-byte
// overhead low while bounding the in-flight memory of the transfer window
// (TransferWindow × ChunkSize per direction).
const ChunkSize = 128 * 1024

// TransferWindow is the number of in-flight read/write requests the pipelined
// transfer loops keep queued. On links with non-trivial round-trip time this
// masks the per-chunk serialisation latency and dramatically improves
// throughput, especially for small chunks. A value of 32 is a good default;
// very high-latency links can benefit from larger values.
const TransferWindow = 32

// maxFrameSize caps the size of a single protocol frame. The protocol is
// length-prefixed so a corrupt or hostile stream could otherwise claim a
// 4 GiB frame and force a matching allocation; 64 MiB comfortably covers the
// largest legitimate frame (a listing of a very large directory) plus a data
// chunk.
const maxFrameSize = 64 << 20

// maxEntries caps the number of FileInfo entries a single ls response may
// carry. Every entry costs at least 37 bytes on the wire, so this bound is
// well within maxFrameSize; it exists so a corrupt length field cannot force a
// huge allocation before the frame contents are validated.
const maxEntries = 1 << 20

type Request struct {
	ID     uint64
	Cmd    string
	Path   string
	Offset int64
	Limit  int
	Data   []byte
}

type FileInfo struct {
	Name       string
	Size       int64
	Mode       uint32
	IsDir      bool
	IsSymlink  bool
	LinkTarget string
	ModTime    int64
	UID        uint32
	GID        uint32
	UserName   string
	GroupName  string
}

type Response struct {
	ID      uint64
	OK      bool
	Error   string
	Path    string
	Entries []FileInfo
	Data    []byte
	Info    *FileInfo
}

// The SFTP channel carries a compact binary protocol instead of JSON. Every
// logical message is one frame:
//
//	[4 bytes] frame length N (big-endian), the number of bytes that follow
//	[N bytes] message payload
//
// The length prefix makes frames self-delimiting, so a frame split across
// several channel data messages (channelImpl.WriteData fragments anything
// larger than the negotiated maximum packet size) is reassembled by the
// receiver without parsing. Request and response payloads use fixed-width
// big-endian integers and length-prefixed strings; file data is carried as
// raw bytes. Compared with the previous JSON encoding this removes the base64
// expansion of data chunks (a 33% wire overhead on transfers), the JSON field
// names and escaping, and the marshal/unmarshal CPU cost on every chunk.
//
// Request payload:
//
//	[1 byte]  command code
//	[8 bytes] request ID
//	[2 bytes] path length, then the path bytes
//	[8 bytes] offset (int64)
//	[4 bytes] limit (uint32)
//	[4 bytes] data length, then the raw data bytes
//
// Response payload:
//
//	[8 bytes] request ID
//	[1 byte]  ok (0/1)
//	[2 bytes] error length, then the error bytes
//	[2 bytes] path length, then the path bytes
//	[4 bytes] entry count, then that many FileInfo records
//	[4 bytes] data length, then the raw data bytes
//	[1 byte]  has info (0/1), then a FileInfo record when set
//
// FileInfo record:
//
//	[2 bytes] name length, then the name
//	[8 bytes] size (int64)
//	[4 bytes] mode (uint32)
//	[1 byte]  flags: bit 0 = directory, bit 1 = symlink
//	[2 bytes] link target length, then the link target
//	[8 bytes] modification time (int64, Unix seconds)
//	[4 bytes] uid
//	[4 bytes] gid
//	[2 bytes] user name length, then the user name
//	[2 bytes] group name length, then the group name

// Command codes for the binary request format.
const (
	cmdPwd byte = iota + 1
	cmdCd
	cmdLs
	cmdStat
	cmdGet
	cmdPut
	cmdMkdir
	cmdRm
	cmdRmdir
)

func cmdCode(cmd string) byte {
	switch cmd {
	case "pwd":
		return cmdPwd
	case "cd":
		return cmdCd
	case "ls":
		return cmdLs
	case "stat":
		return cmdStat
	case "get":
		return cmdGet
	case "put":
		return cmdPut
	case "mkdir":
		return cmdMkdir
	case "rm":
		return cmdRm
	case "rmdir":
		return cmdRmdir
	}
	return 0
}

func cmdName(code byte) string {
	switch code {
	case cmdPwd:
		return "pwd"
	case cmdCd:
		return "cd"
	case cmdLs:
		return "ls"
	case cmdStat:
		return "stat"
	case cmdGet:
		return "get"
	case cmdPut:
		return "put"
	case cmdMkdir:
		return "mkdir"
	case cmdRm:
		return "rm"
	case cmdRmdir:
		return "rmdir"
	}
	return ""
}

// --- Frame encoding ---

func appendU8(b []byte, v byte) []byte    { return append(b, v) }
func appendU16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func appendU32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }
func appendU64(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }
func appendI64(b []byte, v int64) []byte  { return binary.BigEndian.AppendUint64(b, uint64(v)) }
func appendStr(b []byte, s string) []byte {
	b = appendU16(b, uint16(len(s)))
	return append(b, s...)
}
func appendBytes(b []byte, p []byte) []byte {
	b = appendU32(b, uint32(len(p)))
	return append(b, p...)
}

// EncodeRequest serializes req into a complete binary frame: a 4-byte
// big-endian length prefix followed by the payload.
func EncodeRequest(req *Request) []byte {
	size := 4 + 1 + 8 + 2 + len(req.Path) + 8 + 4 + 4 + len(req.Data)
	buf := make([]byte, 4, size)
	return encodeRequestFrameInto(buf, req)
}

func encodeRequestFrameInto(buf []byte, req *Request) []byte {
	buf = appendU8(buf, cmdCode(req.Cmd))
	buf = appendU64(buf, req.ID)
	buf = appendStr(buf, req.Path)
	buf = appendI64(buf, req.Offset)
	buf = appendU32(buf, uint32(req.Limit))
	buf = appendBytes(buf, req.Data)
	binary.BigEndian.PutUint32(buf, uint32(len(buf)-4))
	return buf
}

// EncodeResponse serializes resp into a complete binary frame: a 4-byte
// big-endian length prefix followed by the payload.
func EncodeResponse(resp *Response) []byte {
	buf := make([]byte, 4, responseFrameSize(resp))
	return encodeResponseFrameInto(buf, resp)
}

func responseFrameSize(resp *Response) int {
	size := 4 + 8 + 1 + 2 + len(resp.Error) + 2 + len(resp.Path) + 4 + 4 + len(resp.Data) + 1
	for i := range resp.Entries {
		size += fileInfoFrameSize(&resp.Entries[i])
	}
	if resp.Info != nil {
		size += fileInfoFrameSize(resp.Info)
	}
	return size
}

func fileInfoFrameSize(e *FileInfo) int {
	return 2 + len(e.Name) + 8 + 4 + 1 + 2 + len(e.LinkTarget) + 8 + 4 + 4 + 2 + len(e.UserName) + 2 + len(e.GroupName)
}

func encodeResponseFrameInto(buf []byte, resp *Response) []byte {
	buf = appendU64(buf, resp.ID)
	if resp.OK {
		buf = appendU8(buf, 1)
	} else {
		buf = appendU8(buf, 0)
	}
	buf = appendStr(buf, resp.Error)
	buf = appendStr(buf, resp.Path)
	buf = appendU32(buf, uint32(len(resp.Entries)))
	for i := range resp.Entries {
		buf = encodeFileInfoInto(buf, &resp.Entries[i])
	}
	buf = appendBytes(buf, resp.Data)
	if resp.Info != nil {
		buf = appendU8(buf, 1)
		buf = encodeFileInfoInto(buf, resp.Info)
	} else {
		buf = appendU8(buf, 0)
	}
	binary.BigEndian.PutUint32(buf, uint32(len(buf)-4))
	return buf
}

func encodeFileInfoInto(buf []byte, e *FileInfo) []byte {
	buf = appendStr(buf, e.Name)
	buf = appendI64(buf, e.Size)
	buf = appendU32(buf, e.Mode)
	var flags byte
	if e.IsDir {
		flags |= 1
	}
	if e.IsSymlink {
		flags |= 2
	}
	buf = appendU8(buf, flags)
	buf = appendStr(buf, e.LinkTarget)
	buf = appendI64(buf, e.ModTime)
	buf = appendU32(buf, e.UID)
	buf = appendU32(buf, e.GID)
	buf = appendStr(buf, e.UserName)
	buf = appendStr(buf, e.GroupName)
	return buf
}

// --- Frame decoding ---

// frameCursor walks a frame payload. String fields are copied out of the
// frame; byte slices (the Data fields) alias the frame, which is safe because
// a fresh frame is allocated for every received message and the decoded data
// is consumed before the next message is read.
type frameCursor struct {
	b   []byte
	pos int
}

func (c *frameCursor) take(n int) ([]byte, error) {
	if n < 0 || c.pos+n > len(c.b) {
		return nil, fmt.Errorf("sftp: truncated frame")
	}
	s := c.b[c.pos : c.pos+n]
	c.pos += n
	return s, nil
}

func (c *frameCursor) u8() (byte, error) {
	s, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return s[0], nil
}

func (c *frameCursor) u16() (uint16, error) {
	s, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(s), nil
}

func (c *frameCursor) u32() (uint32, error) {
	s, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(s), nil
}

func (c *frameCursor) u64() (uint64, error) {
	s, err := c.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(s), nil
}

func (c *frameCursor) i64() (int64, error) {
	v, err := c.u64()
	return int64(v), err
}

func (c *frameCursor) str() (string, error) {
	n, err := c.u16()
	if err != nil {
		return "", err
	}
	s, err := c.take(int(n))
	if err != nil {
		return "", err
	}
	return string(s), nil
}

// bytes returns the next length-prefixed byte slice, aliasing the frame.
func (c *frameCursor) bytes() ([]byte, error) {
	n, err := c.u32()
	if err != nil {
		return nil, err
	}
	return c.take(int(n))
}

// DecodeRequest deserializes a request frame into req. The Data field aliases
// payload and stays valid for the lifetime of payload.
func DecodeRequest(payload []byte, req *Request) error {
	c := &frameCursor{b: payload}
	code, err := c.u8()
	if err != nil {
		return err
	}
	if req.ID, err = c.u64(); err != nil {
		return err
	}
	if req.Path, err = c.str(); err != nil {
		return err
	}
	if req.Offset, err = c.i64(); err != nil {
		return err
	}
	limit, err := c.u32()
	if err != nil {
		return err
	}
	req.Limit = int(limit)
	if req.Data, err = c.bytes(); err != nil {
		return err
	}
	req.Cmd = cmdName(code)
	return nil
}

// DecodeResponse deserializes a response frame into resp. The Data field
// aliases payload and stays valid for the lifetime of payload.
func DecodeResponse(payload []byte, resp *Response) error {
	c := &frameCursor{b: payload}
	var err error
	if resp.ID, err = c.u64(); err != nil {
		return err
	}
	ok, err := c.u8()
	if err != nil {
		return err
	}
	resp.OK = ok != 0
	if resp.Error, err = c.str(); err != nil {
		return err
	}
	if resp.Path, err = c.str(); err != nil {
		return err
	}
	count, err := c.u32()
	if err != nil {
		return err
	}
	if count > maxEntries {
		return fmt.Errorf("sftp: too many entries: %d", count)
	}
	resp.Entries = nil
	if count > 0 {
		resp.Entries = make([]FileInfo, 0, count)
		for i := 0; i < int(count); i++ {
			var e FileInfo
			if err := decodeFileInfo(c, &e); err != nil {
				return err
			}
			resp.Entries = append(resp.Entries, e)
		}
	}
	if resp.Data, err = c.bytes(); err != nil {
		return err
	}
	hasInfo, err := c.u8()
	if err != nil {
		return err
	}
	resp.Info = nil
	if hasInfo != 0 {
		resp.Info = &FileInfo{}
		if err := decodeFileInfo(c, resp.Info); err != nil {
			return err
		}
	}
	return nil
}

func decodeFileInfo(c *frameCursor, e *FileInfo) error {
	var err error
	if e.Name, err = c.str(); err != nil {
		return err
	}
	if e.Size, err = c.i64(); err != nil {
		return err
	}
	if e.Mode, err = c.u32(); err != nil {
		return err
	}
	flags, err := c.u8()
	if err != nil {
		return err
	}
	e.IsDir = flags&1 != 0
	e.IsSymlink = flags&2 != 0
	if e.LinkTarget, err = c.str(); err != nil {
		return err
	}
	if e.ModTime, err = c.i64(); err != nil {
		return err
	}
	if e.UID, err = c.u32(); err != nil {
		return err
	}
	if e.GID, err = c.u32(); err != nil {
		return err
	}
	if e.UserName, err = c.str(); err != nil {
		return err
	}
	if e.GroupName, err = c.str(); err != nil {
		return err
	}
	return nil
}

// --- Channel transport ---

// framePoolCap is the capacity of pooled frame buffers. Frames carrying a
// data chunk dominate transfer traffic and fit in a chunk-sized buffer plus
// the fixed protocol fields. Larger frames (a listing of a huge directory)
// grow past this and are simply not pooled.
const framePoolCap = 4 + ChunkSize + 128

// framePool recycles the send-side frame buffers. WriteData consumes the
// frame synchronously (copying it into channel messages), so a buffer can be
// returned to the pool as soon as the write returns. This removes a per-chunk
// allocation from both the client's pipelined transfers and the server's
// response loop.
var framePool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4, framePoolCap)
	},
}

// SendRequest writes one request frame to the channel. Request frames are
// self-delimiting (4-byte length prefix), so a frame fragmented across
// several channel data messages is reassembled by the receiver.
func SendRequest(ch ssh3.Channel, req *Request) error {
	buf := framePool.Get().([]byte)
	buf = encodeRequestFrameInto(buf, req)
	_, err := ch.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_NONE)
	framePool.Put(buf[:4])
	return err
}

// sftpMessageChannel is the minimal channel surface needed to receive the
// data messages that carry SFTP requests and responses.
type sftpMessageChannel interface {
	NextMessage() (ssh3Messages.Message, error)
}

// receiveFrame reads one complete logical SFTP frame from the channel and
// returns its payload (the bytes after the length prefix). Channel writes
// split payloads larger than the negotiated maximum packet size across
// several DataOrExtendedDataMessage messages (see channelImpl.WriteData), so
// the payloads of consecutive data messages are accumulated until the length
// prefix says the frame is complete. Non-data messages are skipped, mirroring
// the previous request loop.
func receiveFrame(ch sftpMessageChannel) ([]byte, error) {
	var payload []byte
	for {
		msg, err := ch.NextMessage()
		if err != nil {
			return nil, err
		}
		dataMsg, ok := msg.(*ssh3Messages.DataOrExtendedDataMessage)
		if !ok || dataMsg.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
			continue
		}
		payload = append(payload, dataMsg.Data...)
		if len(payload) < 4 {
			continue
		}
		total := 4 + int(binary.BigEndian.Uint32(payload[:4]))
		if total > maxFrameSize {
			return nil, fmt.Errorf("sftp: frame too large: %d bytes", total)
		}
		// Grow to exactly total once, so a frame split across several channel
		// data messages is not reallocated and copied on every fragment.
		if len(payload) < total && cap(payload) < total {
			grown := make([]byte, len(payload), total)
			copy(grown, payload)
			payload = grown
		}
		if len(payload) >= total {
			return payload[4:total], nil
		}
	}
}

// ReceiveResponse reads the next response frame from the channel and decodes
// it. The returned response's Data field aliases the frame payload; the
// payload is not reused by subsequent calls, so the data stays valid.
func ReceiveResponse(ch ssh3.Channel) (*Response, error) {
	payload, err := receiveFrame(ch)
	if err != nil {
		return nil, err
	}
	resp := &Response{}
	if err := DecodeResponse(payload, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

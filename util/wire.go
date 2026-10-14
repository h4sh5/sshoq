// copied from github.com/quic-go/quic-go

package util

import (
	"bytes"
	"fmt"
	"io"
)

// taken from the QUIC draft
const (
	// Min is the minimum value allowed for a QUIC varint.
	Min = 0

	// Max is the maximum allowed value for a QUIC varint (2^62-1).
	Max = maxVarInt8

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// Reader implements both the io.ByteReader and io.Reader interfaces.
type Reader interface {
	io.ByteReader
	io.Reader
}

const (
	// MaxFieldLength is the absolute ceiling applied to any length-prefixed field
	// (an SSH string, an SSH byte string) read from a peer. Without such a ceiling,
	// a 10-byte message announcing a 2^62-1 length makes the process allocate up to
	// 4 EiB of address space, and any length above Go's maxAlloc makes `make`
	// panic ("makeslice: len out of range"), which kills the whole process.
	// Readers which know a tighter bound (a channel knows the maximum packet size it
	// negotiated with the peer) must use it, see NewLengthLimitedReader.
	MaxFieldLength uint64 = 1 << 24
)

// MaxLengthAware is implemented by readers which know the maximum length of a
// length-prefixed field they are willing to accept from the peer.
type MaxLengthAware interface {
	// MaxFieldLength returns the maximum accepted length, in bytes.
	MaxFieldLength() uint64
}

// lengthLimitedReader bounds the length-prefixed fields read from the wrapped Reader.
type lengthLimitedReader struct {
	Reader
	max uint64
}

var _ Reader = &lengthLimitedReader{}
var _ MaxLengthAware = &lengthLimitedReader{}

// NewLengthLimitedReader wraps r so that any length-prefixed field longer than max
// bytes is refused instead of being allocated. It is meant to be used for the data
// coming from a peer, with max set to the maximum packet size negotiated with that
// peer. Wrapping an already limited reader tightens its limit, it never loosens it.
func NewLengthLimitedReader(r Reader, max uint64) Reader {
	if max > MaxFieldLength {
		max = MaxFieldLength
	}
	if limited, ok := r.(*lengthLimitedReader); ok && limited.max <= max {
		return limited
	}
	return &lengthLimitedReader{Reader: r, max: max}
}

func (r *lengthLimitedReader) MaxFieldLength() uint64 {
	return r.max
}

func (r *lengthLimitedReader) ReadByte() (byte, error) {
	var b [1]byte
	n, err := r.Read(b[:])
	if n == 1 && err == io.EOF {
		err = nil
	}
	return b[0], err
}

// checkFieldLength refuses a length received from the peer when it is larger than
// what the reader is prepared to allocate for it.
func checkFieldLength(buf Reader, length uint64) error {
	max := uint64(MaxFieldLength)
	if aware, ok := buf.(MaxLengthAware); ok {
		if limited := aware.MaxFieldLength(); limited < max {
			max = limited
		}
	}
	if length > max {
		return fmt.Errorf("peer announced a %d bytes field, the maximum accepted length is %d bytes", length, max)
	}
	return nil
}

type byteReader struct {
	io.Reader
}

var _ Reader = &byteReader{}

// NewReader returns a Reader for r.
// If r already implements both io.ByteReader and io.Reader, NewReader returns r.
// Otherwise, r is wrapped to add the missing interfaces.
func NewReader(r io.Reader) Reader {
	if r, ok := r.(Reader); ok {
		return r
	}
	return &byteReader{r}
}

func (r *byteReader) ReadByte() (byte, error) {
	var b [1]byte
	n, err := r.Reader.Read(b[:])
	if n == 1 && err == io.EOF {
		err = nil
	}
	return b[0], err
}

// Writer implements both the io.ByteWriter and io.Writer interfaces.
type Writer interface {
	io.ByteWriter
	io.Writer
}

var _ Writer = &bytes.Buffer{}

type byteWriter struct {
	io.Writer
}

var _ Writer = &byteWriter{}

// NewWriter returns a Writer for w.
// If r already implements both io.ByteWriter and io.Writer, NewWriter returns w.
// Otherwise, w is wrapped to add the missing interfaces.
func NewWriter(w io.Writer) Writer {
	if w, ok := w.(Writer); ok {
		return w
	}
	return &byteWriter{w}
}

func (w *byteWriter) WriteByte(c byte) error {
	_, err := w.Writer.Write([]byte{c})
	return err
}

// ReadVarInt reads a number in the QUIC varint format from r.
func ReadVarInt(r Reader) (uint64, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	len := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if len == 1 {
		return uint64(b1), nil
	}
	b2, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if len == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

// AppendVarInt appends i in the QUIC varint format.
func AppendVarInt(b []byte, i uint64) []byte {
	if i <= maxVarInt1 {
		return append(b, uint8(i))
	}
	if i <= maxVarInt2 {
		return append(b, []byte{uint8(i>>8) | 0x40, uint8(i)}...)
	}
	if i <= maxVarInt4 {
		return append(b, []byte{uint8(i>>24) | 0x80, uint8(i >> 16), uint8(i >> 8), uint8(i)}...)
	}
	if i <= maxVarInt8 {
		return append(b, []byte{
			uint8(i>>56) | 0xc0, uint8(i >> 48), uint8(i >> 40), uint8(i >> 32),
			uint8(i >> 24), uint8(i >> 16), uint8(i >> 8), uint8(i),
		}...)
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}

// AppendVarIntWithLen append i in the QUIC varint format with the desired length.
func AppendVarIntWithLen(b []byte, i uint64, length uint64) []byte {
	if length != 1 && length != 2 && length != 4 && length != 8 {
		panic("invalid varint length")
	}
	l := VarIntLen(i)
	if l == length {
		return AppendVarInt(b, i)
	}
	if l > length {
		panic(fmt.Sprintf("cannot encode %d in %d bytes", i, length))
	}
	if length == 2 {
		b = append(b, 0b01000000)
	} else if length == 4 {
		b = append(b, 0b10000000)
	} else if length == 8 {
		b = append(b, 0b11000000)
	}
	for j := uint64(1); j < length-l; j++ {
		b = append(b, 0)
	}
	for j := uint64(0); j < l; j++ {
		b = append(b, uint8(i>>(8*(l-1-j))))
	}
	return b
}

// VarIntLen determines the number of bytes that will be needed to write the number i.
func VarIntLen(i uint64) uint64 {
	if i <= maxVarInt1 {
		return 1
	}
	if i <= maxVarInt2 {
		return 2
	}
	if i <= maxVarInt4 {
		return 4
	}
	if i <= maxVarInt8 {
		return 8
	}
	// Don't use a fmt.Sprintf here to format the error message.
	// The function would then exceed the inlining budget.
	panic(struct {
		message string
		num     uint64
	}{"value doesn't fit into 62 bits: ", i})
}

func ParseSSHString(buf Reader) (string, error) {
	length, err := ReadVarInt(buf)
	if err != nil {
		return "", InvalidSSHString{err}
	}
	// the length comes from the peer: it must be bounded *before* anything is allocated,
	// otherwise a few bytes received are enough to ask for an arbitrarily large allocation
	if err := checkFieldLength(buf, length); err != nil {
		return "", InvalidSSHString{err}
	}
	if length == 0 {
		return "", nil
	}
	out := make([]byte, length)
	n, err := io.ReadFull(buf, out)
	if n != int(length) {
		return "", InvalidSSHString{fmt.Errorf("expected length %d, read length %d", length, n)}
	}
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(out[:n]), err
}

func ParseSSHBytes(buf Reader) ([]byte, error) {
	length, err := ReadVarInt(buf)
	if err != nil {
		return []byte{}, InvalidSSHString{err}
	}
	// same as ParseSSHString: never allocate what the peer merely announces
	if err := checkFieldLength(buf, length); err != nil {
		return []byte{}, InvalidSSHString{err}
	}
	if length == 0 {
		return []byte{}, nil
	}
	out := make([]byte, length)
	n, err := io.ReadFull(buf, out)
	if n != int(length) {
		return []byte{}, InvalidSSHString{fmt.Errorf("expected length %d, read length %d", length, n)}
	}
	if err != nil && err != io.EOF {
		return []byte{}, err
	}
	return out, err
}

func WriteSSHString(out []byte, s string) (int, error) {
	if uint64(len(out)) < uint64(SSHStringLen(s)) {
		return 0, fmt.Errorf("buffer too small to write varint: %d < %d", len(out), SSHStringLen(s))
	}
	buf := AppendVarInt(nil, uint64(len(s)))

	copied := copy(out, buf)
	copied += copy(out[copied:], s)
	return copied, nil
}

func WriteSSHBytes(out []byte, in []byte) (int, error) {
	if uint64(len(out)) < uint64(SSHBytesLen(in)) {
		return 0, fmt.Errorf("buffer too small to write varint: %d < %d", len(out), SSHBytesLen(in))
	}
	buf := AppendVarInt(nil, uint64(len(in)))

	copied := copy(out, buf)
	copied += copy(out[copied:], in)
	return copied, nil
}

func SSHStringLen(s string) int {
	return int(VarIntLen(uint64(len(s)))) + len(s)
}

func SSHBytesLen(s []byte) int {
	return int(VarIntLen(uint64(len(s)))) + len(s)
}

func MinUint64(a uint64, b uint64) uint64 {
	if a <= b {
		return a
	}
	return b
}

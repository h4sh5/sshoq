package sftp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
)

const ChunkSize = 32 * 1024

// TransferWindow is the number of in-flight read/write requests the pipelined
// transfer loops keep queued. On links with non-trivial round-trip time this
// masks the per-chunk serialisation latency and dramatically improves
// throughput, especially for small chunks. A value of 8 is a good default;
// very high-latency links can benefit from larger values.
const TransferWindow = 8

type Request struct {
	ID     uint64 `json:"id"`
	Cmd    string `json:"cmd"`
	Path   string `json:"path,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

type FileInfo struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Mode       uint32 `json:"mode"`
	IsDir      bool   `json:"is_dir"`
	IsSymlink  bool   `json:"is_symlink,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
	ModTime    int64  `json:"mod_time"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	UserName   string `json:"user_name,omitempty"`
	GroupName  string `json:"group_name,omitempty"`
}

type Response struct {
	ID      uint64     `json:"id"`
	OK      bool       `json:"ok"`
	Error   string     `json:"error,omitempty"`
	Path    string     `json:"path,omitempty"`
	Entries []FileInfo `json:"entries,omitempty"`
	Data    []byte     `json:"data,omitempty"`
	Info    *FileInfo  `json:"info,omitempty"`
}

func SendRequest(ch ssh3.Channel, req *Request) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	_, err = ch.WriteData(data, ssh3Messages.SSH_EXTENDED_DATA_NONE)
	return err
}

// sftpMessageChannel is the minimal channel surface needed to receive the
// data messages that carry SFTP requests and responses.
type sftpMessageChannel interface {
	NextMessage() (ssh3Messages.Message, error)
}

// receiveJSON reads one complete logical SFTP message from the channel and
// returns its raw JSON payload. Channel writes split payloads larger than the
// negotiated maximum packet size across several DataOrExtendedDataMessage
// messages (see channelImpl.WriteData), so the payloads of consecutive data
// messages are accumulated until they form a single complete JSON document.
// Non-data messages are skipped, mirroring the previous request loop.
func receiveJSON(ch sftpMessageChannel) ([]byte, error) {
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
		complete, err := isCompleteJSON(payload)
		if err != nil {
			return nil, err
		}
		if complete {
			return payload, nil
		}
	}
}

// isCompleteJSON reports whether payload is exactly one complete JSON document.
// A payload that ends in the middle of a document (a truncated prefix of a
// message that is still arriving across channel data messages) is reported as
// incomplete, not as an error.
func isCompleteJSON(payload []byte) (bool, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		if err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	// A second decode must hit EOF: the payload must be exactly one value,
	// with no trailing data.
	if err := dec.Decode(&v); err != nil {
		if err == io.EOF {
			return true, nil
		}
		if err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	return false, fmt.Errorf("multiple JSON values in one sftp message")
}

func ReceiveResponse(ch ssh3.Channel) (*Response, error) {
	payload, err := receiveJSON(ch)
	if err != nil {
		return nil, err
	}
	resp := &Response{}
	if err := json.Unmarshal(payload, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

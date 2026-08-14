package sftp

import (
	"encoding/json"
	"fmt"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
)

const ChunkSize = 16 * 1024

type Request struct {
	ID     uint64 `json:"id"`
	Cmd    string `json:"cmd"`
	Path   string `json:"path,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	IsDir   bool   `json:"is_dir"`
	ModTime int64  `json:"mod_time"`
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

func ReceiveResponse(ch ssh3.Channel) (*Response, error) {
	msg, err := ch.NextMessage()
	if err != nil {
		return nil, err
	}
	dataMsg, ok := msg.(*ssh3Messages.DataOrExtendedDataMessage)
	if !ok || dataMsg.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
		return nil, fmt.Errorf("unexpected message type on sftp channel")
	}
	resp := &Response{}
	if err := json.Unmarshal([]byte(dataMsg.Data), resp); err != nil {
		return nil, err
	}
	return resp, nil
}

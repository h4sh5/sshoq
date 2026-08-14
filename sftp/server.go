package sftp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
	"github.com/h4sh5/sshoq/util/unix_util"
)

type ServerSession struct {
	channel    ssh3.Channel
	currentDir string
}

func ServeChannel(ctx context.Context, user *unix_util.User, channel ssh3.Channel) {
	session := &ServerSession{
		channel:    channel,
		currentDir: user.Dir,
	}
	if session.currentDir == "" {
		session.currentDir = "."
	}

	log.Info().Msgf("starting SFTP session for user %s", user.Username)
	defer channel.Close()
	defer log.Info().Msgf("ending SFTP session for user %s", user.Username)

	for {
		msg, err := channel.NextMessage()
		if err != nil {
			if err != io.EOF {
				log.Error().Msgf("sftp channel error: %s", err)
			}
			return
		}

		dataMsg, ok := msg.(*ssh3Messages.DataOrExtendedDataMessage)
		if !ok || dataMsg.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(dataMsg.Data), &req); err != nil {
			session.respond(&Response{Error: fmt.Sprintf("invalid request: %s", err)})
			continue
		}

		resp := session.handleRequest(req)
		if err := session.respond(resp); err != nil {
			log.Error().Msgf("failed to send sftp response: %s", err)
			return
		}
	}
}

func (s *ServerSession) respond(resp *Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = s.channel.WriteData(data, ssh3Messages.SSH_EXTENDED_DATA_NONE)
	return err
}

func (s *ServerSession) resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.currentDir, p)
}

func (s *ServerSession) handleRequest(req Request) *Response {
	resp := &Response{ID: req.ID}
	switch req.Cmd {
	case "pwd":
		resp.OK = true
		resp.Path = s.currentDir

	case "cd":
		target := s.resolvePath(req.Path)
		info, err := os.Stat(target)
		if err != nil {
			resp.Error = err.Error()
		} else if !info.IsDir() {
			resp.Error = "not a directory"
		} else {
			s.currentDir = target
			resp.OK = true
		}

	case "ls":
		target := s.resolvePath(req.Path)
		if target == "" {
			target = "."
		}
		entries, err := os.ReadDir(target)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
			for _, e := range entries {
				info, err := e.Info()
				if err != nil {
					continue
				}
				resp.Entries = append(resp.Entries, FileInfo{
					Name:    e.Name(),
					Size:    info.Size(),
					Mode:    uint32(info.Mode()),
					IsDir:   e.IsDir(),
					ModTime: info.ModTime().Unix(),
				})
			}
		}

	case "stat":
		target := s.resolvePath(req.Path)
		info, err := os.Stat(target)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
			resp.Info = &FileInfo{
				Name:    info.Name(),
				Size:    info.Size(),
				Mode:    uint32(info.Mode()),
				IsDir:   info.IsDir(),
				ModTime: info.ModTime().Unix(),
			}
		}

	case "get":
		target := s.resolvePath(req.Path)
		f, err := os.Open(target)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		defer f.Close()

		if req.Offset > 0 {
			_, err = f.Seek(req.Offset, io.SeekStart)
			if err != nil {
				resp.Error = err.Error()
				break
			}
		}

		limit := req.Limit
		if limit <= 0 || limit > ChunkSize {
			limit = ChunkSize
		}

		buf := make([]byte, limit)
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			resp.Error = err.Error()
			break
		}
		resp.OK = true
		resp.Data = buf[:n]

	case "put":
		target := s.resolvePath(req.Path)
		dir := filepath.Dir(target)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		flag := os.O_CREATE | os.O_WRONLY
		if req.Offset == 0 {
			flag |= os.O_TRUNC
		}
		f, err := os.OpenFile(target, flag, 0644)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		defer f.Close()

		if req.Offset > 0 {
			_, err = f.Seek(req.Offset, io.SeekStart)
			if err != nil {
				resp.Error = err.Error()
				break
			}
		}

		_, err = f.Write(req.Data)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
		}

	case "mkdir":
		target := s.resolvePath(req.Path)
		err := os.MkdirAll(target, 0755)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
		}

	case "rm":
		target := s.resolvePath(req.Path)
		err := os.Remove(target)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
		}

	case "rmdir":
		target := s.resolvePath(req.Path)
		err := os.RemoveAll(target)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
		}

	default:
		resp.Error = fmt.Sprintf("unknown command: %s", req.Cmd)
	}
	return resp
}

package sftp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
	"github.com/h4sh5/sshoq/util/unix_util"
)

const (
	accessX = 0x1
	accessW = 0x2
	accessR = 0x4
)

type ServerSession struct {
	channel    ssh3.Channel
	currentDir string
	user       *unix_util.User
	groups     map[uint32]bool
	baseDirFd  int
	baseDev    uint64
	baseIno    uint64
}

func ServeChannel(ctx context.Context, user *unix_util.User, channel ssh3.Channel) {
	session := &ServerSession{
		channel:    channel,
		currentDir: user.Dir,
		user:       user,
		groups:     buildGroupSet(user),
	}
	if session.currentDir == "" {
		session.currentDir = "."
	}

	if err := session.pinBaseDir(); err != nil {
		log.Warn().Msgf("sftp: failed to pin base directory %s: %s", session.currentDir, err)
	}
	if session.baseDirFd > 0 {
		defer unix.Close(session.baseDirFd)
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

func buildGroupSet(user *unix_util.User) map[uint32]bool {
	groups := make(map[uint32]bool)
	if user == nil {
		groups[uint32(os.Getgid())] = true
		gids, err := os.Getgroups()
		if err == nil {
			for _, gid := range gids {
				if gid >= 0 {
					groups[uint32(gid)] = true
				}
			}
		}
		return groups
	}

	groups[uint32(user.Gid)] = true
	lookupUser, err := osuser.Lookup(user.Username)
	if err != nil {
		log.Warn().Msgf("sftp: failed to lookup groups for user %s: %s", user.Username, err)
		return groups
	}

	groupIDs, err := lookupUser.GroupIds()
	if err != nil {
		log.Warn().Msgf("sftp: failed to read supplementary groups for user %s: %s", user.Username, err)
		return groups
	}

	for _, gid := range groupIDs {
		parsed, err := strconv.ParseUint(gid, 10, 32)
		if err != nil {
			continue
		}
		groups[uint32(parsed)] = true
	}

	return groups
}

func (s *ServerSession) pinBaseDir() error {
	s.baseDirFd = 0

	fd, err := unix.Open(s.currentDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return err
	}

	s.baseDirFd = fd
	s.baseDev = uint64(st.Dev)
	s.baseIno = uint64(st.Ino)
	return nil
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
	target := s.resolvePath(req.Path)

	switch req.Cmd {
	case "pwd":
		resp.OK = true
		resp.Path = s.currentDir

	case "cd":
		if err := s.checkAncestorExecute(target); err != nil {
			resp.Error = err.Error()
			break
		}
		dirfd, pathArg := s.dirFDAndPath(req.Path, target)
		fd, err := unix.Openat(dirfd, pathArg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		defer unix.Close(fd)

		if err := s.checkFDPermission(fd, accessR|accessX); err != nil {
			resp.Error = fmt.Sprintf("permission denied: %s", err)
			break
		}

		s.currentDir = target
		resp.OK = true

	case "ls":
		if target == "" {
			target = "."
		}
		if err := s.checkAncestorExecute(target); err != nil {
			resp.Error = err.Error()
			break
		}
		dirfd, pathArg := s.dirFDAndPath(req.Path, target)
		fd, err := unix.Openat(dirfd, pathArg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		file := os.NewFile(uintptr(fd), target)
		if file == nil {
			unix.Close(fd)
			resp.Error = "failed to open directory"
			break
		}
		defer file.Close()

		if err := s.checkFDPermission(fd, accessR|accessX); err != nil {
			resp.Error = fmt.Sprintf("permission denied: %s", err)
			break
		}

		entries, err := file.ReadDir(-1)
		if err != nil {
			resp.Error = err.Error()
			break
		}

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

	case "stat":
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
		if err := s.checkAncestorExecute(target); err != nil {
			resp.Error = err.Error()
			break
		}
		dirfd, pathArg := s.dirFDAndPath(req.Path, target)
		fd, err := unix.Openat(dirfd, pathArg, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		file := os.NewFile(uintptr(fd), target)
		if file == nil {
			unix.Close(fd)
			resp.Error = "failed to open file"
			break
		}
		defer file.Close()

		if err := s.checkFDPermission(fd, accessR); err != nil {
			resp.Error = fmt.Sprintf("permission denied: %s", err)
			break
		}

		if req.Offset > 0 {
			_, err = file.Seek(req.Offset, io.SeekStart)
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
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			resp.Error = err.Error()
			break
		}
		resp.OK = true
		resp.Data = buf[:n]

	case "put":
		if err := s.checkAncestorExecute(target); err != nil {
			resp.Error = err.Error()
			break
		}
		parentFd, name, err := s.openParentDir(req.Path, target)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		defer unix.Close(parentFd)

		var st unix.Stat_t
		statErr := unix.Fstatat(parentFd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		isNewFile := statErr == syscall.ENOENT
		if statErr != nil && !isNewFile {
			resp.Error = statErr.Error()
			break
		}

		if isNewFile {
			if err := s.checkFDPermission(parentFd, accessW|accessX); err != nil {
				resp.Error = fmt.Sprintf("permission denied: %s", err)
				break
			}
		} else if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			resp.Error = "is a directory"
			break
		}

		flags := unix.O_WRONLY | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if isNewFile {
			flags |= unix.O_EXCL
		}
		if req.Offset == 0 {
			flags |= unix.O_TRUNC
		}

		fd, err := unix.Openat(parentFd, name, flags, 0644)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		file := os.NewFile(uintptr(fd), target)
		if file == nil {
			unix.Close(fd)
			resp.Error = "failed to open file"
			break
		}
		defer file.Close()

		if err := s.checkFDPermission(fd, accessW); err != nil {
			resp.Error = fmt.Sprintf("permission denied: %s", err)
			break
		}

		if req.Offset > 0 {
			_, err = file.Seek(req.Offset, io.SeekStart)
			if err != nil {
				resp.Error = err.Error()
				break
			}
		}

		_, err = file.Write(req.Data)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
		}

	case "mkdir":
		if err := s.checkAncestorExecute(target); err != nil {
			resp.Error = err.Error()
			break
		}
		parentFd, name, err := s.openParentDir(req.Path, target)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		defer unix.Close(parentFd)

		if err := s.checkFDPermission(parentFd, accessW|accessX); err != nil {
			resp.Error = fmt.Sprintf("permission denied: %s", err)
			break
		}

		var st unix.Stat_t
		if err := unix.Fstatat(parentFd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			resp.Error = fmt.Sprintf("%s already exists", target)
			break
		} else if err != syscall.ENOENT {
			resp.Error = err.Error()
			break
		}

		err = unix.Mkdirat(parentFd, name, 0755)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
		}

	case "rm":
		if err := s.checkAncestorExecute(target); err != nil {
			resp.Error = err.Error()
			break
		}
		parentFd, name, err := s.openParentDir(req.Path, target)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		defer unix.Close(parentFd)

		if err := s.checkFDPermission(parentFd, accessW|accessX); err != nil {
			resp.Error = fmt.Sprintf("permission denied: %s", err)
			break
		}

		err = unix.Unlinkat(parentFd, name, 0)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
		}

	case "rmdir":
		if err := s.checkAncestorExecute(target); err != nil {
			resp.Error = err.Error()
			break
		}
		parentFd, name, err := s.openParentDir(req.Path, target)
		if err != nil {
			resp.Error = err.Error()
			break
		}
		defer unix.Close(parentFd)

		if err := s.checkFDPermission(parentFd, accessW|accessX); err != nil {
			resp.Error = fmt.Sprintf("permission denied: %s", err)
			break
		}

		err = unix.Unlinkat(parentFd, name, unix.AT_REMOVEDIR)
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

func (s *ServerSession) dirFDAndPath(rawPath, resolvedPath string) (int, string) {
	if filepath.IsAbs(rawPath) {
		return unix.AT_FDCWD, resolvedPath
	}

	if rawPath == "" {
		rawPath = "."
	}

	if fd, ok := s.baseDirForRelative(); ok {
		return fd, rawPath
	}
	return unix.AT_FDCWD, resolvedPath
}

func (s *ServerSession) baseDirForRelative() (int, bool) {
	if s.baseDirFd <= 0 {
		return 0, false
	}

	var st syscall.Stat_t
	if err := syscall.Stat(s.currentDir, &st); err != nil {
		return 0, false
	}

	if uint64(st.Dev) != s.baseDev || uint64(st.Ino) != s.baseIno {
		return 0, false
	}

	return s.baseDirFd, true
}

func (s *ServerSession) openParentDir(rawPath, resolvedPath string) (int, string, error) {
	dirfd, pathArg := s.dirFDAndPath(rawPath, resolvedPath)
	cleaned := filepath.Clean(pathArg)
	name := filepath.Base(cleaned)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return -1, "", fmt.Errorf("invalid path")
	}

	parent := filepath.Dir(cleaned)
	if parent == "" {
		parent = "."
	}

	fd, err := unix.Openat(dirfd, parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	return fd, name, nil
}

func (s *ServerSession) checkFDPermission(fd int, required int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	return s.checkStatPermission(st.Uid, st.Gid, uint32(st.Mode), required)
}

func (s *ServerSession) checkStatPermission(uid, gid, mode uint32, required int) error {
	sessionUID := uint32(os.Getuid())
	if s.user != nil {
		sessionUID = uint32(s.user.Uid)
	}

	perm := mode & 0o7
	sessionGroups := s.groups
	if len(sessionGroups) == 0 {
		sessionGroups = buildGroupSet(s.user)
		s.groups = sessionGroups
	}

	switch {
	case uid == sessionUID:
		perm = (mode >> 6) & 0o7
	case sessionGroups[gid]:
		perm = (mode >> 3) & 0o7
	}

	if required&accessR != 0 && perm&0o4 == 0 {
		return os.ErrPermission
	}
	if required&accessW != 0 && perm&0o2 == 0 {
		return os.ErrPermission
	}
	if required&accessX != 0 && perm&0o1 == 0 {
		return os.ErrPermission
	}

	return nil
}

func (s *ServerSession) checkAncestorExecute(path string) error {
	clean := filepath.Clean(path)
	if clean == "." || clean == "" {
		return nil
	}

	if filepath.IsAbs(clean) {
		var rootSt syscall.Stat_t
		if err := syscall.Stat(string(filepath.Separator), &rootSt); err != nil {
			return err
		}
		if err := s.checkStatPermission(rootSt.Uid, rootSt.Gid, uint32(rootSt.Mode), accessX); err != nil {
			return fmt.Errorf("permission denied: %w", err)
		}
	}

	parts := strings.Split(clean, string(filepath.Separator))
	if len(parts) <= 1 {
		return nil
	}

	current := ""
	if filepath.IsAbs(clean) {
		current = string(filepath.Separator)
		parts = strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	}

	for i := 0; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" || part == "." {
			continue
		}

		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}

		var st syscall.Stat_t
		if err := syscall.Stat(current, &st); err != nil {
			return err
		}
		if (st.Mode & syscall.S_IFMT) != syscall.S_IFDIR {
			return syscall.ENOTDIR
		}
		if err := s.checkStatPermission(st.Uid, st.Gid, uint32(st.Mode), accessX); err != nil {
			return fmt.Errorf("permission denied: %w", err)
		}
	}

	return nil
}

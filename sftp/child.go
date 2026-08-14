package sftp

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
	"github.com/h4sh5/sshoq/util"
	"github.com/h4sh5/sshoq/util/unix_util"
)

const (
	sftpChildEnv    = "SSHOQ_SFTP_CHILD"
	sftpUsernameEnv = "SSHOQ_SFTP_USERNAME"
	sftpUIDEnv      = "SSHOQ_SFTP_UID"
	sftpGIDEnv      = "SSHOQ_SFTP_GID"
	sftpGroupsEnv   = "SSHOQ_SFTP_GROUPS"
	sftpHomeEnv     = "SSHOQ_SFTP_HOME"
	sftpShellEnv    = "SSHOQ_SFTP_SHELL"
	sftpLogLevelEnv = "SSH3_LOG_LEVEL"
)

// ServeChannel handles an SFTP channel. When the server process is running as
// root and the target user differs from the current process, the SFTP session
// is served in a forked child process that runs with the target user's UID,
// GID and supplementary groups. This prevents the privilege drop from affecting
// the main server process and other concurrent sessions.
func ServeChannel(ctx context.Context, user *unix_util.User, channel ssh3.Channel) {
	if user == nil {
		log.Error().Msg("sftp: no user provided, closing channel")
		channel.Close()
		return
	}

	// If we are not root or already running as the target user, handle the
	// session in-process. Tests and non-root server deployments use this path.
	if os.Getuid() != 0 || (uint64(os.Getuid()) == user.Uid && uint64(os.Getgid()) == user.Gid) {
		serveChannelInProcess(ctx, user, channel)
		return
	}

	serveChannelInChild(ctx, user, channel)
}

// serveChannelInChild spawns a child process running as the target user and
// proxies SFTP requests/responses between the QUIC channel and the child.
func serveChannelInChild(ctx context.Context, user *unix_util.User, channel ssh3.Channel) {
	groupIDs, err := buildGroupIDs(user)
	if err != nil {
		log.Error().Msgf("sftp: failed to build group list for user %s: %s", user.Username, err)
		channel.Close()
		return
	}

	exe, err := os.Executable()
	if err != nil {
		log.Error().Msgf("sftp: failed to determine executable path: %s", err)
		channel.Close()
		return
	}

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		log.Error().Msgf("sftp: failed to create stdin pipe: %s", err)
		channel.Close()
		return
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		log.Error().Msgf("sftp: failed to create stdout pipe: %s", err)
		stdinR.Close()
		stdinW.Close()
		channel.Close()
		return
	}

	cmd := exec.Command(exe)
	cmd.Dir = user.Dir
	cmd.Env = append(os.Environ(),
		sftpChildEnv+"=1",
		sftpUsernameEnv+"="+user.Username,
		sftpUIDEnv+"="+strconv.FormatUint(user.Uid, 10),
		sftpGIDEnv+"="+strconv.FormatUint(user.Gid, 10),
		sftpGroupsEnv+"="+formatGroups(groupIDs),
		sftpHomeEnv+"="+user.Dir,
		sftpShellEnv+"="+user.Shell,
	)
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = childSysProcAttr(uint32(user.Uid), uint32(user.Gid), uint32Groups(groupIDs))

	if err := cmd.Start(); err != nil {
		log.Error().Msgf("sftp: failed to start child process for user %s: %s", user.Username, err)
		stdinR.Close()
		stdinW.Close()
		stdoutR.Close()
		stdoutW.Close()
		channel.Close()
		return
	}

	// Close the parent's copies of the child-facing pipe ends.
	stdinR.Close()
	stdoutW.Close()

	log.Info().Msgf("starting SFTP session for user %s in child process %d", user.Username, cmd.Process.Pid)

	var wg sync.WaitGroup
	wg.Add(2)

	// Forward QUIC channel data messages to the child's stdin.
	go func() {
		defer wg.Done()
		defer stdinW.Close()
		for {
			msg, err := channel.NextMessage()
			if err != nil {
				if err != io.EOF {
					log.Error().Msgf("sftp: error reading from channel: %s", err)
				}
				return
			}
			dataMsg, ok := msg.(*ssh3Messages.DataOrExtendedDataMessage)
			if !ok || dataMsg.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
				continue
			}
			if err := writeFrame(stdinW, []byte(dataMsg.Data)); err != nil {
				if err != io.EOF && !isClosedPipe(err) {
					log.Error().Msgf("sftp: error writing to child stdin: %s", err)
				}
				return
			}
		}
	}()

	// Forward child stdout responses back to the QUIC channel.
	go func() {
		defer wg.Done()
		defer channel.Close()
		reader := bufio.NewReader(stdoutR)
		for {
			frame, err := readFrame(reader)
			if err != nil {
				if err != io.EOF {
					log.Error().Msgf("sftp: error reading from child stdout: %s", err)
				}
				return
			}
			if _, err := channel.WriteData(frame, ssh3Messages.SSH_EXTENDED_DATA_NONE); err != nil {
				if !isClosedPipe(err) {
					log.Error().Msgf("sftp: error writing to channel: %s", err)
				}
				return
			}
		}
	}()

	// Wait for either direction to finish, then terminate the child if needed.
	go func() {
		wg.Wait()
		if cmd.Process != nil {
			cmd.Process.Signal(syscall.SIGTERM)
			time.AfterFunc(2*time.Second, func() {
				if cmd.Process != nil {
					cmd.Process.Kill()
				}
			})
		}
		stdinW.Close()
		stdoutR.Close()
		channel.Close()
	}()

	if err := cmd.Wait(); err != nil {
		log.Debug().Msgf("sftp: child process for user %s exited: %s", user.Username, err)
	}
	log.Info().Msgf("ending SFTP session for user %s", user.Username)
}

// RunHandler is the entry point for the forked SFTP child process. It reads
// requests from stdin and writes responses to stdout.
func RunHandler(ctx context.Context) int {
	user, err := userFromEnv()
	if err != nil {
		log.Error().Msgf("sftp: invalid child environment: %s", err)
		return 1
	}

	ch := newStdioChannel()
	serveChannelInProcess(ctx, user, ch)
	return 0
}

func userFromEnv() (*unix_util.User, error) {
	uidStr := os.Getenv(sftpUIDEnv)
	gidStr := os.Getenv(sftpGIDEnv)
	if uidStr == "" || gidStr == "" {
		return nil, fmt.Errorf("missing %s or %s", sftpUIDEnv, sftpGIDEnv)
	}
	uid, err := strconv.ParseUint(uidStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid uid: %w", err)
	}
	gid, err := strconv.ParseUint(gidStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid gid: %w", err)
	}
	return &unix_util.User{
		Username: os.Getenv(sftpUsernameEnv),
		Uid:      uid,
		Gid:      gid,
		Dir:      os.Getenv(sftpHomeEnv),
		Shell:    os.Getenv(sftpShellEnv),
	}, nil
}

// stdioChannel implements ssh3.Channel over stdin/stdout using a simple
// length-prefixed framing. It is only intended for the SFTP child process.
type stdioChannel struct {
	reader *bufio.Reader
	mu     sync.Mutex
	closed bool
}

func newStdioChannel() *stdioChannel {
	return &stdioChannel{reader: bufio.NewReader(os.Stdin)}
}

func (c *stdioChannel) NextMessage() (ssh3Messages.Message, error) {
	frame, err := readFrame(c.reader)
	if err != nil {
		return nil, err
	}
	return &ssh3Messages.DataOrExtendedDataMessage{
		DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE,
		Data:     string(frame),
	}, nil
}

func (c *stdioChannel) WriteData(dataBuf []byte, dataType ssh3Messages.SSHDataType) (int, error) {
	if dataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
		return 0, fmt.Errorf("extended data not supported")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writeFrame(os.Stdout, dataBuf); err != nil {
		return 0, err
	}
	return len(dataBuf), nil
}

func (c *stdioChannel) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		os.Stdin.Close()
		os.Stdout.Close()
	}
}

func (c *stdioChannel) ChannelID() util.ChannelID                               { return 0 }
func (c *stdioChannel) ConversationID() ssh3.ConversationID                     { return ssh3.ConversationID{} }
func (c *stdioChannel) ConversationStreamID() uint64                            { return 0 }
func (c *stdioChannel) ReceiveDatagram(_ context.Context) ([]byte, error)       { return nil, io.EOF }
func (c *stdioChannel) SendDatagram(_ []byte) error                             { return fmt.Errorf("not supported") }
func (c *stdioChannel) SendRequest(_ *ssh3Messages.ChannelRequestMessage) error { return nil }
func (c *stdioChannel) CancelRead()                                             {}
func (c *stdioChannel) MaxPacketSize() uint64                                   { return 1 << 20 }
func (c *stdioChannel) ChannelType() string                                     { return "sftp" }
func (c *stdioChannel) WaitOpen() error                                         { return nil }
func (c *stdioChannel) RejectOpen(_ uint64, _ string) error                     { return fmt.Errorf("not supported") }
func (c *stdioChannel) confirmChannel(_ uint64) error                           { return nil }
func (c *stdioChannel) setDatagramSender(_ func([]byte) error)                  {}
func (c *stdioChannel) waitAddDatagram(_ context.Context, _ []byte) error       { return nil }
func (c *stdioChannel) addDatagram(_ []byte) bool                               { return true }
func (c *stdioChannel) maybeSendHeader() error                                  { return nil }
func (c *stdioChannel) setDgramQueue(_ *util.DatagramsQueue)                    {}

func writeFrame(w io.Writer, data []byte) error {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > 1<<24 {
		return nil, fmt.Errorf("frame too large: %d", n)
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

func formatGroups(groups []int) string {
	parts := make([]string, len(groups))
	for i, g := range groups {
		parts[i] = strconv.Itoa(g)
	}
	return strings.Join(parts, ",")
}

func uint32Groups(groups []int) []uint32 {
	out := make([]uint32, len(groups))
	for i, g := range groups {
		out[i] = uint32(g)
	}
	return out
}

func isClosedPipe(err error) bool {
	if err == nil {
		return false
	}
	if err == io.ErrClosedPipe || err == io.EOF {
		return true
	}
	if pathErr, ok := err.(*os.PathError); ok {
		return pathErr.Err == syscall.EPIPE || pathErr.Err == syscall.EBADF
	}
	return false
}

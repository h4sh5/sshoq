package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/h4sh5/sshoq/client/winsize"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"runtime"

	_ "net/http/pprof"

	"github.com/caddyserver/certmagic"
	"github.com/creack/pty"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	ssh3 "github.com/h4sh5/sshoq"
	"github.com/h4sh5/sshoq/internal"
	ssh3Messages "github.com/h4sh5/sshoq/message"
	"github.com/h4sh5/sshoq/server_auth"
	ssh3sftp "github.com/h4sh5/sshoq/sftp"
	util "github.com/h4sh5/sshoq/util"
	"github.com/h4sh5/sshoq/util/unix_util"
)

var signals = map[string]os.Signal{
	"SIGABRT":   syscall.Signal(0x6),
	"SIGALRM":   syscall.Signal(0xe),
	"SIGBUS":    syscall.Signal(0x7),
	"SIGCHLD":   syscall.Signal(0x11),
	"SIGCLD":    syscall.Signal(0x11),
	"SIGCONT":   syscall.Signal(0x12),
	"SIGFPE":    syscall.Signal(0x8),
	"SIGHUP":    syscall.Signal(0x1),
	"SIGILL":    syscall.Signal(0x4),
	"SIGINT":    syscall.Signal(0x2),
	"SIGIO":     syscall.Signal(0x1d),
	"SIGIOT":    syscall.Signal(0x6),
	"SIGKILL":   syscall.Signal(0x9),
	"SIGPIPE":   syscall.Signal(0xd),
	"SIGPOLL":   syscall.Signal(0x1d),
	"SIGPROF":   syscall.Signal(0x1b),
	"SIGPWR":    syscall.Signal(0x1e),
	"SIGQUIT":   syscall.Signal(0x3),
	"SIGSEGV":   syscall.Signal(0xb),
	"SIGSTKFLT": syscall.Signal(0x10),
	"SIGSTOP":   syscall.Signal(0x13),
	"SIGSYS":    syscall.Signal(0x1f),
	"SIGTERM":   syscall.Signal(0xf),
	"SIGTRAP":   syscall.Signal(0x5),
	"SIGTSTP":   syscall.Signal(0x14),
	"SIGTTIN":   syscall.Signal(0x15),
	"SIGTTOU":   syscall.Signal(0x16),
	"SIGUNUSED": syscall.Signal(0x1f),
	"SIGURG":    syscall.Signal(0x17),
	"SIGUSR1":   syscall.Signal(0xa),
	"SIGUSR2":   syscall.Signal(0xc),
	"SIGVTALRM": syscall.Signal(0x1a),
	"SIGWINCH":  syscall.Signal(0x1c),
	"SIGXCPU":   syscall.Signal(0x18),
	"SIGXFSZ":   syscall.Signal(0x19),
}

type channelType uint64

const (
	LARVAL = channelType(iota)
	OPEN
)

type openPty struct {
	pty     *os.File // pty used by the server/user to communicate with the running process
	tty     *os.File // tty used by the running process to communicate with the server/user
	winSize *pty.Winsize
	term    string
}

type runningCommand struct {
	exec.Cmd
	stdoutR io.Reader
	stderrR io.Reader
	stdinW  io.Writer
}

// wireExitStatus turns the outcome of a process into the number this request carries.
//
// Go reports -1 for a process which was killed by a signal, and this request has no way of
// saying so (that is what the exit-signal request, which ssh3 does not use yet, is for).
// Turning -1 into a uint64 gives 18446744073709551615, which does not even fit a QUIC
// varint: it used to panic on its way out, and the client was left without an exit status.
// Report it the way a shell does instead, 128 plus the signal number, so that the client
// gets a number it can act on.
func wireExitStatus(state *os.ProcessState) uint64 {
	code := state.ExitCode()
	if code >= 0 {
		return uint64(code)
	}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + uint64(status.Signal())
	}
	// nothing better to go on: 255 is what a shell reports for a command it could not run
	return 255
}

// hangup tells the command of a session that the session is gone, the way a terminal does
// when the connection it belongs to drops. A session with a pty gets that hangup for free
// when the master side is closed; a command on pipes does not, and the end of stdin is no
// use to a program which never reads it. This is what OpenSSH does to its children too.
func (c *runningCommand) hangup() error {
	if c.Process == nil || c.ProcessState != nil {
		// the command never started, or is over and reaped already
		return nil
	}
	// os.Process refuses to signal a process it has already waited for - it answers
	// ErrProcessDone - so this cannot reach a pid the kernel gave to somebody else in the
	// meantime
	if err := c.Process.Signal(syscall.SIGHUP); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

type runningSession struct {
	channelState        channelType
	pty                 *openPty
	runningCmd          *runningCommand
	authAgentSocketPath string
	env                 map[string]string // env requests received while in LARVAL state
}

// var runningSessions = make(map[ssh3.Channel]*runningSession)
//
// The map is keyed on the channel, so an entry keeps the channel - and with it the QUIC
// streams and the datagram queue - alive. It is therefore deleted, and the session
// resources released, as soon as the goroutine reading that channel returns: a session
// which stayed in here would hold its terminal and its pipes for the lifetime of the
// server, and a few thousand logins would end it with "too many open files" for everybody.
var runningSessions = util.NewSyncMap[ssh3.Channel, *runningSession]()

// Close releases everything the session owns which is not closed by the process itself:
// the two ends of the terminal it asked for, and the write end of the command's stdin.
//
// The pty pair is worth spelling out: a shell which exited leaves the master side open on
// our side, and the /dev/pts index allocated with it, until we close it. The stdin write
// end is normally closed by Cmd.Wait(), which is deliberately not used here (it would race
// with the output readers); whoever waits for the process must close it instead.
//
// The command itself is hung up first: a client which disappears would otherwise leave its
// shell - or its loop, or its editor - running on the server for good, memory included.
func (s *runningSession) Close() {
	if s.runningCmd != nil {
		if err := s.runningCmd.hangup(); err != nil {
			log.Warn().Msgf("could not tell the command of a session that it lost its client: %s", err)
		}
	}
	if s.runningCmd != nil && s.runningCmd.stdinW != nil {
		if closer, ok := s.runningCmd.stdinW.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	if s.pty != nil {
		if s.pty.pty != nil {
			_ = s.pty.pty.Close()
		}
		if s.pty.tty != nil {
			_ = s.pty.tty.Close()
		}
	}
}

func setWinsize(f *os.File, charWidth, charHeight, pixWidth, pixHeight uint64) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(charHeight), uint16(charWidth), uint16(pixWidth), uint16(pixHeight)})))
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

func setupEnv(user *unix_util.User, runningCommand *runningCommand, authAgentSocketPath string) {
	// TODO: set the environment like in do_setup_env of https://github.com/openssh/openssh-portable/blob/master/session.c
	runningCommand.Cmd.Env = append(runningCommand.Cmd.Env,
		fmt.Sprintf("HOME=%s", user.Dir),
		fmt.Sprintf("USER=%s", user.Username),
		fmt.Sprintf("LOGNAME=%s", user.Username),
		fmt.Sprintf("SHELL=%s", user.Shell),
		fmt.Sprintf("PATH=%s", "/usr/bin:/bin:/usr/sbin:/sbin"),
	)
	if authAgentSocketPath != "" {
		runningCommand.Cmd.Env = append(runningCommand.Cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", authAgentSocketPath))
	}
}

func isExpectedForwardingStreamClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return streamErr.Remote
	}
	return false
}

func forwardUDPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.UDPConn) {
	go func() {
		defer ssh3.RecoverGoroutine("the UDP forwarding channel datagram loop")
		defer conn.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			datagram, err := channel.ReceiveDatagram(ctx)
			if err != nil {
				log.Error().Msgf("could not receive datagram: %s", err)
				return
			}
			_, err = conn.Write(datagram)
			if err != nil {
				log.Error().Msgf("could not write datagram on UDP socket: %s", err)
				return
			}
		}
	}()

	go func() {
		defer channel.Close()
		defer conn.Close()
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := conn.Read(buf)
			if err != nil {
				log.Error().Msgf("could read datagram on UDP socket: %s", err)
				return
			}
			err = channel.SendDatagram(buf[:n])
			if err != nil {
				log.Error().Msgf("could send datagram on channel: %s", err)
				return
			}
		}
	}()
}

// forwardingDrainTimeout bounds for how long a forwarding target may still
// answer after the other direction has been closed. Half-close semantics are
// preserved (the target gets an EOF on its input and keeps its output until it
// answered), but a read which stays blocked longer than this grace is killed:
// otherwise one silent, never-closing target would park the forwarding
// goroutine, the socket and the QUIC channel forever.
const forwardingDrainTimeout = 30 * time.Second

func forwardTCPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.TCPConn) {
	var directions sync.WaitGroup
	directions.Add(2)
	// both directions being half-closed is not enough for the operating system
	// to release the socket: the file descriptor of a TCP connection is only
	// freed by an explicit Close. Without it, every forwarded connection would
	// keep one descriptor for the lifetime of the whole session, until the
	// process runs out of file descriptors and no new forwarding - dynamic or
	// not - can be served anymore
	go func() {
		directions.Wait()
		conn.Close()
	}()
	go func() {
		defer ssh3.RecoverGoroutine("the TCP forwarding channel read loop")
		defer directions.Done()
		defer func() {
			// half-close the socket, so the target still may answer what it was
			// asked - but bound that chance: a goroutine blocked in conn.Read on a
			// target which neither answers nor closes is woken up by the expiring
			// deadline, instead of leaking one stream per such connection
			conn.CloseWrite()
			conn.SetReadDeadline(time.Now().Add(forwardingDrainTimeout))
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			genericMessage, err := channel.NextMessage()
			if errors.Is(err, io.EOF) || isExpectedForwardingStreamClose(err) {
				log.Debug().Msgf("tcp-forwarding channel %d closed normally: %v", channel.ChannelID(), err)
				return
			} else if err != nil {
				log.Error().Msgf("could get message from tcp forwarding channel: %s", err)
				return
			}

			// nothing to process
			if genericMessage == nil {
				return
			}

			switch message := genericMessage.(type) {
			case *ssh3Messages.DataOrExtendedDataMessage:
				if message.DataType == ssh3Messages.SSH_EXTENDED_DATA_NONE {
					_, err := conn.Write([]byte(message.Data))
					if err != nil {
						log.Error().Msgf("could not write data on TCP socket: %s", err)
						// signal the write error to the peer
						channel.CancelRead()
						return
					}
				} else {
					log.Warn().Msgf("ignoring message data of unexpected type %d on TCP forwarding channel %d", message.DataType, channel.ChannelID())
				}
			default:
				log.Warn().Msgf("ignoring message of type %T on TCP forwarding channel %d", message, channel.ChannelID())
			}
		}
	}()

	go func() {
		defer directions.Done()
		defer channel.Close()
		defer conn.CloseRead()
		buf := make([]byte, channel.MaxPacketSize())
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := conn.Read(buf)
			if err != nil {
				if isExpectedForwardingStreamClose(err) {
					log.Debug().Msgf("TCP forwarding socket closed normally on server channel %d: %v", channel.ChannelID(), err)
					return
				}
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// the other direction was closed and the target did not answer
					// within the grace period: give up on it
					log.Debug().Msgf("TCP forwarding to %s timed out while draining channel %d: %s", conn.RemoteAddr(), channel.ChannelID(), err)
					return
				}
				log.Error().Msgf("could read data on TCP socket: %s", err)
				return
			}
			_, errWrite := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if errWrite != nil {
				if isExpectedForwardingStreamClose(errWrite) {
					log.Debug().Msgf("server TCP forwarding channel closed normally while writing on channel %d: %v", channel.ChannelID(), errWrite)
					return
				}
				switch quicErr := errWrite.(type) {
				case *quic.StreamError:
					if quicErr.Remote && quicErr.ErrorCode == 42 {
						log.Info().Msgf("writing was canceled by the remote, closing the socket")
					} else {
						log.Error().Msgf("unhandled quic stream error: %+v", quicErr)
					}
				default:
					log.Error().Msgf("could send data on channel: %s", errWrite)
				}
				return
			}
		}
	}()
}

func forwardReverseTCPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.TCPConn) {
	var directions sync.WaitGroup
	directions.Add(2)
	// same as forwardTCPInBackground: half-closing both directions does not free
	// the file descriptor, only Close does
	go func() {
		directions.Wait()
		conn.Close()
	}()
	go func() {
		defer directions.Done()
		defer channel.Close()
		defer conn.CloseRead()
		buf := make([]byte, channel.MaxPacketSize())
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := conn.Read(buf)
			if err != nil && err != io.EOF {
				log.Error().Msgf("could read data on TCP socket: %s", err)
				return
			}
			_, errWrite := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if errWrite != nil {
				switch quicErr := errWrite.(type) {
				case *quic.StreamError:
					if quicErr.Remote && quicErr.ErrorCode == 42 {
						log.Info().Msgf("writing was canceled by the remote, closing the socket: %s", errWrite)
					} else {
						log.Error().Msgf("unhandled quic stream error: %+v", quicErr)
					}
				default:
					log.Error().Msgf("could send data on channel: %s", errWrite)
				}
				return
			}
			if err == io.EOF {
				return
			}
		}
	}()

	go func() {
		defer ssh3.RecoverGoroutine("the reverse TCP forwarding channel read loop")
		defer directions.Done()
		defer conn.CloseWrite()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			genericMessage, err := channel.NextMessage()
			if err == io.EOF {
				log.Info().Msgf("eof on reverse-tcp-forwarding channel %d", channel.ChannelID())
			} else if err != nil {
				log.Error().Msgf("could get message from tcp forwarding channel: %s", err)
				return
			}

			// nothing to process
			if genericMessage == nil {
				return
			}

			switch message := genericMessage.(type) {
			case *ssh3Messages.DataOrExtendedDataMessage:
				if message.DataType == ssh3Messages.SSH_EXTENDED_DATA_NONE {
					_, err := conn.Write([]byte(message.Data))
					if err != nil {
						log.Error().Msgf("could not write data on TCP socket: %s", err)
						// signal the write error to the peer
						channel.CancelRead()
						return
					}
				} else {
					log.Warn().Msgf("ignoring message data of unexpected type %d on TCP forwarding channel %d", message.DataType, channel.ChannelID())
				}
			default:
				log.Warn().Msgf("ignoring message of type %T on TCP forwarding channel %d", message, channel.ChannelID())
			}
		}
	}()

}

func execCmdInBackground(channel ssh3.Channel, openPty *openPty, user *unix_util.User, runningCommand *runningCommand, authAgentSocketPath string) error {
	setupEnv(user, runningCommand, authAgentSocketPath)
	if openPty != nil {
		err := unix_util.StartWithSizeAndPty(&runningCommand.Cmd, openPty.winSize, openPty.pty, openPty.tty)
		if err != nil {
			return err
		}
	} else {
		err := runningCommand.Start()
		if err != nil {
			return err
		}
	}

	go func() {
		defer ssh3.RecoverGoroutine("the command output forwarder")

		type readResult struct {
			data []byte
			err  error
		}

		stdoutChan := make(chan readResult, 1)
		stderrChan := make(chan readResult, 1)
		execResultChan := make(chan error, 1)
		execExitStatus := uint64(0)

		readStdout := func() {
			defer ssh3.RecoverGoroutine("the command stdout reader")
			defer close(stdoutChan)
			defer func() {
				// the pipe read ends are no longer closed by Wait() (see below), so we
				// close them once the output is fully read to avoid leaking file descriptors
				if closer, ok := runningCommand.stdoutR.(io.Closer); ok {
					closer.Close()
				}
			}()
			if runningCommand.stdoutR != nil {
				for {
					buf := make([]byte, channel.MaxPacketSize())
					n, err := runningCommand.stdoutR.Read(buf)
					out := make([]byte, n)
					copy(out, buf[:n])
					stdoutChan <- readResult{data: out, err: err}
					if err != nil {
						return
					}
				}
			}
		}
		readStderr := func() {
			defer ssh3.RecoverGoroutine("the command stderr reader")
			defer close(stderrChan)
			defer func() {
				if closer, ok := runningCommand.stderrR.(io.Closer); ok {
					closer.Close()
				}
			}()
			if runningCommand.stderrR != nil {
				for {
					buf := make([]byte, channel.MaxPacketSize())
					n, err := runningCommand.stderrR.Read(buf)
					out := make([]byte, n)
					copy(out, buf[:n])
					stderrChan <- readResult{data: out, err: err}
					if err != nil {
						return
					}
				}
			}
		}

		go readStdout()
		go readStderr()
		go func() {
			defer ssh3.RecoverGoroutine("the command waiter")
			// Use Process.Wait() rather than Cmd.Wait(): the latter closes the stdout
			// and stderr pipe read ends after the process exits, racing with the
			// readStdout/readStderr goroutines above and potentially discarding the
			// command output (Read then returns os.ErrClosed). The pipes are closed
			// explicitly once fully read instead. Cmd.Wait() only additionally wraps
			// the error in an *exec.ExitError, which is reconstructed here.
			state, _ := runningCommand.Process.Wait()
			var waitErr error
			if state != nil && !state.Success() {
				waitErr = &exec.ExitError{ProcessState: state}
			}
			execResultChan <- waitErr
			close(execResultChan)
		}()

		for {
			select {
			case stdoutResult, ok := <-stdoutChan:
				if !ok {
					// disable the channel: a select on a nil is always blocking
					stdoutChan = nil
				} else {
					buf, err := stdoutResult.data, stdoutResult.err
					// an error could be returned but still with relevant data, so first send the data
					_, err2 := channel.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_NONE)
					if err2 != nil {
						log.Error().Msgf("could not write the pty's output in an SSH message: %+v\n", err)
						return
					}
					if err != nil && !errors.Is(err, io.EOF) {
						log.Info().Msgf("could not read the pty's output, it might have been closed by the running process: %s", err)
					}
				}

			case stderrResult, ok := <-stderrChan:
				if !ok {
					// disable the channel: a select on a nil is always blocking
					stderrChan = nil
				} else {
					buf, err := stderrResult.data, stderrResult.err
					_, err2 := channel.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_STDERR)
					if err2 != nil {
						log.Error().Msgf("could not write the pty's output in an SSH message: %+v\n", err)
						return
					}
					if err != nil && !errors.Is(err, io.EOF) {
						log.Info().Msgf("could not read the pty's error output, it might have been closed by the running process: %s", err)
					}
				}

			case err, ok := <-execResultChan:
				if !ok {
					// disable the channel: a select on a nil is always blocking
					execResultChan = nil
				} else {
					execExitStatus = uint64(0)
					if err != nil {
						if exitError, ok := err.(*exec.ExitError); ok {
							execExitStatus = wireExitStatus(exitError.ProcessState)
						}
					}
				}
			}
			if stdoutChan == nil && stderrChan == nil && execResultChan == nil {
				// The process is gone and everything it printed has been forwarded. Its
				// stdin, which Cmd.Wait() would have closed for us, is closed here: left
				// open, one pipe end leaks per command executed on the server, forever.
				if runningCommand.stdinW != nil {
					if closer, ok := runningCommand.stdinW.(io.Closer); ok {
						_ = closer.Close()
					}
				}
				err := channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
					WantReply:      false,
					ChannelRequest: &ssh3Messages.ExitStatusRequest{ExitStatus: execExitStatus},
				})
				if err != nil {
					log.Error().Msgf("Could not send exit status message to the peer: %s", err)
				}
				// both channels are closed, nothing else to do, return
				return
			}
		}
	}()
	return nil
}

func newPtyReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.PtyRequest, wantReply bool) error {
	var session *runningSession
	session, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("internal error: cannot find session for current channel")
	}

	if session.channelState != LARVAL {
		return fmt.Errorf("cannot request new pty on already established session")
	}

	if session.pty != nil {
		return fmt.Errorf("cannot request new pty on a channel with an already existing pty")
	}
	winSize := &pty.Winsize{Rows: uint16(request.CharHeight), Cols: uint16(request.CharWidth), X: uint16(request.PixelWidth), Y: uint16(request.PixelHeight)}
	pty, tty, err := pty.Open()
	if err != nil {
		return err
	}

	setWinsize(pty, request.CharWidth, request.CharHeight, request.PixelWidth, request.PixelHeight)

	session.pty = &openPty{
		pty:     pty,
		tty:     tty,
		term:    request.Term,
		winSize: winSize,
	}

	return nil
}

func newX11Req(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.X11Request, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

// rejectShellRequest refuses an interactive shell when the identity which authenticated
// the conversation is restricted to a command: what such an identity may run is exactly
// the command it names, and a shell is not it. Ending the session is what a denied
// restriction means here; carrying on because the client asked for a shell would make the
// restriction decorative.
func rejectShellRequest(identityOptions *ssh3.IdentityOptions) error {
	if identityOptions != nil && identityOptions.ForcedCommand != "" {
		return fmt.Errorf("refusing the shell request: the identity which authenticated this conversation is "+
			"restricted to the command %q", identityOptions.ForcedCommand)
	}
	return nil
}

func newCommand(user *unix_util.User, channel ssh3.Channel, loginShell bool, command string, args ...string) error {
	var session *runningSession
	session, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("internal error: cannot find session for current channel")
	}

	if session.channelState != LARVAL {
		return fmt.Errorf("cannot request new shell on already established session")
	}

	env := ""
	if session.pty != nil {
		env = fmt.Sprintf("TERM=%s", session.pty.term)
	}

	var stdoutR, stderrR, stdinR io.Reader
	var stdoutW, stderrW, stdinW io.Writer
	var err error = nil
	var cmd *exec.Cmd

	if session.pty != nil {
		stdoutW = session.pty.tty
		stderrW = session.pty.tty
		stdinR = session.pty.tty

		stdoutR = session.pty.pty
		stderrR = nil
		stdinW = session.pty.pty
		cmd, _, _, _, err = user.CreateCommand(env, stdoutW, stderrW, stdinR, loginShell, command, args...)
	} else {
		// CreateCommandPipeOutput creates the pipes of the command it returns, and returns
		// them: they must not be created here as well, or the three pairs created are six
		// file descriptors which belong to nothing and stay open forever.
		cmd, stdoutR, stderrR, stdinW, err = user.CreateCommandPipeOutput(env, loginShell, command, args...)
	}

	if err != nil {
		return err
	}

	runningCommand := &runningCommand{
		Cmd:     *cmd,
		stdoutR: stdoutR,
		stderrR: stderrR,
		stdinW:  stdinW,
	}

	// apply the environment variables requested by the client (SetEnv/SendEnv)
	for name, value := range session.env {
		runningCommand.Cmd.Env = append(runningCommand.Cmd.Env, name+"="+value)
	}

	session.runningCmd = runningCommand

	session.channelState = OPEN

	return execCmdInBackground(channel, session.pty, user, session.runningCmd, session.authAgentSocketPath)
}

func newShellReq(user *unix_util.User, channel ssh3.Channel, wantReply bool) error {
	return newCommand(user, channel, true, user.Shell)
}

// similar to OpenSSH: environment variables are only accepted while the
// channel is still in LARVAL state, i.e. before a shell or a command has
// been started. They are stored in the session and applied to the process
// when it is started by newCommand.
func newEnvReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.EnvRequest, wantReply bool) error {
	session, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("cannot find session for current channel")
	}

	if session.channelState != LARVAL {
		return fmt.Errorf("cannot request a new environment variable on an already established session")
	}

	if request.Name == "" {
		return fmt.Errorf("empty environment variable name")
	}
	if session.env == nil {
		session.env = make(map[string]string)
	}
	session.env[request.Name] = request.Value
	log.Debug().Msgf("added environment variable %s to session", request.Name)
	return nil
}

// similar behaviour to OpenSSH; exec requests are just pasted in the user's shell
func newCommandInShellReq(user *unix_util.User, channel ssh3.Channel, wantReply bool, command string) error {
	return newCommand(user, channel, false, user.Shell, "-c", command)
}

func newSubsystemReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.SubsystemRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newWindowChangeReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.WindowChangeRequest, wantReply bool) error {
	session, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("cannot find session for current channel")
	}
	ws := winsize.WindowSize{
		NRows:       uint16(request.CharHeight),
		NCols:       uint16(request.CharWidth),
		PixelWidth:  uint16(request.PixelWidth),
		PixelHeight: uint16(request.PixelHeight),
	}
	// the terminal is what this request resizes: without one there is nothing to resize.
	// There is no reason to die over it - a client may send window-change before pty-req,
	// or without pty-req at all.
	if session.pty == nil || session.pty.pty == nil {
		return fmt.Errorf("cannot change the window size of a session without a pty")
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, session.pty.pty.Fd(), uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return fmt.Errorf("ioctl failed: %v", errno)
	}
	return nil
}

func newSignalReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.SignalRequest, wantReply bool) error {
	runningSession, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("could not find running session for channel %d (conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	if runningSession.channelState == LARVAL {
		return fmt.Errorf("cannot send signal for channel in LARVAL state (channel %d, conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	switch channel.ChannelType() {
	case "session":
		if runningSession.runningCmd == nil {
			return fmt.Errorf("there is no running command on Channel %d (conv %d) to feed the received data", channel.ChannelID(), channel.ConversationID())
		}
		signal, ok := signals["SIG"+request.SignalNameWithoutSig]
		if !ok {
			return fmt.Errorf("unhandled signal SIG%s", request.SignalNameWithoutSig)
		}
		runningSession.runningCmd.Process.Signal(signal)
	default:
		return fmt.Errorf("channel type %s not implemented", channel.ChannelType())
	}
	return nil
}

func newExitStatusReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.ExitStatusRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newExitSignalReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.ExitSignalRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func handleUDPForwardingChannel(ctx context.Context, user *unix_util.User, conv *ssh3.Conversation, channel *ssh3.UDPForwardingChannelImpl) error {
	// TODO: currently, the rights for socket creation are not checked. The socket is opened with the process's uid and gid
	// Not sure how to handled that in go since we cannot temporarily change the uid/gid without potentially impacting every
	// other goroutine
	conn, err := net.DialUDP("udp", nil, channel.RemoteAddr)
	if err != nil {
		return err
	}
	forwardUDPInBackground(ctx, channel, conn)
	return nil
}

// forwardingConnectTimeout bounds the connection attempt to a forwarding
// target. Without a timeout, dialing an unreachable address (SYN dropped by a
// firewall for instance) hangs for the whole kernel TCP timeout, and every
// request behind such a target used to stop the whole forwarding machinery.
const forwardingConnectTimeout = 30 * time.Second

func handleTCPForwardingChannel(ctx context.Context, user *unix_util.User, conv *ssh3.Conversation, channel *ssh3.TCPForwardingChannelImpl) error {
	// TODO: currently, the rights for socket creation are not checked. The socket is opened with the process's uid and gid
	// Not sure how to handled that in go since we cannot temporarily change the uid/gid without potentially impacting every
	// other goroutine
	//
	// The connection to the target is established in the background: the conversation
	// channel accept loop must never block on it, otherwise one request to a dead or
	// firewalled target stalls every other forwarding of the same session (the proxy
	// appears to "eventually stop responding": channels are queued until the blocked
	// dial finally fails, then all the stale queued requests hit their targets at once).
	go func() {
		dialer := net.Dialer{Timeout: forwardingConnectTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", channel.RemoteAddr.String())
		if err != nil {
			log.Error().Msgf("could not dial TCP target %s on channel %d: %s", channel.RemoteAddr, channel.ChannelID(), err)
			// the channel was already confirmed: closing it is how the failure is
			// signalled to the client, which then aborts the tunneled connection
			// instead of waiting forever for a response that will never come
			channel.Close()
			return
		}
		forwardTCPInBackground(ctx, channel, conn.(*net.TCPConn))
	}()
	return nil
}

// Copied from client.go ForwardTCP()
// closeWhenDone closes closer once the conversation is over. For a socket it is also how
// the loop blocked in Accept/ReadFromUDP gets released, so that a forwarding does not
// outlive the client which asked for it - and, in the case of a listening socket, does not
// keep the port bound so that it can never be forwarded again.
func closeWhenDone(ctx context.Context, closer io.Closer, what string) {
	<-ctx.Done()
	if err := closer.Close(); err != nil {
		log.Debug().Msgf("could not close the %s: %s", what, err)
	}
}

func handleTCPReverseForwardingChannel(ctx context.Context, user *unix_util.User, conv *ssh3.Conversation, channel *ssh3.TCPReverseForwardingChannelImpl) error {
	listener, err := net.ListenTCP("tcp", channel.LocalAddr)
	if err != nil {
		log.Error().Msgf("could not listen on %s for the reverse TCP forwarding: %s", channel.LocalAddr, err)
		// The channel has been confirmed before this is called, so closing it is the only
		// way to tell the client that the port it asked for is not forwarded at all.
		// Returning nil, as this used to, leaves the client - and the user - believing it is.
		channel.Close()
		return err
	}
	go closeWhenDone(ctx, listener, fmt.Sprintf("reverse TCP forwarding socket on %s", channel.LocalAddr))

	go func() {
		defer ssh3.RecoverGoroutine("the reverse TCP forwarding accept loop")
		defer listener.Close()
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				// the usual way out: the conversation ended and closed the listener
				log.Debug().Msgf("no more connections on the reverse TCP forwarding: %s", err)
				return
			}

			forwardingChannel, err := conv.OpenTCPReverseForwardingChannel(30000, 10, channel.RemoteAddr)
			if err != nil {
				log.Error().Msgf("could not open new TCP reverse forwarding channel: %s", err)
				// nobody is going to carry this connection: hanging up is what tells the peer
				// which connected to the forwarded port that there is nothing behind it
				conn.Close()
				return
			}
			forwardReverseTCPInBackground(ctx, forwardingChannel, conn)
		}
	}()
	return nil
}

// Functions below should be included in a package to avoid reusing them aswell in ssh3-server.go

func ListenUDPReuse(ctx context.Context, network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(netw, addr string, c syscall.RawConn) error {
			var firstErr error
			c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil && firstErr == nil {
					firstErr = fmt.Errorf("SO_REUSEADDR: %w", err)
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil && firstErr == nil {
					firstErr = fmt.Errorf("SO_REUSEPORT: %w", err)
				}
			})
			return firstErr
		},
	}

	pc, err := lc.ListenPacket(ctx, network, laddr.String()) // "udp", "udp4", or "udp6"
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("not a UDP socket")
	}
	return uc, nil
}

// ListenUDPWithAutoMulticast listens on udpAddr.
// If udpAddr.IP is multicast, it binds to the wildcard address on the same
// family+port and joins the multicast group. Otherwise it just listens normally.
//
// If ifaceName is non-empty, it will join only on that interface.
// Otherwise it tries all "up" multicast-capable interfaces (excluding loopback).
func ListenUDPWithAutoMulticast(udpAddr *net.UDPAddr, ifaceName string) (*net.UDPConn, error) {
	if udpAddr == nil {
		return nil, fmt.Errorf("nil UDPAddr")
	}
	isV4 := udpAddr.IP.To4() != nil

	// Non-multicast or unspecified: plain listen in the right family.
	if udpAddr.IP == nil || !udpAddr.IP.IsMulticast() {
		network := "udp"
		if isV4 {
			network = "udp4"
		} else {
			network = "udp6"
		}
		return net.ListenUDP(network, udpAddr)
	}

	// Multicast: bind to wildcard in the right family.
	var bind *net.UDPAddr
	var network string
	if isV4 {
		bind = &net.UDPAddr{IP: net.IPv4zero, Port: udpAddr.Port}
		network = "udp4"
	} else {
		bind = &net.UDPAddr{IP: net.IPv6unspecified, Port: udpAddr.Port}
		network = "udp6"
	}

	var err error
	var conn *net.UDPConn
	if conn == nil {
		//conn, err = net.ListenUDP(network, bind)
		conn, err = ListenUDPReuse(context.Background(), network, bind)
		if err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
		// Linux: ensure we only receive groups we actually join.
		if runtime.GOOS == "linux" {
			if err := disableMulticastAll(conn); err != nil {
				// consider returning the error; otherwise log loudly
				return nil, fmt.Errorf("disableMulticastAll: %w", err)
			}
		}
	}
	// Join group (same join helpers as before)
	if isV4 {
		// Belt-and-braces: filter by destination IP from control messages.
		p := ipv4.NewPacketConn(conn)
		if err := joinOnInterfacesV4(p, udpAddr, ifaceName); err != nil {
			conn.Close()
			return nil, err
		}

	} else {
		p := ipv6.NewPacketConn(conn)
		if err := joinOnInterfacesV6(p, udpAddr, ifaceName); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func joinOnInterfacesV4(p *ipv4.PacketConn, group *net.UDPAddr, ifaceName string) error {
	if ifaceName != "" {
		ifi, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("iface '%s': %w", ifaceName, err)
		}
		return p.JoinGroup(ifi, &net.UDPAddr{IP: group.IP})
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list ifaces: %w", err)
	}

	var errs []string
	joined := 0
	for _, ifi := range ifaces {
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagMulticast) == 0 || (ifi.Flags&net.FlagLoopback) != 0 {
			continue
		}
		if err := p.JoinGroup(&ifi, &net.UDPAddr{IP: group.IP}); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ifi.Name, err))
			continue
		}
		joined++
	}
	if joined == 0 {
		if len(errs) > 0 {
			return errors.New("failed to join on any iface: " + strings.Join(errs, "; "))
		}
		return errors.New("no suitable interfaces found to join multicast")
	}
	return nil
}

func joinOnInterfacesV6(p *ipv6.PacketConn, group *net.UDPAddr, ifaceName string) error {
	if ifaceName != "" {
		ifi, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("iface '%s': %w", ifaceName, err)
		}
		return p.JoinGroup(ifi, &net.UDPAddr{IP: group.IP})
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list ifaces: %w", err)
	}

	var errs []string
	joined := 0
	for _, ifi := range ifaces {
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagMulticast) == 0 || (ifi.Flags&net.FlagLoopback) != 0 {
			continue
		}
		if err := p.JoinGroup(&ifi, &net.UDPAddr{IP: group.IP}); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ifi.Name, err))
			continue
		}
		joined++
	}
	if joined == 0 {
		if len(errs) > 0 {
			return errors.New("failed to join on any iface: " + strings.Join(errs, "; "))
		}
		return errors.New("no suitable interfaces found to join multicast")
	}
	return nil
}

func disableMulticastAll(uc *net.UDPConn) error {
	rc, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		// IP_MULTICAST_ALL = 49 on Linux; use unix.IP_MULTICAST_ALL for portability.
		// but this function is only needed on linux, and unix.IP_MULTICAST_ALL does not exist on mac
		// https://pkg.go.dev/golang.org/x/sys/unix#pkg-constants
		if e := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, 0x31, 0); e != nil {
			serr = e
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// maxReverseUDPFlows bounds, for one reverse UDP forwarding, how many peers may have a
// channel open at the same time. The peers are the addresses the datagrams come from, so
// without a bound anything able to throw a datagram at the forwarded port - a broadcast or
// multicast address included - would get a QUIC channel, a goroutine and a table entry
// each, and keep them, since a peer which stops answering is never noticed.
const maxReverseUDPFlows = 1000

func handleUDPReverseForwardingChannel(ctx context.Context, user *unix_util.User, conv *ssh3.Conversation, ch *ssh3.UDPReverseForwardingChannelImpl) error {
	conn, err := ListenUDPWithAutoMulticast(ch.LocalAddr, "")
	//conn, err := net.ListenUDP("udp", ch.LocalAddr)
	if err != nil {
		log.Error().Msgf("could not listen on %s for the reverse UDP forwarding: %s", ch.LocalAddr, err)
		// see handleTCPReverseForwardingChannel: the confirmed channel is the only handle on
		// the failure, and closing it is how the client learns the forward is not up
		ch.Close()
		return err
	}
	go closeWhenDone(ctx, conn, fmt.Sprintf("reverse UDP forwarding socket on %s", ch.LocalAddr))

	flows := util.NewPeerTable[ssh3.Channel](maxReverseUDPFlows)
	go func() {
		defer ssh3.RecoverGoroutine("the reverse UDP forwarding read loop")
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				// the usual way out: the conversation ended and closed the socket
				log.Debug().Msgf("no more datagrams on the reverse UDP forwarding: %s", err)
				return
			}
			channel, ok := flows.Get(addr.String())
			if !ok {
				newChannel, err := conv.OpenUDPReverseForwardingChannel(30000, 10, ch.LocalAddr, ch.RemoteAddr)
				if err != nil {
					log.Error().Msgf("could not open new UDP reverse forwarding channel: %s", err)
					return
				}
				if !flows.Add(addr.String(), newChannel) {
					newChannel.Close()
					log.Warn().Msgf("more than %d peers on the reverse UDP forwarding on %s, dropping datagram from %s",
						maxReverseUDPFlows, ch.LocalAddr, addr)
					continue
				}
				channel = newChannel
				go func() {
					defer ssh3.RecoverGoroutine("the reverse UDP forwarding channel datagram loop")
					// the peer may come back later and get a channel again: what must not
					// happen is a peer which went away keeping its entry forever
					defer flows.Remove(addr.String())
					for {
						dgram, err := channel.ReceiveDatagram(ctx)
						if err != nil {
							log.Error().Msgf("could not receive datagram on channel: %s", err)
							return
						}
						_, err = conn.WriteToUDP(dgram, addr)
						if err != nil {
							log.Error().Msgf("could not write datagram on socket: %s", err)
							return
						}
					}
				}()
			}

			err = channel.SendDatagram(buf[:n])
			if err != nil {
				log.Error().Msgf("could not send datagram: %s", err)
				return
			}
		}
	}()
	return nil
}

func newDataReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.DataOrExtendedDataMessage) error {
	runningSession, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("could not find running session for channel %d (conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	if runningSession.channelState == LARVAL {
		return fmt.Errorf("cannot receive data for channel in LARVAL state (channel %d, conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	switch channel.ChannelType() {
	case "session":
		if runningSession.runningCmd == nil {
			return fmt.Errorf("there is no running command on Channel %d (conv %d) to feed the received data", channel.ChannelID(), channel.ConversationID())
		}
		switch request.DataType {
		case ssh3Messages.SSH_EXTENDED_DATA_NONE:
			runningSession.runningCmd.stdinW.Write([]byte(request.Data))
		default:
			return fmt.Errorf("extended data type forbidden server PTY")
		}
	default:
		return fmt.Errorf("channel type %s not implemented", channel.ChannelType())
	}
	return nil
}

func handleAuthAgentSocketConn(conn net.Conn, conversation *ssh3.Conversation) {
	// one goroutine per accepted agent-socket connection, reading messages which come
	// from the network: see ssh3.RecoverGoroutine
	defer ssh3.RecoverGoroutine("the SSH agent socket connection handler")
	channel, err := conversation.OpenChannel("agent-connection", 30000, 10)
	if err != nil {
		log.Error().Msgf("could not open channel from server: %s", err.Error())
		return
	}
	go func() {
		defer ssh3.RecoverGoroutine("the SSH agent socket to client pipe")
		defer channel.Close()
		buf := make([]byte, channel.MaxPacketSize())
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Info().Msgf("could not read data socket %d: %s", channel.ChannelID(), err.Error())
				return
			}
			_, err = channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if err != nil {
				log.Info().Msgf("could not write data on agent channel %d: %s", channel.ChannelID(), err.Error())
				return
			}
		}
	}()
	for {
		genericMessage, err := channel.NextMessage()
		if err != nil {
			log.Error().Msgf("could not get data from channel %d: %s", channel.ChannelID(), err.Error())
			return
		}
		switch message := genericMessage.(type) {
		case *ssh3Messages.DataOrExtendedDataMessage:
			_, err := conn.Write([]byte(message.Data))
			if err != nil {
				log.Error().Msgf("could not write data to channel %d: %s", channel.ChannelID(), err.Error())
				return
			}
		default:
			log.Error().Msgf("unhandled message type on agent channel %T", message)
			return
		}
	}
}

func listenAndAcceptAuthSockets(cancel context.CancelCauseFunc, conversation *ssh3.Conversation, listener net.Listener, maxSSHPacketSize uint64, socketDir string) {
	defer cancel(nil)
	defer listener.Close()
	// the directory of the agent socket was created for this conversation only, and nobody
	// but it can use it: it must not stay behind, or every agent-forwarded session leaves an
	// orphan directory in /tmp
	defer os.RemoveAll(socketDir)
	for {
		log.Debug().Msg("waiting for new agent connections to forward")
		conn, err := listener.Accept()
		if err != nil {
			log.Error().Msgf("error while listening for agent connections: %s", err.Error())
			cancel(err)
			return
		}
		// new ssh agent client
		go handleAuthAgentSocketConn(conn, conversation)
	}
}

func openAgentSocketAndForwardAgent(parent context.Context, conv *ssh3.Conversation, user *unix_util.User) (string, error) {
	sockPath, err := unix_util.NewUnixSocketPath()
	if err != nil {
		return "", err
	}

	// whatever goes wrong below, the directory created for the socket must not stay behind:
	// every session asking for agent forwarding would otherwise leave one in /tmp forever
	sockDir := path.Dir(sockPath)
	defer func() {
		if err != nil {
			_ = os.RemoveAll(sockDir)
		}
	}()

	var listener net.ListenConfig
	agentSock, err := listener.Listen(parent, "unix", sockPath)
	if err != nil {
		log.Error().Msgf("could not listen on agent socket: %s", err.Error())
		return "", err
	}
	// Giving a context to Listen does not make the socket close when that context is done, it
	// only bounds the call itself. Without closing it by hand the accept loop below never
	// notices the conversation ended: the goroutine, the socket file and the directory holding
	// it stayed behind for the whole life of the server, and anything able to reach the stale
	// socket was handed a conversation which no longer existed.
	go closeWhenDone(parent, agentSock, "the SSH agent socket")

	err = os.Chown(sockDir, int(user.Uid), int(user.Gid))
	if err != nil {
		log.Error().Msgf("could chown the directory of the listening socket at %s: %s", sockPath, err.Error())
		agentSock.Close()
		return "", err
	}
	err = os.Chown(sockPath, int(user.Uid), int(user.Gid))
	if err != nil {
		log.Error().Msgf("could chown the listening socket at %s: %s", sockPath, err.Error())
		agentSock.Close()
		return "", err
	}

	// the context is only worth creating once the socket exists: it is the accept loop's to
	// cancel, and an error path returning before that would leak it
	_, cancel := context.WithCancelCause(parent)
	go listenAndAcceptAuthSockets(cancel, conv, agentSock, 30000, sockDir)
	return sockPath, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

type autogenCertificates []string

func (i *autogenCertificates) String() string {
	return fmt.Sprint(*i)
}

func (i *autogenCertificates) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func ServerMain() int {
	// SFTP child handler entry point. This must run before flag parsing and
	// server initialization so that the forked SFTP worker starts with the
	// smallest possible surface and with the authenticated user's privileges.
	if os.Getenv("SSHOQ_SFTP_CHILD") == "1" {
		return ssh3sftp.RunHandler(context.Background())
	}

	bindAddr := flag.String("bind", "[::]:443", "the address:port pair to listen to, e.g. 0.0.0.0:443")
	verbose := flag.Bool("v", false, "verbose mode, if set")
	displayVersion := flag.Bool("version", false, "if set, displays the software version on standard output and exit")
	urlPath := flag.String("url-path", "/sshoq-server", "the secret URL path on which the ssh3 server listens")
	disableSFTP := flag.Bool("disable-sftp", false, "if set, disable the built-in SFTP channel handler on the server")
	generateSelfSignedCert := flag.Bool("generate-selfsigned-cert", false, "if set, generates a self-self-signed cerificate and key "+
		"that will be stored at the paths indicated by the -cert and -key args (they must not already exist)")
	certPath := flag.String("cert", "./cert.pem", "the filename of the server certificate (or fullchain)")
	keyPath := flag.String("key", "./priv.key", "the filename of the certificate private key")
	var autogenCertificates autogenCertificates
	flag.Var(&autogenCertificates, "generate-public-cert", "Automatically produce and use a valid public certificate using"+
		"Let's Encrypt for the provided domain name. The flag can be used several times to generate several certificates."+
		"If certificates have already been generated previously using this flag, "+
		"they will simply be reused without being regenerated. The public certificates are automatically renewed as long as the "+
		"server is running. Automatically-generated IP public certificates are not available yet.")
	enablePasswordLogin := false
	if unix_util.PasswordAuthAvailable() {
		flag.BoolVar(&enablePasswordLogin, "enable-password-login", false, "if set, enable password authentication (disabled by default)")
	}
	remoteForward := flag.String("R", "", "connect to an existing remote sshoq server and ask it to open a port on its localhost, " +
		"forwarding the traffic of that port to this local sshoq server. Syntax: user@host:port/url-path%remote-port " +
		"(e.g. user@example.com:4443/sshoq-remote%4444). Users can then point a normal sshoq client at " +
		"the remote host's localhost:remote-port to reach this server, even when it sits behind a NAT. " +
		"The destination on this host defaults to this server's own -bind port and may be spelled out as " +
		"user@host:port/url-path%remote-port@localip@localport.")
	flag.StringVar(remoteForward, "remote-forward", "", "alias for -R")
	var remotePublicKeys stringSliceFlag
	flag.Var(&remotePublicKeys, "rpub", "authorize a public key in the memory of this server run only, without adding it to " +
		"~/.ssh3/authorized_identities, so that whoever holds the matching private key can connect - typically through the -R " +
		"forwarded port - without a password and without the key being installed on any file, on either side of the connection. " +
		"The argument is either the public key itself (\"ssh-ed25519 AAAA... comment\") or the name of a file containing one. " +
		"May be specified multiple times.")
	flag.Var(&remotePublicKeys, "remote-public-key", "alias for -rpub")
	var cmdlinePubkeys stringSliceFlag
	flag.Var(&cmdlinePubkeys, "pubkey", "authorize a public key for this server run only, exactly like -rpub, but with no " +
		"relation to -R: the key is held in the memory of the server, it is never added to ~/.ssh3/authorized_identities " +
		"nor to ~/.ssh/authorized_keys, and it stops being accepted as soon as the server stops. " +
		"The argument is either the public key itself (\"ssh-ed25519 AAAA... comment\") or the name of a file containing one. " +
		"May be specified multiple times.")
	var remoteForwardIdentities stringSliceFlag
	flag.Var(&remoteForwardIdentities, "R-identity", "private key file used to authenticate to the remote sshoq server given with -R. "+
		"May be specified multiple times; the default ~/.ssh keys are used when absent.")
	remoteForwardInsecure := flag.Bool("R-insecure", false, "if set, skip the server certificate verification of the remote sshoq server connected to with -R")
	flag.Parse()

	// validate the -R argument before anything else, so that a bad spec fails
	// the startup rather than being noticed only in the log file, minutes after
	// the certificates were loaded and the server announced itself
	var reverseTunnelCfg *reverseTunnelConfig
	if *remoteForward != "" {
		var err error
		reverseTunnelCfg, err = parseReverseTunnelSpec(*remoteForward, *bindAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			return -1
		}
	}

	// the public keys given with -pubkey and -rpub are authorized in the memory of
	// this server run only: nothing is ever added to ~/.ssh3/authorized_identities,
	// on either side of a -R connection. They are registered before the server can
	// accept anything, direct or forwarded, so that the first connection through
	// the tunnel already finds the key it is going to authenticate with.
	if len(cmdlinePubkeys)+len(remotePublicKeys) > 0 {
		identityLines, err := collectStaticAuthorizedIdentities(append(append([]string{}, cmdlinePubkeys...), remotePublicKeys...))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			return -1
		}
		server_auth.AddStaticAuthorizedIdentities(identityLines...)
		fmt.Fprintf(os.Stderr, "Authorized %d public key(s) from -pubkey/-rpub for this server run only (no identities file was modified)\n",
			len(identityLines))
	}

	if *displayVersion {
		fmt.Fprintln(os.Stdout, filepath.Base(os.Args[0]), "version", ssh3.GetCurrentSoftwareVersion())
		return 0
	}

	internal.CloseClientPluginsRegistry()
	internal.CloseServerPluginsRegistry()

	if !enablePasswordLogin {
		fmt.Fprintln(os.Stderr, "password login is disabled")
	}

	certPathExists := fileExists(*certPath)
	keyPathExists := fileExists(*keyPath)

	// handle bad case where one of the cert or key path is valid but not the other
	badCertificatesConf := (certPathExists && !keyPathExists) ||
		(!certPathExists && keyPathExists) ||
		(!certPathExists && !keyPathExists && !*generateSelfSignedCert && len(autogenCertificates) == 0) // no certificate available whatsoever

	if badCertificatesConf {
		if !certPathExists {
			fmt.Fprintf(os.Stderr, "the \"%s\" certificate file does not exist\n", *certPath)
		}
		if !keyPathExists {
			fmt.Fprintf(os.Stderr, "the \"%s\" certificate private key file does not exist\n", *keyPath)
		}
		fmt.Fprintln(os.Stderr, "No certificate available for the QUIC connection, generating self signed cert.. (please use -generate-public-cert my-domain.example.org to generate trusted cert with Let's Encrypt if possible)")

		*generateSelfSignedCert = true
	}
	if *generateSelfSignedCert {
		if certPathExists {
			log.Warn().Msgf("Warning: asked for generating a certificate but the \"%s\" file already exists; new cert will only be generated if both path and key do not exist\n", *certPath)
		}
		if keyPathExists {
			log.Warn().Msgf("Warning: asked for generating a private key but the \"%s\" file already exists; new key will only be generated if both path and key do not exist\n", *keyPath)
		}
		if !(certPathExists && keyPathExists) {
			pubkey, privkey, err := util.GenerateKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not generate private key: %s\n", err)
				return -1
			}
			cert, err := util.GenerateCert(privkey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not generate certificate: %s\n", err)
				return -1
			}

			err = util.DumpCertAndKeyToFiles(cert, pubkey, privkey, *certPath, *keyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not save certificate and key to files: %s\n", err)
				return -1
			}

			certPathExists = true
			keyPathExists = true
		}

	}

	if *verbose {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		util.ConfigureLogger("debug")
	} else {
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))

		logFileName := os.Getenv("SSH3_LOG_FILE")
		if logFileName == "" {
			logFileName = "sshoq.log"
		}
		// the log holds usernames, peer addresses and conversation IDs: it must not be
		// world-readable on a multi-user host
		logFile, err := util.OpenSecretAppendFile(logFileName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open log file %s: %s\n", logFileName, err.Error())
			return -1
		}
		log.Logger = log.Output(logFile)
	}

	tlsConfig := &tls.Config{}
	if len(autogenCertificates) > 0 {
		var zapLevel zapcore.Level
		switch zerolog.GlobalLevel() {
		case zerolog.TraceLevel:
			fallthrough
		case zerolog.DebugLevel:
			zapLevel = zap.DebugLevel
		case zerolog.InfoLevel:
			zapLevel = zap.InfoLevel
		case zerolog.WarnLevel:
			zapLevel = zap.WarnLevel
		case zerolog.ErrorLevel:
			zapLevel = zap.ErrorLevel
		}
		certmagic.Default.Logger = zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
			os.Stderr,
			zapLevel,
		))
		certmagic.Default.Logger = certmagic.Default.Logger.Named("github.com/caddyserver/certmagic")

		var err error
		fmt.Fprintln(os.Stderr, "Generate public certificates...")
		tlsConfig, err = certmagic.TLS(autogenCertificates)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not generate public certificates: %s\n", err)
			return -1
		}
		fmt.Fprintln(os.Stderr, "Successfully generated public certificates")
	}

	if certPathExists && keyPathExists {
		certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not load -cert and -key pair: %s\n", err)
			return -1
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
	}

	log.Debug().Msgf("version %s", ssh3.GetCurrentSoftwareVersion())

	quicConf := &quic.Config{
		Allow0RTT:       false,
		KeepAlivePeriod: 1 * time.Second,
		EnableDatagrams: true,
		// client-initiated bidi (channel) and uni streams allowed, bounded: see
		// ssh3.MaxIncomingStreams
		MaxIncomingStreams:    ssh3.MaxIncomingStreams,
		MaxIncomingUniStreams: ssh3.MaxIncomingUniStreams,
	}

	var err error

	server := http3.Server{
		Handler:         nil,
		Addr:            *bindAddr,
		QuicConfig:      quicConf,
		EnableDatagrams: true,
		TLSConfig:       tlsConfig,
	}

	mux := http.NewServeMux()
	ssh3Server := ssh3.NewServer(30000, 10, &server, func(authenticatedUsername string, conv *ssh3.Conversation) error {
		authenticatedUser, err := unix_util.GetUser(authenticatedUsername)
		if err != nil {
			return err
		}
		// The identity which authenticated this conversation may carry OpenSSH-style
		// restrictions (command=, from=, restrict, no-pty, ...) read from the
		// authorized_keys / authorized_identities line of the user. They express what the
		// owner of that file allows, so they must be enforced on every channel and every
		// request of the session: an option which is read when the identity is parsed and
		// then forgotten is a restriction which does nothing.
		identityOptions := conv.IdentityOptions()
		if identityOptions != nil {
			log.Debug().Msgf("conversation %s of user %s authenticated with a restricted identity",
				conv.ConversationID(), authenticatedUsername)
		}
		conv.SetChannelOpenHandler(func(channel ssh3.Channel) error {
			if channel.ChannelType() == "sftp" && *disableSFTP {
				log.Warn().Msgf("rejecting SFTP channel for user %s: feature disabled", authenticatedUsername)
				return ssh3.ChannelOpenFailure{
					ReasonCode: ssh3.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
					ErrorMsg:   "SFTP is disabled on the server",
				}
			}
			if err := identityOptions.CheckChannelOpen(channel.ChannelType()); err != nil {
				log.Warn().Msgf("rejecting %s channel for user %s: %s", channel.ChannelType(), authenticatedUsername, err)
				return ssh3.ChannelOpenFailure{
					ReasonCode: ssh3.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
					ErrorMsg:   err.Error(),
				}
			}
			return nil
		})
		for {
			channel, err := conv.AcceptChannel(conv.Context())
			if err != nil {
				return err
			}

			switch c := channel.(type) {
			case *ssh3.UDPForwardingChannelImpl:
				handleUDPForwardingChannel(conv.Context(), authenticatedUser, conv, c)
			case *ssh3.TCPForwardingChannelImpl:
				handleTCPForwardingChannel(conv.Context(), authenticatedUser, conv, c)
			case *ssh3.TCPReverseForwardingChannelImpl:
				handleTCPReverseForwardingChannel(conv.Context(), authenticatedUser, conv, c)
			case *ssh3.UDPReverseForwardingChannelImpl:
				handleUDPReverseForwardingChannel(conv.Context(), authenticatedUser, conv, c)
			default:
				if channel.ChannelType() == "sftp" {
					go ssh3sftp.ServeChannel(conv.Context(), authenticatedUser, channel)
					continue
				}
				session := &runningSession{
					channelState: LARVAL,
					pty:          nil,
					runningCmd:   nil,
				}
				runningSessions.Insert(channel, session)
				go func() {
					defer ssh3.RecoverGoroutine("the session channel read loop")
					// handle the main sessionChannel, once it ends, the whole conversation ends
					defer channel.Close()
					defer conv.Close()
					// Nothing else ever takes the session, nor the terminal and the pipes it
					// holds, back: this is where they are released, and where the channel stops
					// being referenced by the map of running sessions.
					defer runningSessions.Delete(channel)
					defer session.Close()
					for {
						genericMessage, err := channel.NextMessage()
						if errors.Is(err, net.ErrClosed) {
							log.Debug().Msgf("the connection was closed by the application: %s", err)
							return
						} else if err != nil && !errors.Is(err, io.EOF) {
							log.Error().Msgf("error when getting message: %s", err)
							return
						}
						if genericMessage == nil {
							return
						}
						switch message := genericMessage.(type) {
						case *ssh3Messages.ChannelRequestMessage:
							switch requestMessage := message.ChannelRequest.(type) {
							case *ssh3Messages.PtyRequest:
								// no-pty / restrict: no terminal for an identity which forbids one
								err = identityOptions.CheckRequest("pty-req")
								if err == nil {
									err = newPtyReq(authenticatedUser, channel, *requestMessage, message.WantReply)
								}
							case *ssh3Messages.EnvRequest:
								err = identityOptions.CheckRequest("env")
								if err == nil {
									err = newEnvReq(authenticatedUser, channel, *requestMessage, message.WantReply)
								}
							case *ssh3Messages.X11Request:
								err = identityOptions.CheckRequest("x11-req")
								if err == nil {
									err = newX11Req(authenticatedUser, channel, *requestMessage, message.WantReply)
								}
							case *ssh3Messages.ShellRequest:
								err = rejectShellRequest(identityOptions)
								if err == nil {
									err = newShellReq(authenticatedUser, channel, message.WantReply)
								}
							case *ssh3Messages.ExecRequest:
								// command=: whatever the client asked to run is replaced by the command the identity
								// restricts the session to
								command := requestMessage.Command
								if identityOptions != nil && identityOptions.ForcedCommand != "" {
									if command != identityOptions.ForcedCommand {
										log.Warn().Msgf("running the forced command of the identity of user %s instead of %q",
											authenticatedUsername, command)
									}
									command = identityOptions.ForcedCommand
								}
								err = newCommandInShellReq(authenticatedUser, channel, message.WantReply, command)
							case *ssh3Messages.SubsystemRequest:
								err = newSubsystemReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.WindowChangeRequest:
								err = newWindowChangeReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.SignalRequest:
								err = newSignalReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.ExitStatusRequest:
								err = newExitStatusReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.ExitSignalRequest:
								err = newExitSignalReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							}
						case *ssh3Messages.DataOrExtendedDataMessage:
							runningSession, ok := runningSessions.Get(channel)
							if ok && runningSession.channelState == LARVAL {
								if message.Data == string("forward-agent") {
									// no-agent-forwarding / restrict: the agent socket of the user is not made
									// available to a session which must not see it
									err = identityOptions.CheckRequest("agent-forwarding")
									if err == nil {
										runningSession.authAgentSocketPath, err = openAgentSocketAndForwardAgent(conv.Context(), conv, authenticatedUser)
									}
								} else {
									// invalid data on larval state
									err = fmt.Errorf("invalid data on ssh channel with LARVAL state")
								}
							} else {
								err = newDataReq(authenticatedUser, channel, *message)
							}
						}
						if err != nil {
							log.Error().Msgf("error while processing message: %+v: %+v\n", genericMessage, err)
							return
						}
					}
				}()
			}

		}
	})
	ssh3Handler := ssh3Server.GetHTTPHandlerFunc(context.Background())
	handler, err := server_auth.HandleAuths(context.Background(), enablePasswordLogin, 30000, ssh3Handler)
	if err != nil {
		log.Error().Msgf("Could not get authentication handlers: %s", err)
		return -1
	}
	mux.HandleFunc(*urlPath, handler)
	server.Handler = mux

	// -R: dial out to the remote sshoq server in the background and keep the
	// reverse forwarding of this server's port alive across reconnects. It is
	// started before ListenAndServe because the tunnel only serves traffic to
	// the local socket once it exists, and connections to the destination are
	// opened lazily, per remote user.
	if reverseTunnelCfg != nil {
		go runReverseTunnel(reverseTunnelCfg, remoteForwardIdentities, *remoteForwardInsecure)
	}

	outputMessage := fmt.Sprintf("Server started, listening on %s%s", *bindAddr, *urlPath)
	fmt.Fprintln(os.Stderr, outputMessage)
	log.Info().Msg(outputMessage)
	err = server.ListenAndServe()

	if err != nil {
		// print to stderr as well as the log file: the "Server started" message
		// has already been displayed, and users should not have to inspect the
		// log file to understand why the server failed to start (e.g. another
		// server is already listening on the same address)
		fmt.Fprintf(os.Stderr, "error while serving HTTP connection: %s\n", err)
		log.Error().Msgf("error while serving HTTP connection: %s", err)
		return -1
	}

	return 0
}

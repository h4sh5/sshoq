package cmd

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
)

// newEnvReq must refuse to operate on a channel that has no session.
func TestNewEnvReq_UnknownChannel(t *testing.T) {
	channel := ssh3.NewMockChannel()
	if err := newEnvReq(nil, channel, ssh3Messages.EnvRequest{Name: "FOO", Value: "bar"}, false); err == nil {
		t.Error("expected an error for a channel with no running session, got nil")
	}
}

// In LARVAL state, env requests must be accepted and stored in the session.
func TestNewEnvReq_LarvalState(t *testing.T) {
	channel := ssh3.NewMockChannel()
	runningSessions.Insert(channel, &runningSession{channelState: LARVAL})
	defer runningSessions.Delete(channel)

	err := newEnvReq(nil, channel, ssh3Messages.EnvRequest{Name: "FOO", Value: "bar"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	session, ok := runningSessions.Get(channel)
	if !ok {
		t.Fatal("session has disappeared")
	}
	if got, ok := session.env["FOO"]; !ok || got != "bar" {
		t.Errorf("expected FOO=bar to be stored, got %v", session.env)
	}
}

// Multiple env requests for the same name: the last one wins.
func TestNewEnvReq_DuplicateNameLastWins(t *testing.T) {
	channel := ssh3.NewMockChannel()
	runningSessions.Insert(channel, &runningSession{channelState: LARVAL})
	defer runningSessions.Delete(channel)

	if err := newEnvReq(nil, channel, ssh3Messages.EnvRequest{Name: "FOO", Value: "first"}, false); err != nil {
		t.Fatal(err)
	}
	if err := newEnvReq(nil, channel, ssh3Messages.EnvRequest{Name: "FOO", Value: "second"}, false); err != nil {
		t.Fatal(err)
	}

	session, _ := runningSessions.Get(channel)
	if got := session.env["FOO"]; got != "second" {
		t.Errorf("expected the last value (second) to win, got %q", got)
	}
}

// A request with an empty name must be rejected.
func TestNewEnvReq_EmptyName(t *testing.T) {
	channel := ssh3.NewMockChannel()
	runningSessions.Insert(channel, &runningSession{channelState: LARVAL})
	defer runningSessions.Delete(channel)

	if err := newEnvReq(nil, channel, ssh3Messages.EnvRequest{Name: "", Value: "bar"}, false); err == nil {
		t.Error("expected an error for an empty variable name, got nil")
	}
}

// Once the session is established (shell/exec started), further env
// requests must be rejected.
func TestNewEnvReq_OpenState(t *testing.T) {
	channel := ssh3.NewMockChannel()
	runningSessions.Insert(channel, &runningSession{channelState: OPEN})
	defer runningSessions.Delete(channel)

	if err := newEnvReq(nil, channel, ssh3Messages.EnvRequest{Name: "FOO", Value: "bar"}, false); err == nil {
		t.Error("expected an error when the session is already established, got nil")
	}
}

// The exit status of a command which ran and finished normally is the number it returned.
func TestWireExitStatus_NormalExit(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 3")
	if err := cmd.Run(); err == nil {
		t.Fatal("expected the command to have failed with status 3")
	}
	if got := wireExitStatus(cmd.ProcessState); got != 3 {
		t.Errorf("expected exit status 3, got %d", got)
	}
}

// A command killed by a signal has no exit code at all: Go answers -1, which becomes
// 18446744073709551615 once cast to the uint64 of the request, and that does not fit a
// varint - it panicked on its way to the client, which was left without a status. It must
// come out the way a shell reports it, 128 plus the signal number.
func TestWireExitStatus_KilledBySignal(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start the command: %s", err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("could not kill the command: %s", err)
	}
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected an *exec.ExitError, got %T (%v)", err, err)
	}
	if got := wireExitStatus(exitErr.ProcessState); got != 128+uint64(syscall.SIGTERM) {
		t.Errorf("expected exit status %d, got %d", 128+uint64(syscall.SIGTERM), got)
	}
}

// A command which is still running has nobody to signal, and a command whose process has
// been waited for must not be signalled again: its pid may already belong to somebody
// else's work by then.
func TestRunningCommandHangup(t *testing.T) {
	// never started
	if err := (&runningCommand{}).hangup(); err != nil {
		t.Errorf("hanging up a command which never started should do nothing, got: %s", err)
	}

	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Run(); err != nil {
		t.Fatalf("the command should have run: %s", err)
	}
	running := &runningCommand{Cmd: *cmd}
	if err := running.hangup(); err != nil {
		t.Errorf("hanging up a command which is over and reaped should do nothing, got: %s", err)
	}
}

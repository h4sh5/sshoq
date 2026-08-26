package cmd

import (
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

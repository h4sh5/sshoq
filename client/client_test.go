package client

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
)

// recordingChannel records every request sent through it.
type recordingChannel struct {
	sentRequests []*ssh3Messages.ChannelRequestMessage
}

func (c *recordingChannel) SendRequest(r *ssh3Messages.ChannelRequestMessage) error {
	c.sentRequests = append(c.sentRequests, r)
	return nil
}

var _ channelRequestSender = &recordingChannel{}

func TestSendEnvRequests_AllSent(t *testing.T) {
	channel := &recordingChannel{}
	err := sendEnvRequests(channel, []string{"foo=bar", "GREETING=hello world", "EMPTY="})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(channel.sentRequests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(channel.sentRequests))
	}
	for i, req := range channel.sentRequests {
		if !req.WantReply {
			t.Errorf("request %d: wantReply should be true", i)
		}
		envReq, ok := req.ChannelRequest.(*ssh3Messages.EnvRequest)
		if !ok {
			t.Fatalf("request %d: expected *EnvRequest, got %T", i, req.ChannelRequest)
		}
		switch i {
		case 0:
			if envReq.Name != "foo" || envReq.Value != "bar" {
				t.Errorf("request %d: expected foo=bar, got %s=%s", i, envReq.Name, envReq.Value)
			}
		case 1:
			if envReq.Name != "GREETING" || envReq.Value != "hello world" {
				t.Errorf("request %d: expected GREETING=hello world, got %s=%s", i, envReq.Name, envReq.Value)
			}
		case 2:
			// values may contain further '=' and may be empty; only the first
			// '=' separates the name from the value
			if envReq.Name != "EMPTY" || envReq.Value != "" {
				t.Errorf("request %d: expected EMPTY=, got %s=%s", i, envReq.Name, envReq.Value)
			}
		}
	}
}

func TestSendEnvRequests_ValueContainsEquals(t *testing.T) {
	channel := &recordingChannel{}
	err := sendEnvRequests(channel, []string{"A=B=C=D"})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(channel.sentRequests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(channel.sentRequests))
	}
	envReq, ok := channel.sentRequests[0].ChannelRequest.(*ssh3Messages.EnvRequest)
	if !ok {
		t.Fatalf("expected *EnvRequest, got %T", channel.sentRequests[0].ChannelRequest)
	}
	if envReq.Name != "A" || envReq.Value != "B=C=D" {
		t.Errorf("expected A=B=C=D, got %s=%s", envReq.Name, envReq.Value)
	}
}

// Malformed entries must be skipped (with a warning) instead of aborting the
// whole session setup.
func TestSendEnvRequests_MalformedSkipped(t *testing.T) {
	channel := &recordingChannel{}
	err := sendEnvRequests(channel, []string{"noequals", "=orphanvalue", "valid=yes"})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(channel.sentRequests) != 1 {
		t.Fatalf("expected only the valid entry to be sent, got %d requests", len(channel.sentRequests))
	}
	envReq, ok := channel.sentRequests[0].ChannelRequest.(*ssh3Messages.EnvRequest)
	if !ok {
		t.Fatalf("expected *EnvRequest, got %T", channel.sentRequests[0].ChannelRequest)
	}
	if envReq.Name != "valid" || envReq.Value != "yes" {
		t.Errorf("expected valid=yes, got %s=%s", envReq.Name, envReq.Value)
	}
}

// With no environment variable, no request must be sent and no error returned.
func TestSendEnvRequests_EmptyList(t *testing.T) {
	channel := &recordingChannel{}
	if err := sendEnvRequests(channel, nil); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(channel.sentRequests) != 0 {
		t.Fatalf("expected no requests, got %d", len(channel.sentRequests))
	}
}

func TestIsExpectedTCPForwardCloseError(t *testing.T) {
	if !isExpectedTCPForwardCloseError(io.EOF) {
		t.Fatal("expected io.EOF to be treated as a normal close")
	}
	if !isExpectedTCPForwardCloseError(net.ErrClosed) {
		t.Fatal("expected net.ErrClosed to be treated as a normal close")
	}
	if !isExpectedTCPForwardCloseError(&quic.StreamError{Remote: true}) {
		t.Fatal("expected remote quic stream cancel to be treated as a normal close")
	}
	if isExpectedTCPForwardCloseError(&quic.StreamError{Remote: false}) {
		t.Fatal("expected local stream errors to remain abnormal")
	}
	if isExpectedTCPForwardCloseError(errors.New("boom")) {
		t.Fatal("expected non-close errors to remain abnormal")
	}
}

func TestSSH3TCPConnReadIgnoresEmptyDataFrames(t *testing.T) {
	channel := ssh3.NewMockChannel(
		&ssh3Messages.DataOrExtendedDataMessage{DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE, Data: ""},
		&ssh3Messages.DataOrExtendedDataMessage{DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE, Data: "hello"},
	)
	conn := newSSH3TCPConn(channel, nil, nil)

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected read to succeed, got %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes, got %d", n)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("expected hello payload, got %q", string(buf[:n]))
	}

	if got, err := conn.Write([]byte("world")); err != nil || got != 5 {
		t.Fatalf("expected 5-byte write to succeed, got n=%d err=%v", got, err)
	}
	if got := string(channel.Writes[0]); got != "world" {
		t.Fatalf("expected write payload world, got %q", got)
	}
}

package ssh3

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	ssh3Messages "github.com/h4sh5/sshoq/message"
	"github.com/h4sh5/sshoq/util"
	"github.com/quic-go/quic-go"
)

type stubReceiveStream struct {
	*bytes.Reader
}

func (s *stubReceiveStream) StreamID() quic.StreamID         { return 1 }
func (s *stubReceiveStream) CancelRead(quic.StreamErrorCode) {}
func (s *stubReceiveStream) SetReadDeadline(time.Time) error { return nil }

type stubWriteCloser struct {
	bytes.Buffer
	closed bool
}

func (s *stubWriteCloser) Close() error {
	s.closed = true
	return nil
}

func marshalMessage(t *testing.T, msg ssh3Messages.Message) []byte {
	t.Helper()
	buf := make([]byte, msg.Length())
	_, err := msg.Write(buf)
	if err != nil {
		t.Fatalf("failed to marshal message: %v", err)
	}
	return buf
}

func TestChannelWaitOpenConfirmation(t *testing.T) {
	recv := &stubReceiveStream{
		Reader: bytes.NewReader(marshalMessage(t, &ssh3Messages.ChannelOpenConfirmationMessage{MaxPacketSize: 30000})),
	}
	send := &stubWriteCloser{}
	channel := NewChannel(1, ConversationID{}, 2, "sftp", 30000, recv, send, nil, nil, true, true, false, 0, nil).(*channelImpl)

	if err := channel.WaitOpen(); err != nil {
		t.Fatalf("WaitOpen returned error: %v", err)
	}
	if !channel.confirmReceived {
		t.Fatal("expected channel to be marked as confirmed")
	}
	if send.Len() == 0 {
		t.Fatal("expected channel header to be sent when waiting for open confirmation")
	}
}

func TestChannelWaitOpenFailure(t *testing.T) {
	recv := &stubReceiveStream{
		Reader: bytes.NewReader(marshalMessage(t, &ssh3Messages.ChannelOpenFailureMessage{
			ReasonCode:       SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
			ErrorMessageUTF8: "SFTP is disabled on the server",
			LanguageTag:      "en",
		})),
	}
	send := &stubWriteCloser{}
	channel := NewChannel(1, ConversationID{}, 2, "sftp", 30000, recv, send, nil, nil, true, true, false, 0, nil).(*channelImpl)

	err := channel.WaitOpen()
	if err == nil {
		t.Fatal("expected WaitOpen to return a channel open failure")
	}
	var openFailure ChannelOpenFailure
	if !errors.As(err, &openFailure) {
		t.Fatalf("expected ChannelOpenFailure, got %T", err)
	}
	if openFailure.ErrorMsg != "SFTP is disabled on the server" {
		t.Fatalf("unexpected error message: %q", openFailure.ErrorMsg)
	}
}

func TestChannelRejectOpen(t *testing.T) {
	send := &stubWriteCloser{}
	channel := NewChannel(1, ConversationID{}, 2, "sftp", 30000, &stubReceiveStream{Reader: bytes.NewReader(nil)}, send, nil, nil, false, false, true, 0, nil)

	if err := channel.RejectOpen(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "SFTP is disabled on the server"); err != nil {
		t.Fatalf("RejectOpen returned error: %v", err)
	}
	if !send.closed {
		t.Fatal("expected channel to be closed after rejection")
	}

	parsed, err := ssh3Messages.ParseMessage(util.NewReader(bytes.NewReader(send.Bytes())))
	if err != nil {
		t.Fatalf("failed to parse rejection message: %v", err)
	}
	failure, ok := parsed.(*ssh3Messages.ChannelOpenFailureMessage)
	if !ok {
		t.Fatalf("expected channel-open failure message, got %T", parsed)
	}
	if failure.ErrorMessageUTF8 != "SFTP is disabled on the server" {
		t.Fatalf("unexpected failure message: %q", failure.ErrorMessageUTF8)
	}
}

// WriteData must report how many bytes of the *caller's* payload made it to the
// channel (net.Conn/Write semantics), not how many bytes were written on the
// underlying QUIC stream: the encoded messages carry extra framing (message type
// and string length varints) which must not leak into the returned count.
// Reporting more bytes than given breaks every io.Copy based caller (a write
// returning more than the slice handed to it is reported as
// "invalid write result"), which is what broke dynamic (SOCKS5) forwarding.
func TestChannelWriteDataReturnsInputLength(t *testing.T) {
	for _, tc := range []struct {
		name          string
		maxPacketSize uint64
		payload       string
	}{
		{"single message", 30000, "hello from the other side"},
		{"split over several messages", 20, string(bytes.Repeat([]byte("x"), 250))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			send := &stubWriteCloser{}
			channel := NewChannel(1, ConversationID{}, 2, "direct-tcp", tc.maxPacketSize,
				&stubReceiveStream{Reader: bytes.NewReader(nil)}, send, nil, nil, false, true, true, 0, nil)

			written, err := channel.WriteData([]byte(tc.payload), ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if err != nil {
				t.Fatalf("WriteData returned error: %v", err)
			}
			if written != len(tc.payload) {
				t.Fatalf("expected WriteData to report %d bytes, reported %d", len(tc.payload), written)
			}

			// the written bytes must still decode back to the expected payload
			reader := util.NewReader(bytes.NewReader(send.Bytes()))
			var decoded strings.Builder
			for decoded.Len() < len(tc.payload) {
				message, err := ssh3Messages.ParseMessage(reader)
				if err != nil {
					t.Fatalf("could not parse written message: %s", err)
				}
				data, ok := message.(*ssh3Messages.DataOrExtendedDataMessage)
				if !ok {
					t.Fatalf("expected a data message, got %T", message)
				}
				decoded.WriteString(data.Data)
			}
			if decoded.String() != tc.payload {
				t.Fatalf("expected payload %q, got %q", tc.payload, decoded.String())
			}
		})
	}
}

var _ io.Reader = (*stubReceiveStream)(nil)

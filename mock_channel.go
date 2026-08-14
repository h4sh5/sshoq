package ssh3

import (
	"context"
	"io"

	ssh3Messages "github.com/h4sh5/sshoq/message"
	"github.com/h4sh5/sshoq/util"
)

// MockChannel is a minimal implementation of Channel intended for testing
// subpackages that need to send and receive messages over a channel.
type MockChannel struct {
	Writes      [][]byte
	SentMsgs    []ssh3Messages.Message
	NextMsgs    []ssh3Messages.Message
	MsgIndex    int
	Closed      bool
	MaxPacketSz uint64
}

// NewMockChannel creates a new MockChannel with the supplied pre-programmed messages.
func NewMockChannel(msgs ...ssh3Messages.Message) *MockChannel {
	return &MockChannel{
		NextMsgs:    msgs,
		MaxPacketSz: 30000,
	}
}

func (m *MockChannel) ChannelID() util.ChannelID                               { return 1 }
func (m *MockChannel) ConversationID() ConversationID                          { return ConversationID{} }
func (m *MockChannel) ConversationStreamID() uint64                            { return 1 }
func (m *MockChannel) ReceiveDatagram(_ context.Context) ([]byte, error)       { return nil, io.EOF }
func (m *MockChannel) SendDatagram(_ []byte) error                             { return nil }
func (m *MockChannel) SendRequest(_ *ssh3Messages.ChannelRequestMessage) error { return nil }
func (m *MockChannel) CancelRead()                                             {}
func (m *MockChannel) Close()                                                  { m.Closed = true }
func (m *MockChannel) MaxPacketSize() uint64                                   { return m.MaxPacketSz }
func (m *MockChannel) WriteData(dataBuf []byte, _ ssh3Messages.SSHDataType) (int, error) {
	m.Writes = append(m.Writes, append([]byte(nil), dataBuf...))
	return len(dataBuf), nil
}
func (m *MockChannel) NextMessage() (ssh3Messages.Message, error) {
	if m.MsgIndex >= len(m.NextMsgs) {
		return nil, io.EOF
	}
	msg := m.NextMsgs[m.MsgIndex]
	m.MsgIndex++
	return msg, nil
}
func (m *MockChannel) ChannelType() string { return "mock" }
func (m *MockChannel) WaitOpen() error {
	msg, err := m.NextMessage()
	if err != nil {
		return err
	}
	switch message := msg.(type) {
	case *ssh3Messages.ChannelOpenConfirmationMessage:
		return nil
	case *ssh3Messages.ChannelOpenFailureMessage:
		return ChannelOpenFailure{ReasonCode: message.ReasonCode, ErrorMsg: message.ErrorMessageUTF8}
	default:
		return MessageOnNonConfirmedChannel{message: msg}
	}
}
func (m *MockChannel) RejectOpen(reasonCode uint64, errorMsg string) error {
	m.SentMsgs = append(m.SentMsgs, &ssh3Messages.ChannelOpenFailureMessage{
		ReasonCode:       reasonCode,
		ErrorMessageUTF8: errorMsg,
		LanguageTag:      "en",
	})
	m.Close()
	return nil
}
func (m *MockChannel) confirmChannel(_ uint64) error                     { return nil }
func (m *MockChannel) setDatagramSender(_ func([]byte) error)            {}
func (m *MockChannel) waitAddDatagram(_ context.Context, _ []byte) error { return nil }
func (m *MockChannel) addDatagram(_ []byte) bool                         { return true }
func (m *MockChannel) maybeSendHeader() error                            { return nil }
func (m *MockChannel) setDgramQueue(_ *util.DatagramsQueue)              {}

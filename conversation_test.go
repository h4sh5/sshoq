package ssh3

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestChannelOpenHandlerIsVisibleToIncomingChannels checks the synchronisation between the
// conversation handler goroutine - which installs the channel open handler - and the goroutine
// hijacking an incoming channel stream, which consults it. A channel opened as soon as the
// CONNECT response is back used to be accepted - or rejected - while the handler was not set
// yet, so the server feature guarded by that handler (e.g. -disable-sftp) was silently skipped.
func TestChannelOpenHandlerIsVisibleToIncomingChannels(t *testing.T) {
	conv := &Conversation{}

	setDone := make(chan struct{})
	go func() {
		// the conversation handler does something before installing its handler, as done by
		// sshoq-server which looks up the user first
		time.Sleep(20 * time.Millisecond)
		conv.SetChannelOpenHandler(func(Channel) error { return nil })
		close(setDone)
	}()

	// the incoming channel must wait for the handler instead of deciding on a nil one
	awaited := make(chan struct{})
	go func() {
		conv.awaitChannelOpenHandler()
		close(awaited)
	}()

	select {
	case <-awaited:
		t.Fatal("awaitChannelOpenHandler returned before the open handler was set")
	case <-time.After(10 * time.Millisecond):
	}

	select {
	case <-awaited:
	case <-time.After(5 * time.Second):
		t.Fatal("awaitChannelOpenHandler did not return once the open handler was set")
	}
	<-setDone

	if handler := conv.channelOpenHandlerFunc(); handler == nil {
		t.Fatal("channel open handler is not visible after it was set")
	}
}

// TestChannelOpenHandlerGateReleasedOnClose checks that a channel which is waiting for the
// conversation setup is not left hanging when the conversation goes away or when its handler
// returns without ever installing an open handler.
func TestChannelOpenHandlerGateReleasedOnClose(t *testing.T) {
	t.Run("conversation closed", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		conv := &Conversation{context: ctx}
		released := awaitGate(t, conv)
		cancel(nil)
		awaitClosed(t, released)
	})

	t.Run("conversation handler returned", func(t *testing.T) {
		conv := &Conversation{}
		released := awaitGate(t, conv)
		// server.go defers releaseChannelHandlerGate when the conversation handler returns
		conv.releaseChannelHandlerGate()
		conv.releaseChannelHandlerGate() // idempotent: a second release must not panic
		awaitClosed(t, released)
	})
}

// TestChannelOpenHandlerConcurrentAccess runs the handler setter and reader concurrently, which
// is what -race needs to prove there is no longer a data race on Conversation.channelOpenHandler.
func TestChannelOpenHandlerConcurrentAccess(t *testing.T) {
	conv := &Conversation{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			conv.SetChannelOpenHandler(func(Channel) error { return nil })
		}()
		go func() {
			defer wg.Done()
			conv.awaitChannelOpenHandler()
			_ = conv.channelOpenHandlerFunc()
		}()
	}
	wg.Wait()
}

// awaitGate starts a goroutine waiting for the conversation's channel open handler and returns
// the channel which is closed once that wait ended.
func awaitGate(t *testing.T, conv *Conversation) chan struct{} {
	t.Helper()
	released := make(chan struct{})
	go func() {
		conv.awaitChannelOpenHandler()
		close(released)
	}()
	select {
	case <-released:
		t.Fatal("awaitChannelOpenHandler returned although no open handler was set yet")
	case <-time.After(50 * time.Millisecond):
	}
	return released
}

func awaitClosed(t *testing.T, released chan struct{}) {
	t.Helper()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("awaitChannelOpenHandler is still blocked")
	}
}

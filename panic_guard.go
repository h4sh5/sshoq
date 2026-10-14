package ssh3

import (
	"runtime/debug"

	"github.com/rs/zerolog/log"
)

// RecoverGoroutine contains a panic raised while handling one channel or one
// conversation, so that it costs that channel and not the process.
//
// It exists because a goroutine which parses what arrives on the network used to be
// able to stop the whole server: quic-go recovers a panic raised inside ServeHTTP, but
// not one raised in a goroutine which ServeHTTP started, and reading a message from a
// channel happens in such goroutines (the session read loop, the forwarding pumps, the
// SFTP handler). A single malformed message was then enough to kill every session of
// every other user, the shell commands running on their behalf and the listeners the
// server put in place for them - and, seen from the other side, a rogue or later
// compromised server could crash any client which connected to it.
//
// The parsers are the real fix: message.ParseMessage answers with an error for a
// message type it does not know and the readers refuse a length they would not be able
// to honour. This function is what is left for the panic nobody thought of - it bounds
// the damage, it does not hide the bug: the panic and its stack are logged, and the
// goroutine which carried it ends here instead of resuming.
//
// Call it as the first statement of a goroutine which handles one peer:
//
//	go func() {
//		defer ssh3.RecoverGoroutine("session channel read loop")
//		...
//	}()
//
// Being the first deferred call, it runs last, once the defers closing the channel and
// the conversation have been executed.
func RecoverGoroutine(what string) {
	if raised := recover(); raised != nil {
		log.Error().Msgf("recovered from a panic in %s: %v\n%s", what, raised, debug.Stack())
	}
}

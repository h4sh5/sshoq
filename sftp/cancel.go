package sftp

import (
	"errors"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// ErrCancelled is returned by a transfer that was interrupted by the user:
// Ctrl+C in interactive sftp mode, or SIGINT/SIGTERM in scp mode.
var ErrCancelled = errors.New("transfer cancelled")

// transferCancel is a cancellation flag shared by a transfer and the input
// watcher (interactive mode) or signal handler (scp mode) that interrupts it.
// Transfer loops check cancelled() between chunks and stop as soon as it is
// set, so a Ctrl+C takes effect at the next chunk boundary at the latest.
type transferCancel struct {
	flag atomic.Bool
}

// cancel marks the transfer as cancelled. It is safe to call more than once
// and from any goroutine.
func (c *transferCancel) cancel() {
	if c != nil {
		c.flag.Store(true)
	}
}

// cancelled reports whether the transfer has been cancelled. A nil receiver
// reports false, so transfers without a cancel watcher (e.g. in tests) behave
// exactly as before.
func (c *transferCancel) cancelled() bool {
	return c != nil && c.flag.Load()
}

// watchSignals cancels a transfer when SIGINT or SIGTERM arrives. Scp mode
// runs with a normal terminal, so Ctrl+C is delivered as SIGINT rather than
// as a raw byte (unlike interactive mode, where the terminal is raw and the
// input watcher handles Ctrl+C). It returns a stop function that unregisters
// the handler and lets a later Ctrl+C take its default action again.
func watchSignals(cancel *transferCancel) func() {
	sigs := make(chan os.Signal, 1)
	stop := make(chan struct{})
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigs:
			cancel.cancel()
		case <-stop:
		}
	}()
	return func() {
		signal.Stop(sigs)
		close(stop)
	}
}

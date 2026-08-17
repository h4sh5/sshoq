package sftp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	ssh3 "github.com/h4sh5/sshoq"
	ssh3Messages "github.com/h4sh5/sshoq/message"
)

// cancellingChannel wraps a MockChannel and sets cancel the moment a request
// is written, so a transfer can be interrupted deterministically between
// chunks (a mock channel answers every request instantly, which would finish
// the transfer before an async cancel could land).
type cancellingChannel struct {
	*ssh3.MockChannel
	cancel   *transferCancel
	cancelAt int // cancel when this request (1-based) is written
	writes   int
}

func (c *cancellingChannel) WriteData(dataBuf []byte, dataType ssh3Messages.SSHDataType) (int, error) {
	c.writes++
	if c.writes == c.cancelAt {
		c.cancel.cancel()
	}
	return c.MockChannel.WriteData(dataBuf, dataType)
}

// waitFor polls until cond returns true or the deadline expires, failing the
// test otherwise.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- transfer-level cancellation ---

// TestUploadFileCancelled verifies that an upload interrupted by Ctrl+C stops
// at the next chunk boundary and returns ErrCancelled without finishing.
func TestUploadFileCancelled(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "local.bin")
	os.WriteFile(localPath, bytes.Repeat([]byte("x"), ChunkSize*2), 0644)

	cancel := &transferCancel{}
	ch := &cancellingChannel{
		MockChannel: newMockChannel(makeJSONDataMsg(&Response{ID: 1, OK: true})),
		cancel:      cancel,
		cancelAt:    1, // interrupt as soon as the first chunk is sent
	}

	err := uploadFile(ch, localPath, "remote.bin", true, cancel)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled, got %v", err)
	}
	if len(ch.Writes) != 1 {
		t.Fatalf("expected the transfer to stop after 1 chunk, got %d", len(ch.Writes))
	}
}

// TestUploadFileCancelledBeforeStart verifies that a transfer cancelled before
// it begins sends no requests at all.
func TestUploadFileCancelledBeforeStart(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "local.bin")
	os.WriteFile(localPath, []byte("data"), 0644)

	cancel := &transferCancel{}
	cancel.cancel()
	ch := newMockChannel()

	err := uploadFile(ch, localPath, "remote.bin", true, cancel)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled, got %v", err)
	}
	if len(ch.Writes) != 0 {
		t.Fatalf("expected no requests when cancelled, got %d", len(ch.Writes))
	}
}

// TestDownloadFileCancelled verifies that a download interrupted by Ctrl+C
// returns ErrCancelled and removes the partially downloaded local file so it
// is not mistaken for a complete download.
func TestDownloadFileCancelled(t *testing.T) {
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "out.bin")
	chunk := bytes.Repeat([]byte("y"), ChunkSize)

	cancel := &transferCancel{}
	ch := &cancellingChannel{
		MockChannel: newMockChannel(
			makeJSONDataMsg(&Response{ID: 1, OK: true, Info: &FileInfo{Name: "remote.bin", Size: int64(ChunkSize * 4)}}),
			makeJSONDataMsg(&Response{ID: 2, OK: true, Data: chunk}),
		),
		cancel:   cancel,
		cancelAt: 2, // interrupt as soon as the first get request is sent
	}

	err := downloadFile(ch, "remote.bin", localPath, true, cancel)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled, got %v", err)
	}
	if _, statErr := os.Stat(localPath); !os.IsNotExist(statErr) {
		t.Fatalf("partial download should be removed, stat error: %v", statErr)
	}
}

// TestDownloadRecursiveCancelled verifies that a cancelled recursive download
// stops before issuing any request.
func TestDownloadRecursiveCancelled(t *testing.T) {
	cancel := &transferCancel{}
	cancel.cancel()
	ch := newMockChannel()

	err := downloadRecursive(ch, "remote-dir", filepath.Join(t.TempDir(), "out"), true, cancel)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled, got %v", err)
	}
	if len(ch.Writes) != 0 {
		t.Fatalf("expected no requests when cancelled, got %d", len(ch.Writes))
	}
}

// TestUploadRecursiveCancelled verifies that a cancelled recursive upload
// stops before issuing any request.
func TestUploadRecursiveCancelled(t *testing.T) {
	tmp := t.TempDir()
	localDir := filepath.Join(tmp, "src")
	os.MkdirAll(localDir, 0o755)
	os.WriteFile(filepath.Join(localDir, "a.txt"), []byte("a"), 0644)

	cancel := &transferCancel{}
	cancel.cancel()
	ch := newMockChannel()

	err := uploadRecursive(ch, localDir, "remote-dir", true, cancel)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled, got %v", err)
	}
	if len(ch.Writes) != 0 {
		t.Fatalf("expected no requests when cancelled, got %d", len(ch.Writes))
	}
}

// --- scp-mode signal handling ---

// TestWatchSignals verifies that SIGTERM delivered to the process cancels the
// transfer through the signal watcher used by scp mode.
func TestWatchSignals(t *testing.T) {
	var cancel transferCancel
	stop := watchSignals(&cancel)
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "SIGTERM to cancel the transfer", cancel.cancelled)
}

// --- interactive-mode stdin watcher ---

// newTestPty replaces os.Stdin/os.Stdout with a fresh pty and returns the
// master end, like the other readline pty tests.
func newTestPty(t *testing.T) *os.File {
	t.Helper()
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("pty not available: %v", err)
	}
	pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 80})
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = tty, tty
	t.Cleanup(func() {
		os.Stdin, os.Stdout = oldIn, oldOut
		ptmx.Close()
		tty.Close()
	})
	return ptmx
}

// startWatcher starts the stdin watcher of r and returns a stop function that
// stops it and waits for it to exit.
func startWatcher(r *interactiveReader, cancel *transferCancel) func() {
	ctx, stop := context.WithCancel(context.Background())
	r.watchWg.Add(1)
	go r.watchCancel(ctx, cancel)
	return func() {
		stop()
		r.watchWg.Wait()
	}
}

// TestInteractiveReaderWatchCancelCancelsOnCtrlC verifies that pressing
// Ctrl+C while a transfer runs sets the cancel flag: in raw mode the terminal
// delivers Ctrl+C as byte 0x03, not as SIGINT.
func TestInteractiveReaderWatchCancelCancelsOnCtrlC(t *testing.T) {
	ptmx := newTestPty(t)
	r, err := newInteractiveReader()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()

	var cancel transferCancel
	stop := startWatcher(r, &cancel)

	if _, err := ptmx.Write([]byte{0x03}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "Ctrl+C to cancel the transfer", cancel.cancelled)
	stop()
}

// TestInteractiveReaderWatchCancelBuffersTypedInput verifies that bytes typed
// while a transfer runs are buffered and reappear at the next prompt instead
// of being lost to the watcher's read.
func TestInteractiveReaderWatchCancelBuffersTypedInput(t *testing.T) {
	ptmx := newTestPty(t)
	r, err := newInteractiveReader()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()

	var cancel transferCancel
	stop := startWatcher(r, &cancel)

	if _, err := ptmx.WriteString("ls\r"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "typed input to be buffered", func() bool {
		r.editor.pendingMu.Lock()
		defer r.editor.pendingMu.Unlock()
		return len(r.editor.pending) == 3
	})
	stop()

	line, err := r.readLine("sftp> ")
	if err != nil {
		t.Fatal(err)
	}
	if line != "ls" {
		t.Fatalf("expected the buffered line %q at the next prompt, got %q", "ls", line)
	}
}

// TestInteractiveReaderWatchCancelStopsOnContext verifies that the watcher
// exits when the transfer finishes even when no input arrives, so it never
// steals bytes typed after the transfer.
func TestInteractiveReaderWatchCancelStopsOnContext(t *testing.T) {
	ptmx := newTestPty(t)
	r, err := newInteractiveReader()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()

	var cancel transferCancel
	stop := startWatcher(r, &cancel)
	stop() // no input at all: must still exit promptly

	// Bytes typed after the transfer must reach the next prompt untouched.
	if _, err := ptmx.WriteString("pwd\r"); err != nil {
		t.Fatal(err)
	}
	line, err := r.readLine("sftp> ")
	if err != nil {
		t.Fatal(err)
	}
	if line != "pwd" {
		t.Fatalf("expected the line %q at the next prompt, got %q", "pwd", line)
	}
}

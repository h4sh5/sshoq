package sftp

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// TestInteractiveReaderPty exercises the interactive reader end to end through
// a real pty: raw-mode terminal handling, width discovery and width-aware
// redrawing. It asserts on the byte stream the editor writes, which is
// deterministic for a fixed terminal size.
func TestInteractiveReaderPty(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("pty not available: %v", err)
	}
	defer ptmx.Close()
	defer tty.Close()
	// A narrow terminal (20 columns) so the typed line wraps.
	if err := pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 20}); err != nil {
		t.Fatal(err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = tty, tty
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	r, err := newInteractiveReader()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()

	go func() {
		time.Sleep(50 * time.Millisecond)
		ptmx.WriteString("abcdefghijklmnopqrstuvwxyz")
		time.Sleep(50 * time.Millisecond)
		ptmx.WriteString("\r")
	}()

	line, err := r.readLine("sftp> ")
	if err != nil {
		t.Fatal(err)
	}
	if line != "abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("readLine: got %q", line)
	}

	ptmx.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 8192)
	n, _ := ptmx.Read(buf)
	out := string(buf[:n])

	// The initial prompt must leave the cursor one column after "sftp> ".
	if !strings.Contains(out, "sftp> \r\x1b[6C") {
		t.Errorf("initial prompt: expected cursor at column 6, got %q", out)
	}
	// Once the line wraps (6 + 14 chars = 20 columns), redraws must first
	// move the cursor up to the prompt line instead of only returning to the
	// start of the wrapped row.
	if !strings.Contains(out, "\x1b[1A\r\x1b[J") {
		t.Errorf("wrapped redraw: expected move-up before clearing, got %q", out)
	}
}

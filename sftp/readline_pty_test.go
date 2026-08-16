package sftp

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// TestInteractiveReaderOutputProcessing verifies that after entering raw mode,
// newline translation is still active on output: a bare "\n" written outside
// the editor (command output such as ls listings, printed with fmt.Println)
// must reach the terminal as CRLF, otherwise each line would start at the
// column where the previous one ended.
func TestInteractiveReaderOutputProcessing(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("pty not available: %v", err)
	}
	defer ptmx.Close()
	defer tty.Close()
	pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 80})

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = tty, tty
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	r, err := newInteractiveReader()
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()

	// The terminal must be raw on input (no echo, no line buffering) but keep
	// output post-processing so bare "\n" is translated to CRLF.
	termios, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if termios.Lflag&unix.ECHO != 0 || termios.Lflag&unix.ICANON != 0 {
		t.Errorf("input not raw: ECHO=%v ICANON=%v",
			termios.Lflag&unix.ECHO != 0, termios.Lflag&unix.ICANON != 0)
	}
	if termios.Oflag&unix.OPOST == 0 || termios.Oflag&unix.ONLCR == 0 {
		t.Errorf("output processing disabled: OPOST=%v ONLCR=%v",
			termios.Oflag&unix.OPOST != 0, termios.Oflag&unix.ONLCR != 0)
	}

	// A single persistent reader feeds a channel so no output is lost to a
	// leaked blocking read.
	ch := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				ch <- b
			}
			if err != nil {
				return
			}
		}
	}()

	readAll := func(d time.Duration) string {
		var b strings.Builder
		for {
			select {
			case c := <-ch:
				b.Write(c)
			case <-time.After(d):
				return b.String()
			}
		}
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		ptmx.WriteString("ls\r")
	}()
	if _, err := r.readLine("sftp> "); err != nil {
		t.Fatal(err)
	}

	// Drain the editor output, then write command output with bare "\n" and
	// verify it reaches the terminal as CRLF.
	readAll(100 * time.Millisecond)
	tty.WriteString("first line\nsecond line\n")
	if out := readAll(300 * time.Millisecond); !strings.Contains(out, "first line\r\nsecond line\r\n") {
		t.Errorf("bare \\n was not translated to CRLF: %q", out)
	}
}

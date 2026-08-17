package sftp

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// redrawInterval is the minimum time between two in-place redraws of a
// progress line. Transfers run in chunks far smaller than what can be
// transferred in this interval, so redraws are rate-limited instead of
// performed once per chunk.
const redrawInterval = 100 * time.Millisecond

// progress renders a single-file transfer progress line showing the
// percentage of the total size already transferred and the transfer speed,
// e.g. "file.txt:  42% 4.2 MB / 10.0 MB 2.3 MB/s". When out is a terminal the
// line is redrawn in place with carriage returns; otherwise intermediate
// redraws are skipped and only the final line is printed.
type progress struct {
	name    string
	total   int64 // 0 when the total size is unknown
	written int64

	start    time.Time
	lastDraw time.Time
	lastLen  int
	drawn    bool
	out      io.Writer
	inplace  bool
	cancel   *transferCancel
}

// newProgress creates a progress reporter for the transfer of name whose
// total size is total bytes (0 when unknown). Output is written to out and,
// when out is a terminal, updated in place with carriage returns. cancel is
// the cancellation flag of the enclosing transfer (nil when the transfer is
// not cancellable).
func newProgress(name string, total int64, out io.Writer, cancel *transferCancel) *progress {
	inplace := false
	if f, ok := out.(*os.File); ok {
		inplace = term.IsTerminal(int(f.Fd()))
	}
	return &progress{
		name:    name,
		total:   total,
		start:   time.Now(),
		out:     out,
		inplace: inplace,
		cancel:  cancel,
	}
}

// cancelled reports whether the transfer has been cancelled by the user
// (Ctrl+C in interactive mode, SIGINT in scp mode). Transfer loops check it
// between chunks and stop as soon as it is set.
func (p *progress) cancelled() bool {
	return p.cancel.cancelled()
}

// add records that n more bytes have been transferred. For terminal output
// the progress line is redrawn at most once every redrawInterval; for
// non-terminal output nothing is drawn until finish.
func (p *progress) add(n int64) {
	p.written += n
	if !p.inplace {
		return
	}
	now := time.Now()
	if p.lastDraw.IsZero() || now.Sub(p.lastDraw) >= redrawInterval {
		p.draw(now)
		p.lastDraw = now
	}
}

// finish prints the final progress line, always terminated by a newline so
// the cursor returns to the start of a fresh line.
func (p *progress) finish() {
	p.draw(time.Now())
	if p.inplace {
		fmt.Fprint(p.out, "\n")
	}
}

// abort clears a partially drawn in-place progress line so a following error
// message starts on a clean line. It does nothing when nothing was drawn.
func (p *progress) abort() {
	if p.inplace && p.drawn {
		fmt.Fprintf(p.out, "\r%s\r", strings.Repeat(" ", p.lastLen))
	}
}

func (p *progress) draw(now time.Time) {
	line := p.line(now)
	if !p.inplace {
		fmt.Fprintf(p.out, "%s\n", line)
		return
	}
	fmt.Fprintf(p.out, "\r%s", line)
	if len(line) < p.lastLen {
		// Pad with spaces so a shorter line fully overwrites the previous,
		// longer one.
		fmt.Fprintf(p.out, "%s", strings.Repeat(" ", p.lastLen-len(line)))
	}
	p.lastLen = len(line)
	p.drawn = true
}

func (p *progress) line(now time.Time) string {
	var b strings.Builder
	b.WriteString(p.name)
	b.WriteString(": ")

	if p.total > 0 {
		pct := float64(p.written) * 100 / float64(p.total)
		if pct > 100 {
			pct = 100
		}
		fmt.Fprintf(&b, "%3.0f%% %s / %s ", pct, humanBytes(p.written), humanBytes(p.total))
	} else {
		b.WriteString(humanBytes(p.written))
		b.WriteString(" ")
	}

	elapsed := now.Sub(p.start).Seconds()
	var speed float64
	if elapsed > 0 {
		speed = float64(p.written) / elapsed
	}
	b.WriteString(formatSpeed(speed))
	return b.String()
}

// humanBytes renders a byte count in a human-readable form using 1024-based
// units (B, KB, MB, GB, TB, PB), e.g. 1536 -> "1.5 KB".
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// formatSpeed renders a transfer speed in bytes per second in a
// human-readable form using 1024-based units, e.g. 2.3e6 -> "2.2 MB/s".
func formatSpeed(bytesPerSec float64) string {
	if bytesPerSec < 0 || bytesPerSec != bytesPerSec || bytesPerSec > 1e18 {
		return "- B/s"
	}
	const unit = 1024
	if bytesPerSec < unit {
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
	div, exp := float64(unit), 0
	for m := bytesPerSec / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB/s", bytesPerSec/div, "KMGTPE"[exp])
}

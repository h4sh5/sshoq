package sftp

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{5*1024*1024 + 512*1024, "5.5 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{int64(3) * 1024 * 1024 * 1024 * 1024, "3.0 TB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.n); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestFormatSpeed(t *testing.T) {
	cases := []struct {
		spd  float64
		want string
	}{
		{0, "0 B/s"},
		{512, "512 B/s"},
		{1024, "1.0 KB/s"},
		{1536, "1.5 KB/s"},
		{2.5 * 1024 * 1024, "2.5 MB/s"},
		{1024 * 1024 * 1024, "1.0 GB/s"},
	}
	for _, c := range cases {
		if got := formatSpeed(c.spd); got != c.want {
			t.Errorf("formatSpeed(%v) = %q, want %q", c.spd, got, c.want)
		}
	}

	// Degenerate inputs must not panic or produce nonsense.
	for _, bad := range []float64{-1, nanValue(), 1e19} {
		if got := formatSpeed(bad); !strings.HasSuffix(got, "B/s") {
			t.Errorf("formatSpeed(%v) = %q, want a speed", bad, got)
		}
	}
}

func nanValue() float64 {
	var zero float64
	return zero / zero
}

func TestProgressNonTerminalPrintsFinalLineOnly(t *testing.T) {
	var buf bytes.Buffer
	p := newProgress("file.txt", 1000, &buf, nil)
	p.add(420)
	// Non-terminal output: nothing is drawn until finish.
	if buf.Len() != 0 {
		t.Fatalf("expected no output before finish, got %q", buf.String())
	}
	p.finish()
	got := buf.String()
	for _, want := range []string{"file.txt: ", "42%", "420 B", "1000 B", "B/s", "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("finish output %q does not contain %q", got, want)
		}
	}
}

func TestProgressUnknownTotalOmitsPercentage(t *testing.T) {
	var buf bytes.Buffer
	p := newProgress("unknown.bin", 0, &buf, nil)
	p.add(2048)
	p.finish()
	got := buf.String()
	if strings.Contains(got, "%") {
		t.Errorf("unknown total should not show a percentage, got %q", got)
	}
	if !strings.Contains(got, "2.0 KB") {
		t.Errorf("expected transferred bytes in output, got %q", got)
	}
}

func TestProgressInPlaceRedrawThrottled(t *testing.T) {
	var buf bytes.Buffer
	p := &progress{name: "big.bin", total: 100, out: &buf, inplace: true, start: time.Now()}

	p.add(25)
	got := buf.String()
	if !strings.HasPrefix(got, "\rbig.bin: ") {
		t.Fatalf("expected in-place redraw, got %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("in-place redraw must not contain a newline, got %q", got)
	}

	// A second add within redrawInterval must not redraw.
	before := buf.Len()
	p.add(25)
	if buf.Len() != before {
		t.Fatalf("expected throttled redraw, output grew from %d to %d", before, buf.Len())
	}

	// After the interval a redraw is allowed.
	time.Sleep(redrawInterval + 20*time.Millisecond)
	p.add(25)
	if buf.Len() <= before {
		t.Fatal("expected a redraw after the throttle interval")
	}
	if strings.Count(buf.String(), "\r") != 2 {
		t.Fatalf("expected exactly 2 redraws, got %q", buf.String())
	}

	p.finish()
	got = buf.String()
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("finish must end with a newline, got %q", got)
	}
	if !strings.Contains(got, "75%") {
		t.Fatalf("expected final percentage 75%%, got %q", got)
	}
}

func TestProgressFinishCapsAt100Percent(t *testing.T) {
	var buf bytes.Buffer
	p := &progress{name: "f", total: 10, written: 20, out: &buf, inplace: true, start: time.Now()}
	p.finish()
	if !strings.Contains(buf.String(), "100%") {
		t.Fatalf("expected percentage capped at 100%%, got %q", buf.String())
	}
}

func TestProgressAbortClearsDrawnLine(t *testing.T) {
	var buf bytes.Buffer
	p := &progress{name: "f", total: 100, out: &buf, inplace: true, start: time.Now()}
	p.add(10)
	p.abort()
	got := buf.String()
	if !strings.HasSuffix(got, "\r") {
		t.Fatalf("abort should end with a carriage return, got %q", got)
	}
	if !strings.Contains(got, strings.Repeat(" ", 5)) {
		t.Fatalf("abort should pad the line with spaces to clear it, got %q", got)
	}
}

func TestProgressAbortWithoutDrawDoesNothing(t *testing.T) {
	var buf bytes.Buffer
	p := &progress{name: "f", total: 100, out: &buf, inplace: true, start: time.Now()}
	p.abort()
	if buf.Len() != 0 {
		t.Fatalf("abort before any draw should write nothing, got %q", buf.String())
	}
}

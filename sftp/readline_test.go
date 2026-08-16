package sftp

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

// typeLine feeds the raw key sequence into a line editor and returns the line
// accepted on the first Enter press.
func typeLine(t *testing.T, input string) string {
	t.Helper()
	var out bytes.Buffer
	e := &lineEditor{
		reader:  bufio.NewReader(strings.NewReader(input)),
		out:     &out,
		prompt:  "sftp> ",
		histPos: -1,
	}
	line, err := e.read()
	if err != nil {
		t.Fatalf("read: unexpected error: %v", err)
	}
	return line
}

func TestLineEditorPlainInput(t *testing.T) {
	if got := typeLine(t, "ls -la\r"); got != "ls -la" {
		t.Errorf("plain input: got %q, want %q", got, "ls -la")
	}
	if got := typeLine(t, "\r"); got != "" {
		t.Errorf("empty line: got %q, want empty", got)
	}
}

func TestLineEditorArrowKeys(t *testing.T) {
	// Left/Right arrows move the cursor; typed characters are inserted there.
	// "put file" is 8 chars, 8 lefts bring cursor to position 0.
	got := typeLine(t, "put file\x1b[D\x1b[D\x1b[D\x1b[D\x1b[D\x1b[D\x1b[D\x1b[Dget \r")
	if got != "get put file" {
		t.Errorf("arrow editing: got %q, want %q", got, "get put file")
	}
}

func TestLineEditorHistory(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{
		reader:  bufio.NewReader(strings.NewReader("ls -la\rpwd\r\x1b[A\r\x1b[A\x1b[A\r")),
		out:     &out,
		prompt:  "sftp> ",
		histPos: -1,
	}

	// First command.
	line, err := e.read()
	if err != nil || line != "ls -la" {
		t.Fatalf("first line: got %q, err %v", line, err)
	}
	// Second command.
	line, err = e.read()
	if err != nil || line != "pwd" {
		t.Fatalf("second line: got %q, err %v", line, err)
	}
	// Up arrow -> "pwd".
	line, err = e.read()
	if err != nil || line != "pwd" {
		t.Fatalf("up once: got %q, err %v", line, err)
	}
	// Up, Up -> "ls -la".
	line, err = e.read()
	if err != nil || line != "ls -la" {
		t.Fatalf("up twice: got %q, err %v", line, err)
	}
}

func TestLineEditorHistoryRestoresDraft(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{
		reader:  bufio.NewReader(strings.NewReader("pwd\rpartial\x1b[A\x1b[B\r")),
		out:     &out,
		prompt:  "sftp> ",
		histPos: -1,
	}

	line, err := e.read()
	if err != nil || line != "pwd" {
		t.Fatalf("first line: got %q, err %v", line, err)
	}
	// Type "partial", press Up (loads "pwd"), press Down (restores "partial").
	line, err = e.read()
	if err != nil || line != "partial" {
		t.Fatalf("history draft restore: got %q, err %v", line, err)
	}
}

func TestLineEditorBackspace(t *testing.T) {
	if got := typeLine(t, "ls /tmp\x7f\x7f\x7f\x7f\r"); got != "ls " {
		t.Errorf("backspace: got %q, want %q", got, "ls ")
	}
}

func TestLineEditorDeleteKey(t *testing.T) {
	// Type "ab", move left, insert "X" -> "aXb", move left, then Delete (ESC[3~)
	// removes the 'X'.
	got := typeLine(t, "ab\x1b[DX\x1b[D\x1b[3~\r")
	if got != "ab" {
		t.Errorf("delete key: got %q, want %q", got, "ab")
	}
}

func TestLineEditorHomeEnd(t *testing.T) {
	got := typeLine(t, "cde\x01ab\x05f\r")
	if got != "abcdef" {
		t.Errorf("ctrl+a/ctrl+e: got %q, want %q", got, "abcdef")
	}
	got = typeLine(t, "cde\x1b[Hab\x1b[Ff\r")
	if got != "abcdef" {
		t.Errorf("home/end keys: got %q, want %q", got, "abcdef")
	}
}

func TestLineEditorCtrlU(t *testing.T) {
	// Type "abc def", move left to position 3 (after "abc"), Ctrl+U deletes "abc".
	got := typeLine(t, "abc def\x1b[D\x1b[D\x1b[D\x1b[D\x15xyz\r")
	if got != "xyz def" {
		t.Errorf("ctrl+u: got %q, want %q", got, "xyz def")
	}
}

func TestLineEditorCtrlK(t *testing.T) {
	// Type "abc def", move left to position 3 (after "abc"), Ctrl+K deletes " def".
	got := typeLine(t, "abc def\x1b[D\x1b[D\x1b[D\x1b[D\x0b\r")
	if got != "abc" {
		t.Errorf("ctrl+k: got %q, want %q", got, "abc")
	}
}

func TestLineEditorCtrlW(t *testing.T) {
	got := typeLine(t, "get somefile\x17\r")
	if got != "get " {
		t.Errorf("ctrl+w: got %q, want %q", got, "get ")
	}
}

func TestLineEditorCtrlCAbortsLine(t *testing.T) {
	got := typeLine(t, "garbage\x03ls\r")
	if got != "ls" {
		t.Errorf("ctrl+c: got %q, want %q", got, "ls")
	}
}

func TestLineEditorCtrlDEOF(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{
		reader:  bufio.NewReader(strings.NewReader("\x04")),
		out:     &out,
		prompt:  "sftp> ",
		histPos: -1,
	}
	if _, err := e.read(); err != io.EOF {
		t.Fatalf("ctrl+d on empty line: got err %v, want io.EOF", err)
	}
}

func TestLineEditorCtrlDDeletesChar(t *testing.T) {
	// Type "ab", move left, Ctrl+D deletes the character under the cursor ('b').
	got := typeLine(t, "ab\x1b[D\x04\r")
	if got != "a" {
		t.Errorf("ctrl+d mid-line: got %q, want %q", got, "a")
	}
}

func TestLineEditorUTF8(t *testing.T) {
	got := typeLine(t, "héllo\r")
	if got != "héllo" {
		t.Errorf("utf-8 input: got %q, want %q", got, "héllo")
	}
}

func TestLineEditorRendering(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{
		reader:  bufio.NewReader(strings.NewReader("abc\x1b[D\x1b[DX\r")),
		out:     &out,
		outFd:   -1,
		width:   80,
		prompt:  "sftp> ",
		histPos: -1,
	}
	line, err := e.read()
	if err != nil || line != "aXbc" {
		t.Fatalf("read: got %q, err %v", line, err)
	}
	// After drawing "sftp> aXbc", the cursor must be placed after "sftp> "
	// plus the cursor position (2), i.e. 8 columns from the line start -- one
	// space after the prompt, not at the 's' of "sftp>".
	rendered := out.String()
	if !strings.Contains(rendered, "sftp> aXbc\r\x1b[8C") {
		t.Errorf("render: expected cursor at column 8 after drawing the line, got %q", rendered)
	}
}

func TestDisplayWidth(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"sftp> ", 6},
		{"héllo", 5},
		{"中文", 4}, // wide chars count as two columns each
		{"a中b", 4},
	}
	for _, c := range cases {
		if got := displayWidth(c.in); got != c.want {
			t.Errorf("displayWidth(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestLineEditorWideCharCursor(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{
		reader:  bufio.NewReader(strings.NewReader("a中b\x1b[D\x1b[DX\r")),
		out:     &out,
		outFd:   -1,
		width:   80,
		prompt:  "sftp> ",
		histPos: -1,
	}
	line, err := e.read()
	if err != nil || line != "aX中b" {
		t.Fatalf("read: got %q, err %v", line, err)
	}
	// Line "aX中b" is 5 columns; the cursor sits after "aX" (2 columns), so
	// 6 (prompt) + 2 = column 8.
	if !strings.Contains(out.String(), "sftp> aX中b\r\x1b[8C") {
		t.Errorf("wide char cursor: got %q", out.String())
	}
}

func TestLineEditorInitialCursorPosition(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{out: &out, outFd: -1, width: 80, prompt: "sftp> "}
	e.render()
	// The cursor must sit one column after the prompt ("sftp> " ends with a
	// space), i.e. column 6, not at column 0.
	if got, want := out.String(), "\r\x1b[Jsftp> \r\x1b[6C"; got != want {
		t.Errorf("initial render: got %q, want %q", got, want)
	}
}

func TestLineEditorWrappedLine(t *testing.T) {
	var out bytes.Buffer
	e := &lineEditor{
		reader:  bufio.NewReader(strings.NewReader("abcdefghijklmn\r")),
		out:     &out,
		outFd:   -1,
		width:   10, // prompt (6) + 14 chars = 20 columns -> 2 rows
		prompt:  "sftp> ",
		histPos: -1,
	}
	line, err := e.read()
	if err != nil || line != "abcdefghijklmn" {
		t.Fatalf("read: got %q, err %v", line, err)
	}
	// Once the line wraps, every redraw must first move the cursor up to the
	// prompt line instead of only returning to the start of the wrapped row,
	// which would leave the first row's characters behind.
	if !strings.Contains(out.String(), "\x1b[1A\r\x1b[J") {
		t.Errorf("wrapped redraw: expected move-up before clearing, got %q", out.String())
	}
}

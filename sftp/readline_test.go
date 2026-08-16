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
		prompt:  "sftp> ",
		histPos: -1,
	}
	line, err := e.read()
	if err != nil || line != "aXbc" {
		t.Fatalf("read: got %q, err %v", line, err)
	}
	// The rendered output must end by moving the cursor to the editing position.
	// With prompt "sftp> " (6 chars) and line "aXbc" (4 chars) and cursor at
	// position 2, the final cursor move is 8 columns left. The trailing "\r\n"
	// is written when Enter is pressed.
	rendered := strings.TrimSuffix(out.String(), "\r\n")
	if !strings.HasSuffix(rendered, "\x1b[8D") {
		t.Errorf("render: expected final cursor move, got suffix %q", rendered[len(rendered)-8:])
	}
}

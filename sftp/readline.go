package sftp

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// maxHistory is the maximum number of commands retained for up/down arrow
// history navigation.
const maxHistory = 500

// interactiveReader reads lines of interactive input for the SFTP shell. It
// uses readline-style editing (raw mode) when stdin and stdout are terminals,
// and falls back to plain line scanning otherwise (e.g. piped input). The
// underlying reader, terminal state and command history are kept for the
// lifetime of the session so no input is lost between lines.
type interactiveReader struct {
	terminal bool
	in       *os.File
	out      *os.File
	state    *term.State
	scanner  *bufio.Scanner
	editor   *lineEditor
}

func newInteractiveReader() (*interactiveReader, error) {
	r := &interactiveReader{in: os.Stdin, out: os.Stdout}

	if term.IsTerminal(int(r.in.Fd())) && term.IsTerminal(int(r.out.Fd())) {
		state, err := term.MakeRaw(int(r.in.Fd()))
		if err != nil {
			return nil, err
		}
		r.terminal = true
		r.state = state
		r.editor = &lineEditor{
			out:     r.out,
			reader:  bufio.NewReader(r.in),
			histPos: -1,
		}
	} else {
		r.scanner = bufio.NewScanner(r.in)
	}
	return r, nil
}

// readLine reads one line of input, applying the prompt only in interactive
// mode. It returns io.EOF when input is exhausted (Ctrl+D on an empty line in
// interactive mode, end of stream otherwise).
func (r *interactiveReader) readLine(prompt string) (string, error) {
	if !r.terminal {
		if !r.scanner.Scan() {
			if err := r.scanner.Err(); err != nil {
				return "", err
			}
			return "", io.EOF
		}
		return r.scanner.Text(), nil
	}

	r.editor.prompt = prompt
	return r.editor.read()
}

// close restores the terminal to its previous state.
func (r *interactiveReader) close() {
	if r.state != nil {
		term.Restore(int(r.in.Fd()), r.state)
	}
}

// lineEditor implements a minimal readline-style line editor over a terminal
// in raw mode: the terminal no longer echoes or line-buffers input, so the
// editor keeps the line contents and cursor position itself and redraws the
// prompt on every change.
type lineEditor struct {
	out    io.Writer
	reader *bufio.Reader // persistent across read() calls
	prompt string
	buf    []rune // characters on the current line
	pos    int    // cursor position within buf
	// history navigation state
	history []string
	histPos int    // index into history while navigating, -1 when editing a fresh line
	stash   string // draft line saved when starting to navigate history
}

func (e *lineEditor) read() (string, error) {
	e.render()

	for {
		b, err := e.reader.ReadByte()
		if err != nil {
			return "", err
		}

		switch {
		case b == '\r' || b == '\n': // Enter
			fmt.Fprint(e.out, "\r\n")
			line := string(e.buf)
			e.buf = e.buf[:0]
			e.pos = 0
			e.addHistory(line)
			return line, nil

		case b == '\x7f' || b == '\x08': // Backspace
			e.backspace()

		case b == '\x1b': // Escape sequence (arrows, Home/End, Delete, ...)
			if err := e.handleEscape(); err != nil {
				return "", err
			}

		case b == '\x03': // Ctrl+C: abort the current line
			fmt.Fprint(e.out, "^C\r\n")
			e.buf = e.buf[:0]
			e.pos = 0
			e.histPos = -1
			e.stash = ""
			e.render()

		case b == '\x04': // Ctrl+D: EOF on an empty line, Delete otherwise
			if len(e.buf) == 0 {
				fmt.Fprint(e.out, "\r\n")
				return "", io.EOF
			}
			e.deleteAtCursor()

		case b == '\x01': // Ctrl+A: start of line
			e.pos = 0
			e.moveCursor()

		case b == '\x05': // Ctrl+E: end of line
			e.pos = len(e.buf)
			e.moveCursor()

		case b == '\x15': // Ctrl+U: delete to the start of the line
			e.buf = append(e.buf[:0], e.buf[e.pos:]...)
			e.pos = 0
			e.render()

		case b == '\x0b': // Ctrl+K: delete to the end of the line
			e.buf = e.buf[:e.pos]
			e.render()

		case b == '\x17': // Ctrl+W: delete the word before the cursor
			e.deleteWordBeforeCursor()

		case b == '\x0c': // Ctrl+L: clear the screen
			fmt.Fprint(e.out, "\x1b[2J\x1b[H")
			e.render()

		default:
			if b >= 0x20 {
				if b < 0x80 {
					e.insertRune(rune(b))
				} else {
					r, err := readRune(e.reader, b)
					if err != nil {
						return "", err
					}
					e.insertRune(r)
				}
			}
		}
	}
}

// handleEscape processes the byte following ESC, decoding the terminal escape
// sequences for the arrow and editing keys. Unknown or incomplete sequences
// are drained and ignored.
func (e *lineEditor) handleEscape() error {
	b, err := e.reader.ReadByte()
	if err != nil {
		return err
	}

	switch b {
	case '[': // CSI: ESC [ ...
		b, err = e.reader.ReadByte()
		if err != nil {
			return err
		}
		switch b {
		case 'A': // Up arrow
			e.historyUp()
		case 'B': // Down arrow
			e.historyDown()
		case 'C': // Right arrow
			if e.pos < len(e.buf) {
				e.pos++
				e.moveCursor()
			}
		case 'D': // Left arrow
			if e.pos > 0 {
				e.pos--
				e.moveCursor()
			}
		case 'H': // Home
			e.pos = 0
			e.moveCursor()
		case 'F': // End
			e.pos = len(e.buf)
			e.moveCursor()
		default:
			if b >= '0' && b <= '9' {
				return e.handleExtendedKey(b)
			}
		}

	case 'O': // SS3: ESC O ... (alternate arrow-key encoding)
		b, err = e.reader.ReadByte()
		if err != nil {
			return err
		}
		switch b {
		case 'A':
			e.historyUp()
		case 'B':
			e.historyDown()
		case 'C':
			if e.pos < len(e.buf) {
				e.pos++
				e.moveCursor()
			}
		case 'D':
			if e.pos > 0 {
				e.pos--
				e.moveCursor()
			}
		case 'H':
			e.pos = 0
			e.moveCursor()
		case 'F':
			e.pos = len(e.buf)
			e.moveCursor()
		}
	}

	// A bare ESC or an unknown sequence is ignored.
	return nil
}

// handleExtendedKey consumes the remainder of a digit-led CSI sequence such as
// ESC [3~ (Delete), ESC [1~ / ESC [7~ (Home) or ESC [4~ / ESC [8~ (End).
// Modified sequences like ESC [1;5C (Ctrl+Right) are drained and ignored.
func (e *lineEditor) handleExtendedKey(first byte) error {
	digits := []byte{first}
	for {
		b, err := e.reader.ReadByte()
		if err != nil {
			return err
		}
		if b >= '0' && b <= '9' {
			digits = append(digits, b)
			continue
		}
		if b == '~' {
			switch string(digits) {
			case "1", "7":
				e.pos = 0
				e.moveCursor()
			case "3":
				e.deleteAtCursor()
			case "4", "8":
				e.pos = len(e.buf)
				e.moveCursor()
			}
			return nil
		}
		// Modifier parameters (';') or an unexpected final byte: ignore the
		// rest of the sequence.
		if b == ';' {
			continue
		}
		return nil
	}
}

func (e *lineEditor) historyUp() {
	if len(e.history) == 0 {
		return
	}
	if e.histPos < 0 {
		e.stash = string(e.buf)
		e.histPos = len(e.history) - 1
	} else if e.histPos > 0 {
		e.histPos--
	}
	e.buf = []rune(e.history[e.histPos])
	e.pos = len(e.buf)
	e.render()
}

func (e *lineEditor) historyDown() {
	if e.histPos < 0 {
		return
	}
	if e.histPos < len(e.history)-1 {
		e.histPos++
		e.buf = []rune(e.history[e.histPos])
	} else {
		// Past the newest history entry: restore the draft line.
		e.histPos = -1
		e.buf = []rune(e.stash)
	}
	e.pos = len(e.buf)
	e.render()
}

func (e *lineEditor) addHistory(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if n := len(e.history); n > 0 && e.history[n-1] == line {
		return
	}
	e.history = append(e.history, line)
	if len(e.history) > maxHistory {
		e.history = e.history[len(e.history)-maxHistory:]
	}
	e.histPos = -1
	e.stash = ""
}

// render redraws the prompt and the current line, then restores the cursor to
// its editing position.
func (e *lineEditor) render() {
	fmt.Fprintf(e.out, "\r%s%s\x1b[K", e.prompt, string(e.buf))
	e.moveCursor()
}

// moveCursor moves the cursor from the end of the rendered line back to the
// current editing position.
func (e *lineEditor) moveCursor() {
	if back := len(e.prompt) + len(e.buf) - e.pos; back > 0 {
		fmt.Fprintf(e.out, "\x1b[%dD", back)
	}
}

func (e *lineEditor) insertRune(r rune) {
	e.buf = append(e.buf, 0)
	copy(e.buf[e.pos+1:], e.buf[e.pos:])
	e.buf[e.pos] = r
	e.pos++
	e.render()
}

func (e *lineEditor) backspace() {
	if e.pos == 0 {
		return
	}
	copy(e.buf[e.pos-1:], e.buf[e.pos:])
	e.buf = e.buf[:len(e.buf)-1]
	e.pos--
	e.render()
}

func (e *lineEditor) deleteAtCursor() {
	if e.pos >= len(e.buf) {
		return
	}
	copy(e.buf[e.pos:], e.buf[e.pos+1:])
	e.buf = e.buf[:len(e.buf)-1]
	e.render()
}

func (e *lineEditor) deleteWordBeforeCursor() {
	if e.pos == 0 {
		return
	}
	start := e.pos
	for start > 0 && isWordSep(e.buf[start-1]) {
		start--
	}
	for start > 0 && !isWordSep(e.buf[start-1]) {
		start--
	}
	e.buf = append(e.buf[:start], e.buf[e.pos:]...)
	e.pos = start
	e.render()
}

func isWordSep(r rune) bool {
	return r == ' ' || r == '\t'
}

// readRune reassembles a multibyte UTF-8 rune whose first byte has already
// been consumed from r.
func readRune(r *bufio.Reader, first byte) (rune, error) {
	n := 1
	switch {
	case first&0xE0 == 0xC0:
		n = 2
	case first&0xF0 == 0xE0:
		n = 3
	case first&0xF8 == 0xF0:
		n = 4
	}
	seq := make([]byte, n)
	seq[0] = first
	if _, err := io.ReadFull(r, seq[1:]); err != nil {
		return 0, err
	}
	rn, _ := utf8.DecodeRune(seq)
	return rn, nil
}

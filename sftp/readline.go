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
			outFd:   int(r.out.Fd()),
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
// prompt on every change. Redrawing is width-aware: the terminal width is
// queried on every redraw and wrapped rows are redrawn too, so editing a long
// line (or resizing the window) does not leave stray characters behind.
type lineEditor struct {
	out    io.Writer
	reader *bufio.Reader // persistent across read() calls
	prompt string
	buf    []rune // characters on the current line
	pos    int    // cursor position within buf (rune index)
	// terminal geometry
	outFd  int // fd used to query the terminal width (-1 when unknown)
	width  int // terminal width in columns, refreshed before each redraw
	curRow int // cursor row relative to the start of the prompt line
	curCol int // cursor column relative to the start of the prompt line
	// history navigation state
	history []string
	histPos int    // index into history while navigating, -1 when editing a fresh line
	stash   string // draft line saved when starting to navigate history
}

func (e *lineEditor) read() (string, error) {
	// The physical cursor sits at the start of a fresh line (the previous
	// command's output ended with a newline), so the prompt line starts at
	// relative row 0, column 0.
	e.curRow, e.curCol = 0, 0
	e.render()

	for {
		b, err := e.reader.ReadByte()
		if err != nil {
			return "", err
		}

		switch {
		case b == '\r' || b == '\n': // Enter
			e.positionAtEnd()
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
			e.positionAtEnd()
			fmt.Fprint(e.out, "^C\r\n")
			e.buf = e.buf[:0]
			e.pos = 0
			e.histPos = -1
			e.stash = ""
			e.curRow, e.curCol = 0, 0
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
// its editing position. Rendering is width-aware: when the prompt plus the
// line contents exceed the terminal width the line wraps, so redrawing starts
// by moving the cursor back up to the start of the prompt line and clearing
// everything below it before drawing again.
func (e *lineEditor) render() {
	e.refreshWidth()
	p := displayWidth(e.prompt)
	total := p + displayWidth(string(e.buf))

	// Move from the current cursor position back to the start of the prompt
	// line, clear everything on and below it, then draw the prompt and the
	// line contents.
	if e.curRow > 0 {
		fmt.Fprintf(e.out, "\x1b[%dA", e.curRow)
	}
	fmt.Fprint(e.out, "\r\x1b[J")
	fmt.Fprint(e.out, e.prompt)
	fmt.Fprint(e.out, string(e.buf))

	// The cursor now sits just past the last character of the drawn line;
	// move it to the editing position.
	e.curRow, e.curCol = total/e.width, total%e.width
	e.moveCursorTo(p + displayWidth(string(e.buf[:e.pos])))
}

// moveCursor moves the cursor to the current editing position without
// redrawing the line contents.
func (e *lineEditor) moveCursor() {
	e.refreshWidth()
	e.moveCursorTo(displayWidth(e.prompt) + displayWidth(string(e.buf[:e.pos])))
}

// positionAtEnd moves the cursor to just past the last character of the line,
// so that a following newline starts output on a fresh row below any wrapped
// rows.
func (e *lineEditor) positionAtEnd() {
	e.refreshWidth()
	e.moveCursorTo(displayWidth(e.prompt) + displayWidth(string(e.buf)))
}

// moveCursorTo positions the cursor at the given display column relative to
// the start of the prompt line and updates the tracked cursor position. The
// tracked position is the authoritative location of the physical cursor, so
// column moves across wrapped rows work without knowing the absolute screen
// coordinates.
func (e *lineEditor) moveCursorTo(target int) {
	row, col := target/e.width, target%e.width
	if rows := e.curRow - row; rows > 0 {
		fmt.Fprintf(e.out, "\x1b[%dA", rows)
	} else if rows := row - e.curRow; rows > 0 {
		fmt.Fprintf(e.out, "\x1b[%dB", rows)
	}
	fmt.Fprint(e.out, "\r")
	if col > 0 {
		fmt.Fprintf(e.out, "\x1b[%dC", col)
	}
	e.curRow, e.curCol = row, col
}

// refreshWidth queries the terminal width before a redraw, falling back to 80
// columns when the terminal size cannot be determined (e.g. in tests).
func (e *lineEditor) refreshWidth() {
	if w, _, err := term.GetSize(e.outFd); err == nil && w > 0 {
		e.width = w
	} else if e.width == 0 {
		e.width = 80
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

// displayWidth returns the number of terminal columns s occupies when
// rendered, counting East Asian wide characters and emoji as two columns so
// cursor positioning and wrapping stay correct on terminals that render them
// wide.
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

// runeWidth returns the display width of a single rune in terminal columns.
// Control characters (which never appear in the line buffer) have width 0.
func runeWidth(r rune) int {
	switch {
	case r < 0x20 || r == 0x7f:
		return 0
	case r < 0x7f:
		return 1
	// East Asian Wide / Fullwidth ranges (approximate, matching the common
	// wcwidth tables).
	case r >= 0x1100 && r <= 0x115f, // Hangul Jamo
		r >= 0x2e80 && r <= 0x303e,   // CJK Radicals .. CJK Symbols and Punctuation
		r >= 0x3041 && r <= 0x33ff,   // Hiragana .. CJK Compatibility
		r >= 0x3400 && r <= 0x4dbf,   // CJK Unified Ideographs Extension A
		r >= 0x4e00 && r <= 0x9fff,   // CJK Unified Ideographs
		r >= 0xa000 && r <= 0xa4cf,   // Yi Syllables .. Yi Radicals
		r >= 0xac00 && r <= 0xd7a3,   // Hangul Syllables
		r >= 0xf900 && r <= 0xfaff,   // CJK Compatibility Ideographs
		r >= 0xfe30 && r <= 0xfe4f,   // CJK Compatibility Forms
		r >= 0xff00 && r <= 0xff60,   // Fullwidth Forms
		r >= 0xffe0 && r <= 0xffe6,   // Fullwidth Signs
		r >= 0x1f300 && r <= 0x1f64f, // Miscellaneous Symbols and Pictographs
		r >= 0x1f900 && r <= 0x1f9ff: // Supplemental Symbols and Pictographs
		return 2
	}
	return 1
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

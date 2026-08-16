package sftp

import (
	"errors"
	"strings"
)

// errUnterminated is returned by makeargv in strict mode when a quote is left
// open at the end of the line, mirroring OpenSSH's "Unterminated quoted
// argument" error.
var errUnterminated = errors.New("unterminated quoted argument")

// makeargv splits a command line into arguments using the same quoting,
// comment and escaping rules as the OpenSSH sftp client (sftp.c makeargv):
//
//   - Whitespace separates arguments except inside single or double quotes.
//   - Single quotes ('…') protect every character literally: the only
//     character that cannot appear inside single quotes is a single quote.
//   - Double quotes ("…") protect most characters; inside double quotes a
//     backslash escapes the next character (but only when followed by a
//     double-quote, a glob metacharacter, or another backslash).
//   - Outside quotes, a backslash escapes the next character, except when
//     followed by ?, [, *, or \ — those sequences are preserved verbatim so
//     that glob(3) can undo the escaping. All other backslash sequences are
//     replaced by the following character.
//   - A '#' outside quotes starts a comment that runs to the end of the line.
//
// When sloppy is true, an unterminated quote at the end of the line is
// tolerated (used for tab completion); otherwise it is an error.
//
// It returns the list of arguments, the byte span of each argument in the
// input line (start and end offsets), the quote character that opened the
// last argument ('\0' when unquoted), and whether the quoting of the last
// argument was properly terminated.
func makeargv(line string, sloppy bool) (args []string, spans [][2]int, lastquote byte, terminated bool, err error) {
	const (
		stStart = iota
		stSQuote
		stDQuote
		stUnquoted
	)

	terminated = true
	state := stStart
	var cur []byte
	argStart := -1

	// finishArg records the current argument when the state is stUnquoted.
	finishArg := func(end int) {
		if state == stUnquoted {
			args = append(args, string(cur))
			spans = append(spans, [2]int{argStart, end})
			state = stStart
			cur = cur[:0]
			argStart = -1
		}
	}

	i := 0
	for i < len(line) {
		c := line[i]

		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			if state == stUnquoted {
				finishArg(i)
			} else if state != stStart {
				// Whitespace inside quotes is preserved.
				cur = append(cur, c)
			}

		case c == '\'' || c == '"':
			q := stDQuote
			if c == '\'' {
				q = stSQuote
			}
			switch state {
			case stStart:
				argStart = i
				state = q
				lastquote = c
			case stUnquoted:
				state = q
				lastquote = c
			default:
				if state == q {
					// Closing quote for the open quote type.
					state = stUnquoted
				} else {
					// Mismatched quote inside a quoted string is literal.
					cur = append(cur, c)
				}
			}

		case c == '\\':
			next := byte(0)
			if i+1 < len(line) {
				next = line[i+1]
			}

			if state == stSQuote || state == stDQuote {
				quot := byte('\'')
				if state == stDQuote {
					quot = '"'
				}
				switch {
				case next == quot:
					// Escaped quote inside the same quote type.
					i++
					cur = append(cur, line[i])
				case next == '?' || next == '[' || next == '*':
					// Triple-escaped glob: \\ + \ + char, matching OpenSSH's
					// double-escaped glob sequence; glob(3)/path.Match undo one
					// level of escaping, yielding \ + literal char.
					cur = append(cur, '\\', '\\', '\\', next)
					i++
				default:
					// \x inside quotes survives as \x (the only characters
					// treated specially are the quote and glob metacharacters).
					cur = append(cur, '\\')
					if next != 0 {
						cur = append(cur, next)
						i++
					}
				}
			} else {
				if state == stStart {
					argStart = i
					state = stUnquoted
					lastquote = 0
				}
				switch {
				case next == '?' || next == '[' || next == '*' || next == '\\':
					// Preserve the backslash so glob matching can undo it.
					cur = append(cur, c, next)
					i++
				case next == 0:
					// Trailing backslash at end of line.
					if sloppy {
						finishArg(i)
						return args, spans, lastquote, false, nil
					}
					return nil, nil, 0, false, errUnterminated
				default:
					// Unescape: remove the backslash, keep the next char.
					cur = append(cur, next)
					i++
				}
			}

		case c == '#':
			if state == stSQuote || state == stDQuote {
				cur = append(cur, c)
			} else {
				// '#' outside quotes starts a comment.
				finishArg(i)
				return args, spans, lastquote, terminated, nil
			}

		default:
			if state == stStart {
				argStart = i
				state = stUnquoted
				lastquote = 0
			}
			if (state == stSQuote || state == stDQuote) && (c == '?' || c == '[' || c == '*') {
				// Escape quoted glob metacharacters so they are matched
				// literally by glob(3) / path.Match.
				cur = append(cur, '\\', c)
			} else {
				cur = append(cur, c)
			}
		}

		i++
	}

	// End of input reached.
	if state == stSQuote || state == stDQuote {
		if sloppy {
			terminated = false
			state = stUnquoted
			finishArg(i)
			return args, spans, lastquote, terminated, nil
		}
		return nil, nil, 0, false, errUnterminated
	}
	finishArg(i)
	return args, spans, lastquote, terminated, nil
}

// undoGlobEscape removes the escaping of glob metacharacters that makeargv
// preserves for glob(3) matching. For commands that do not glob (cd, mkdir,
// rmdir, get-target, put-target, lcd, lls), the backslash before ?, [, *, or
// \ is removed so that the literal path is used. Other backslash sequences
// (\x) are preserved unchanged.
func undoGlobEscape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '?', '[', '*', '\\':
				b.WriteByte(s[i+1])
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unescape removes all backslash escaping from s, turning \X into X for any
// X. This is the inverse of the quoting and escaping applied by makeargv, so
// it yields the literal path the user intended.
func unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			if i+1 < len(s) {
				i++
				c = s[i]
			} else {
				continue // trailing backslash: nothing to escape
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// escapePath escapes s for typed insertion on the command line. Characters
// that are special to the shell quoting are prefixed with a backslash, except
// when they are already protected by the given quote character (quote != 0).
// The backslash itself is always escaped for round-trip correctness.
func escapePath(s string, quote byte) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'', '"', '\\', '\t', '[', '?', ' ', '#', '*':
			if quote == 0 || c == quote || c == '\\' {
				b.WriteByte('\\')
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

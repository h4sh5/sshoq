package sftp

import (
	"path"
	"strings"
	"testing"
)

// The sftp command line, round-tripped.
//
// `makeargv` is the tokeniser every sftp command goes through -- it is what turns the line the user typed
// into `cd`, `get`, `mkdir` and friends' arguments, using OpenSSH's quoting rules -- and `escapePath` is
// what tab completion writes back into the line for whatever name was completed, including a name that
// came from the *server* and is therefore untrusted input. `unescape` and `undoGlobEscape` are the two
// ways the two halves undo each other: `unescape` for the commands that glob, `undoGlobEscape` then the
// tokeniser's own unescaping for the ones that must take the literal path (`cd`, `mkdir`, `lcd`, `lls`,
// the get/put targets -- `client.go` calls it seven times).
//
// `quoting_test.go` checks the individual rules, and does so thoroughly: quotes, comments, spans,
// mismatched quotes, unterminated quotes, glob metacharacters. What none of its nineteen tests said is the
// property the pair exists for -- that a name which goes through completion comes back as the same name,
// and as one argument. That is the only reason `escapePath` exists, and it is the difference between
// "completing a file called `a b`" and "completing `a` and adding an argument called `b`". So it is said
// here, exhaustively, over every string of up to four characters drawn from the alphabet the tokeniser
// treats specially: quote, double quote, backslash, the three glob metacharacters, the comment character,
// space and tab, plus `a` to stand for an ordinary byte.
//
// The composition matters, and one plausible composition is wrong in a way that reads like a bug:
// `unescape(undoGlobEscape(escapePath(s)))` drops a trailing backslash, because `unescape` sees the
// `\\` that `undoGlobEscape` has just produced as an escape with nothing after it. The shipped code never
// applies the two in that order -- the tokeniser has already removed the non-glob escapes by then -- so
// what is tested below is the pipelines as they run (SR-PARSE-04). Writing the wrong one down here is
// cheaper than rediscovering it as a "fix".

// conformanceHostileAlphabet is every byte the tokeniser gives a meaning to, plus one that it does not.
var conformanceHostileAlphabet = []byte{'a', '\'', '"', '\\', '?', '*', '[', '#', ' ', '\t'}

// conformanceNames returns every string of up to maxLen characters over conformanceHostileAlphabet:
// 1 + 10 + 100 + 1000 + 10000 = 11111 for maxLen 4, which every test below finishes in milliseconds.
func conformanceNames(t *testing.T, maxLen int) []string {
	t.Helper()
	var out []string
	var build func(prefix []byte, depth int)
	build = func(prefix []byte, depth int) {
		if depth == 0 {
			out = append(out, string(append([]byte(nil), prefix...)))
			return
		}
		for _, c := range conformanceHostileAlphabet {
			build(append(prefix, c), depth-1)
		}
	}
	for n := 0; n <= maxLen; n++ {
		build(nil, n)
	}
	if len(out) == 0 {
		t.Fatal("no names generated")
	}
	return out
}

// conformanceCompleted renders a name the way the completion code does: sftp/client.go either writes
// escapePath(c, 0), unquoted, or writes the quote character, the escaped body, and the quote character
// again. Every property below is a property of that shape, because that is the shape the tokeniser reads.
func conformanceCompleted(s string, quote byte) string {
	esc := escapePath(s, quote)
	if quote == 0 {
		return esc
	}
	return string(quote) + esc + string(quote)
}

func conformanceQuotes() []byte { return []byte{0, '\'', '"'} }

func conformanceQuoteName(q byte) string {
	switch q {
	case 0:
		return "unquoted"
	case '\'':
		return "single-quoted"
	default:
		return "double-quoted"
	}
}

// TestConformanceEscapePathUnescapeRoundTrip is the innermost promise: whatever the quoting mode, undoing
// the escaping of an escaped name yields the name. A failure here would mean completion can rename a
// file -- the local or remote path used would not be the one the server reported.
func TestConformanceEscapePathUnescapeRoundTrip(t *testing.T) {
	names := conformanceNames(t, 4)
	n := 0
	for _, s := range names {
		for _, q := range conformanceQuotes() {
			esc := escapePath(s, q)
			if got := unescape(esc); got != s {
				t.Fatalf("unescape(escapePath(%q, %s)) = %q: %s", s, conformanceQuoteName(q), got,
					"a completed name would be used as a different path")
			}
			n++
		}
	}
	t.Logf("%d names over 3 quoting modes round-trip exactly", n)
}

// TestConformanceCompletedNameIsOneArgument is the outer promise, and the one a completion bug would
// break: the completed rendering of a name, parsed in strict mode, is exactly one argument -- never two,
// never none, never a rejected line. The case where the name is empty is the only exception, and it is
// the correct one: completing an empty field writes nothing, and nothing is not an argument.
func TestConformanceCompletedNameIsOneArgument(t *testing.T) {
	names := conformanceNames(t, 4)
	n := 0
	for _, s := range names {
		for _, q := range conformanceQuotes() {
			completed := conformanceCompleted(s, q)
			args, spans, _, terminated, err := makeargv("get "+completed, false)
			if err != nil {
				t.Fatalf("makeargv(%q, strict) failed after completing %q (%s): %v",
					"get "+completed, s, conformanceQuoteName(q), err)
			}
			if !terminated {
				t.Fatalf("makeargv(%q) reports an unterminated line after completing %q", "get "+completed, s)
			}
			// An empty completion writes nothing at all, and nothing is not an argument; an
			// empty name in quotes writes '', which is an explicit empty argument.
			want := 2
			if completed == "" {
				want = 1
			}
			if len(args) != want {
				t.Fatalf("completing %q (%s) as %q gave %d arguments %q, want %d",
					s, conformanceQuoteName(q), completed, len(args), args, want)
			}
			if want == 2 {
				if unescape(args[1]) != s {
					t.Fatalf("completing %q as %q yields the argument %q", s, completed, args[1])
				}
				if len(spans) != want {
					t.Fatalf("%d spans for %d arguments", len(spans), want)
				}
				line := "get " + completed
				sp := spans[1]
				if sp[0] < 0 || sp[1] > len(line) || line[sp[0]:sp[1]] != completed {
					t.Fatalf("span %v of %q covers %q, want the completed text %q",
						sp, line, line[min(sp[0], len(line)):min(sp[1], len(line))], completed)
				}
			}
			n++
		}
	}
	t.Logf("%d completed names parse to exactly the argument they stand for", n)
}

// TestConformanceLiteralCommandsGetTheExactPath is the property the seven undoGlobEscape call sites in
// client.go depend on: for the commands that must not glob, the argument the tokeniser produced, with the
// glob escaping taken back off, is the name that was completed. This is the pipeline that reaches
// os.Chdir and resolveLocalPath.
func TestConformanceLiteralCommandsGetTheExactPath(t *testing.T) {
	names := conformanceNames(t, 4)
	n := 0
	for _, s := range names {
		if s == "" {
			continue // no argument, so nothing to hand to cd
		}
		for _, q := range conformanceQuotes() {
			line := "cd " + conformanceCompleted(s, q)
			args, _, _, _, err := makeargv(line, false)
			if err != nil || len(args) != 2 {
				t.Fatalf("cd %q (completing %q, %s): %d args, err %v", line, s, conformanceQuoteName(q), len(args), err)
			}
			if got := undoGlobEscape(args[1]); got != s {
				t.Fatalf("cd takes %q where the completed name was %q (line %q, argument %q)",
					got, s, line, args[1])
			}
			n++
		}
	}
	t.Logf("%d cd arguments are the exact path that was completed", n)
}

// TestConformanceCompletedNameMatchesItselfGlobbing is the other half: for the commands that do glob, the
// argument keeps its glob escapes so that the pattern matches the name literally. A name containing `*`
// must list that file and not every file.
func TestConformanceCompletedNameMatchesItselfGlobbing(t *testing.T) {
	names := conformanceNames(t, 4)
	n := 0
	for _, s := range names {
		if s == "" || strings.ContainsAny(s, " \t") {
			continue // path.Match does not match a space, and the name would not be one field
		}
		pattern := escapePath(s, 0)
		ok, err := path.Match(pattern, s)
		if err != nil {
			t.Fatalf("path.Match(%q, %q): %v", pattern, s, err)
		}
		if !ok {
			t.Fatalf("the completed pattern %q does not match the name %q it came from", pattern, s)
		}
		n++
	}
	t.Logf("%d completed patterns match the name they were made from", n)
}

// TestConformanceSloppyModeAgreesOnCompletedNames closes the last door: sloppy mode is what completion
// itself uses, because the line being completed may be mid-quote. On a name that has just been escaped it
// has to agree with strict mode, or the display and the parse of the same line disagree.
func TestConformanceSloppyModeAgreesOnCompletedNames(t *testing.T) {
	names := conformanceNames(t, 4)
	n := 0
	for _, s := range names {
		for _, q := range conformanceQuotes() {
			line := "put " + conformanceCompleted(s, q)
			strict, strictSpans, strictQuote, strictTerm, strictErr := makeargv(line, false)
			sloppy, sloppySpans, sloppyQuote, sloppyTerm, sloppyErr := makeargv(line, true)
			if (strictErr == nil) != (sloppyErr == nil) {
				t.Fatalf("%q: strict says %v, sloppy says %v", line, strictErr, sloppyErr)
			}
			if strictTerm != sloppyTerm || strictQuote != sloppyQuote {
				t.Fatalf("%q: strict reports terminated=%v quote=%q, sloppy reports terminated=%v quote=%q",
					line, strictTerm, strictQuote, sloppyTerm, sloppyQuote)
			}
			if len(strict) != len(sloppy) || len(strictSpans) != len(sloppySpans) {
				t.Fatalf("%q: %d arguments strict, %d sloppy", line, len(strict), len(sloppy))
			}
			for i := range strict {
				if strict[i] != sloppy[i] || strictSpans[i] != sloppySpans[i] {
					t.Fatalf("%q: argument %d is %q (%v) strict and %q (%v) sloppy",
						line, i, strict[i], strictSpans[i], sloppy[i], sloppySpans[i])
				}
			}
			n++
		}
	}
	t.Logf("%d completed names parse identically in strict and sloppy mode", n)
}

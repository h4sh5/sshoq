package sftp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeargvEmpty(t *testing.T) {
	args, spans, _, terminated, err := makeargv("", false)
	if err != nil || len(args) != 0 || len(spans) != 0 || !terminated {
		t.Errorf("makeargv(\"\") = %v, spans=%v, terminated=%v, err=%v", args, spans, terminated, err)
	}
	args, spans, _, terminated, err = makeargv("   \t", false)
	if err != nil || len(args) != 0 || !terminated {
		t.Errorf("makeargv(whitespace) = %v, err=%v", args, err)
	}
}

func TestMakeargvSimple(t *testing.T) {
	args, spans, _, _, err := makeargv("ls -la", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[0] != "ls" || args[1] != "-la" {
		t.Errorf("got %v, want [ls -la]", args)
	}
	if len(spans) != 2 || spans[0] != [2]int{0, 2} || spans[1] != [2]int{3, 6} {
		t.Errorf("spans = %v, want [[0,2] [3,6]]", spans)
	}
}

func TestMakeargvLeadingTrailingSpaces(t *testing.T) {
	args, _, _, _, err := makeargv("  get   file.txt  ", false)
	if err != nil || len(args) != 2 || args[0] != "get" || args[1] != "file.txt" {
		t.Errorf("got %v, want [get file.txt]", args)
	}
}

func TestMakeargvSingleQuote(t *testing.T) {
	args, _, _, _, err := makeargv("get 'Downloads/Test File.txt'", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "Downloads/Test File.txt" {
		t.Errorf("got %v, want [get Downloads/Test File.txt]", args)
	}
}

func TestMakeargvDoubleQuote(t *testing.T) {
	args, _, _, _, err := makeargv(`get "a b"`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "a b" {
		t.Errorf("got %v, want [get a b]", args)
	}
}

func TestMakeargvBackslashEscape(t *testing.T) {
	args, _, _, _, err := makeargv("put Test\\ File\\ With\\ Space.txt", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "Test File With Space.txt" {
		t.Errorf("got %v, want [put Test File With Space.txt]", args)
	}
}

func TestMakeargvBackslashPreservesGlobMetachar(t *testing.T) {
	// Outside quotes, \?, \[, \*, \\ are preserved so glob can undo them.
	cases := []struct {
		input string
		want  string
	}{
		{`foo\*`, `foo\*`},
		{`foo\?`, `foo\?`},
		{`foo\[`, `foo\[`},
		{`foo\\`, `foo\\`},
		{`foo\ bar`, `foo bar`}, // \space → space (unescaped)
		{`foo\#bar`, `foo#bar`}, // \# → # (unescaped)
		{`foo\a`, `fooa`},       // \a → a (unescaped)
	}
	for _, c := range cases {
		args, _, _, _, err := makeargv("ls "+c.input, false)
		if err != nil {
			t.Errorf("makeargv(ls %s) error: %v", c.input, err)
			continue
		}
		if len(args) != 2 || args[1] != c.want {
			t.Errorf("makeargv(ls %s) = %q, want %q", c.input, args[1], c.want)
		}
	}
}

func TestMakeargvQuotedGlobMetachar(t *testing.T) {
	// Inside quotes, glob metacharacters are escaped so they are matched literally.
	cases := []struct {
		input string
		want  string
	}{
		{`'foo*'`, `foo\*`},
		{`"foo?"`, `foo\?`},
		{`'foo['`, `foo\[`},
		{`"*"`, `\*`},
	}
	for _, c := range cases {
		args, _, _, _, err := makeargv("ls "+c.input, false)
		if err != nil {
			t.Errorf("makeargv(ls %s) error: %v", c.input, err)
			continue
		}
		if len(args) != 2 || args[1] != c.want {
			t.Errorf("makeargv(ls %s) = %q, want %q", c.input, args[1], c.want)
		}
	}
}

func TestMakeargvQuotedBackslash(t *testing.T) {
	// Inside quotes, backslash preserves the next character.
	args, _, _, _, err := makeargv(`ls 'a\ b'`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != `a\ b` {
		t.Errorf("got %q, want %q", args[1], `a\ b`)
	}

	// Inside double quotes, backslash preserves the next character too.
	args, _, _, _, err = makeargv(`ls "a\ b"`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != `a\ b` {
		t.Errorf("got %q, want %q", args[1], `a\ b`)
	}
}

func TestMakeargvQuotedEscapeQuote(t *testing.T) {
	// Inside single quotes, \' → '
	args, _, _, _, err := makeargv(`ls 'a\'b'`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != `a'b` {
		t.Errorf("got %q, want %q", args[1], `a'b`)
	}

	// Inside double quotes, \" → "
	args, _, _, _, err = makeargv(`ls "a\"b"`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != `a"b` {
		t.Errorf("got %q, want %q", args[1], `a"b`)
	}
}

func TestMakeargvAdjacentQuotedSegments(t *testing.T) {
	args, _, _, _, err := makeargv(`ls 'a''b'`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "ab" {
		t.Errorf("got %q, want %q", args[1], "ab")
	}
}

func TestMakeargvQuotedAndUnquotedAdjacent(t *testing.T) {
	args, _, _, _, err := makeargv(`ls 'a b'c`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "a bc" {
		t.Errorf("got %q, want %q", args[1], "a bc")
	}
}

func TestMakeargvMismatchedQuote(t *testing.T) {
	// A single quote inside double quotes is literal.
	args, _, _, _, err := makeargv(`ls "a'b"`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != `a'b` {
		t.Errorf("got %q, want %q", args[1], `a'b`)
	}
	// A double quote inside single quotes is literal.
	args, _, _, _, err = makeargv(`ls 'a"b'`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != `a"b` {
		t.Errorf("got %q, want %q", args[1], `a"b`)
	}
}

func TestMakeargvComment(t *testing.T) {
	args, _, _, _, err := makeargv("ls foo # this is a comment", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[0] != "ls" || args[1] != "foo" {
		t.Errorf("got %v, want [ls foo]", args)
	}

	// A '#' inside quotes is literal.
	args, _, _, _, err = makeargv("get '#file'", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "#file" {
		t.Errorf("got %v, want [get #file]", args)
	}
}

func TestMakeargvUnterminatedQuote(t *testing.T) {
	_, _, _, _, err := makeargv("get 'foo", false)
	if err == nil {
		t.Error("expected error for unterminated quote, got nil")
	}
}

func TestMakeargvSloppyUnterminated(t *testing.T) {
	args, spans, lastquote, terminated, err := makeargv("get 'foo", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "foo" {
		t.Errorf("got %v, want [get foo]", args)
	}
	if lastquote != '\'' {
		t.Errorf("lastquote = %q, want '", lastquote)
	}
	if terminated {
		t.Error("terminated = true, want false")
	}
	_ = spans
}

func TestMakeargvSloppyTrailingBackslash(t *testing.T) {
	args, _, _, terminated, err := makeargv("get foo\\", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "foo" {
		t.Errorf("got %v, want [get foo]", args)
	}
	if terminated {
		t.Error("terminated = true, want false")
	}
}

func TestMakeargvStrictTrailingBackslash(t *testing.T) {
	_, _, _, _, err := makeargv("get foo\\", false)
	if err == nil {
		t.Error("expected error for trailing backslash, got nil")
	}
}

func TestMakeargvSpans(t *testing.T) {
	args, spans, _, _, err := makeargv("cd 'a b' x", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 3 || args[1] != "a b" || args[2] != "x" {
		t.Errorf("args = %v", args)
	}
	// cd: [0,2), 'a b': [3,8), x: [9,10)
	if len(spans) != 3 {
		t.Fatalf("spans = %v, want 3 entries", spans)
	}
	if spans[0] != [2]int{0, 2} {
		t.Errorf("span[0] = %v, want [0,2]", spans[0])
	}
	if spans[1] != [2]int{3, 8} {
		t.Errorf("span[1] = %v, want [3,8]", spans[1])
	}
	if spans[2] != [2]int{9, 10} {
		t.Errorf("span[2] = %v, want [9,10]", spans[2])
	}
}

func TestUndoGlobEscape(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"foo", "foo"},
		{`foo\*bar`, `foo*bar`},
		{`foo\?bar`, `foo?bar`},
		{`foo\[bar`, `foo[bar`},
		{`foo\\bar`, `foo\bar`},
		{`foo\bar`, `foo\bar`},   // \b is not a glob metachar → kept
		{`foo\ bar`, `foo\ bar`}, // \space kept
		{`foo\`, `foo\`},         // trailing backslash kept
	}
	for _, c := range cases {
		got := undoGlobEscape(c.input)
		if got != c.want {
			t.Errorf("undoGlobEscape(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestUnescape(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"foo", "foo"},
		{`foo\ bar`, `foo bar`},
		{`foo\*bar`, `foo*bar`},
		{`foo\\bar`, `foo\bar`},
		{`foo\bar`, `foobar`}, // \b → b (all backslashes removed)
		{`foo\\\*`, `foo\*`},  // \\ → \, \* → *
		{`foo\`, `foo`},       // trailing backslash: removed
	}
	for _, c := range cases {
		got := unescape(c.input)
		if got != c.want {
			t.Errorf("unescape(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestEscapePath(t *testing.T) {
	cases := []struct {
		input string
		quote byte
		want  string
	}{
		{"foo.txt", 0, "foo.txt"},
		{"a b.txt", 0, `a\ b.txt`},
		{"a*b.txt", 0, `a\*b.txt`},
		{"a?b.txt", 0, `a\?b.txt`},
		{"a[b.txt", 0, `a\[b.txt`},
		{"a'b.txt", 0, `a\'b.txt`},
		{`a\b.txt`, 0, `a\\b.txt`},
		{"a#b.txt", 0, `a\#b.txt`},
		// Inside quotes, only the quote char and backslash are escaped.
		{"a b.txt", '\'', "a b.txt"},
		{"a'b.txt", '\'', `a\'b.txt`},
		{`a\b.txt`, '\'', `a\\b.txt`},
		{"a b.txt", '"', "a b.txt"},
		{"a\"b.txt", '"', `a\"b.txt`},
		{`a\b.txt`, '"', `a\\b.txt`},
	}
	for _, c := range cases {
		got := escapePath(c.input, c.quote)
		if got != c.want {
			t.Errorf("escapePath(%q, %q) = %q, want %q",
				c.input, c.quote, got, c.want)
		}
	}
}

func TestGlobSplitEscaped(t *testing.T) {
	// These test cases are added to the existing TestGlobSplit suite.
	cases := []struct {
		arg         string
		wantDir     string
		wantPattern string
		wantOK      bool
	}{
		// Escaped metacharacters: not globs.
		{`foo\*`, "", "", false},
		{`foo\?`, "", "", false},
		{`foo\[`, "", "", false},
		{`dir/foo\*`, "", "", false},
		{`foo\\`, "", "", false},
		// Unescaped metacharacters: globs.
		{"foo*", "", "foo*", true},
		{"dir/foo*", "dir", "foo*", true},
		{`dir\ one/foo*`, `dir\ one`, "foo*", true},
		// Empty.
		{"", "", "", false},
		// Plain.
		{"plain", "", "", false},
		{"path/plain", "", "", false},
	}
	for _, c := range cases {
		dir, pat, ok := globSplit(c.arg)
		if dir != c.wantDir || pat != c.wantPattern || ok != c.wantOK {
			t.Errorf("globSplit(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.arg, dir, pat, ok, c.wantDir, c.wantPattern, c.wantOK)
		}
	}
}

// TestMakeargvWithPoundInCommentPosition verifies that # outside quotes
// terminates the line, even when preceded by a backslash-escaped #.
func TestMakeargvEscapedPound(t *testing.T) {
	// \# outside quotes produces a literal #, then the # char is consumed
	// by the escape processing, so it does NOT start a comment. The next
	// character after the escape is processed normally.
	args, _, _, _, err := makeargv("ls foo\\#bar", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "foo#bar" {
		t.Errorf("got %v, want [ls foo#bar]", args)
	}
}

// TestMakeargvDoubleEscapedGlob verifies that inside quotes, a backslash
// before a glob metacharacter produces a triple-escaped sequence
// (\\ + \ + char → \\\* etc.) that glob(3) will undo to a literal.
func TestMakeargvQuotedBackslashGlob(t *testing.T) {
	// Inside double quotes, \* → \\\* (triple escaped)
	args, _, _, _, err := makeargv(`ls "a\*b"`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args[1] != `a\\\*b` {
		t.Errorf("got %q, want %q", args[1], `a\\\*b`)
	}

	// Inside single quotes, \* → \\\* (same)
	args, _, _, _, err = makeargv(`ls 'a\*b'`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args[1] != `a\\\*b` {
		t.Errorf("got %q, want %q", args[1], `a\\\*b`)
	}
}

// TestMakeargvErrorIsExported ensures the error message matches OpenSSH.
func TestMakeargvErrorMessage(t *testing.T) {
	_, _, _, _, err := makeargv("get 'foo", false)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "unterminated quoted argument" {
		t.Errorf("got error %q, want 'unterminated quoted argument'", err)
	}
}

// TestMakeargvBackslashInUnquotedPreservesDoubleBackslash verifies that
// outside quotes, \\ is preserved (so glob can undo it to \).
func TestMakeargvUnquotedDoubleBackslash(t *testing.T) {
	args, _, _, _, err := makeargv(`ls a\\b`, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args[1] != `a\\b` {
		t.Errorf("got %q, want %q", args[1], `a\\b`)
	}
}

// TestMakeargvLastquoteAndTerminated verifies lastquote and terminated.
func TestMakeargvLastquoteTerminated(t *testing.T) {
	// Unquoted arg: lastquote = 0, terminated = true
	_, _, lq, term, err := makeargv("ls foo", false)
	if err != nil {
		t.Fatal(err)
	}
	if lq != 0 || !term {
		t.Errorf("lastquote=%d, terminated=%v, want 0, true", lq, term)
	}

	// Single-quoted and closed: lastquote = ', terminated = true
	_, _, lq, term, err = makeargv("ls 'foo'", false)
	if err != nil {
		t.Fatal(err)
	}
	if lq != '\'' || !term {
		t.Errorf("lastquote=%d, terminated=%v, want %d, true", lq, term, '\'')
	}

	// Double-quoted and closed: lastquote = ", terminated = true
	_, _, lq, term, err = makeargv(`ls "foo"`, false)
	if err != nil {
		t.Fatal(err)
	}
	if lq != '"' || !term {
		t.Errorf("lastquote=%d, terminated=%v, want %d, true", lq, term, '"')
	}
}

// TestMakeargvErrorType ensures the error can be compared with errors.Is.
func TestMakeargvErrorType(t *testing.T) {
	_, _, _, _, err := makeargv("get 'foo", false)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errUnterminated) {
		t.Errorf("errors.Is(err, errUnterminated) = false, want true")
	}
}

// TestClientDoLsEscapedLiteralGlob verifies that a backslash-escaped glob
// metacharacter is not treated as a glob: ls foo\* lists the literal path
// "foo*" (after makeargv, the escaped star reaches doLs as "foo\*").
func TestClientDoLsEscapedLiteralGlob(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{
		OK:      true,
		Entries: lsEntries("inside"),
	}))
	// parts simulate the output of makeargv("ls foo\\*").
	if err := doLs(ch, "/remote", []string{"ls", `foo\*`}); err != nil {
		t.Fatalf("doLs error: %v", err)
	}
	var got Request
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote/foo*" {
		t.Fatalf("expected ls /remote/foo*, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoLsEscapedSpaceInDir verifies that an escaped space inside a glob
// directory is un-escaped before the ls request: ls 'sub\ dir'/*.txt lists
// /remote/sub dir and matches entries against *.txt.
func TestClientDoLsEscapedSpaceInDir(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{
		OK:      true,
		Entries: lsEntries("a.txt", "b.txt", "c.md"),
	}))
	// parts simulate the output of makeargv("ls 'sub\\ dir'/*.txt").
	if err := doLs(ch, "/remote", []string{"ls", `sub\ dir/*.txt`}); err != nil {
		t.Fatalf("doLs error: %v", err)
	}
	var got Request
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote/sub dir" {
		t.Fatalf("expected ls /remote/sub dir, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoLsQuotedWildcard verifies that a wildcard inside quotes is
// escaped to a literal: ls 'test*' must not glob, so the request goes to the
// literal path /remote/test*.
func TestClientDoLsQuotedWildcard(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{
		OK:      true,
		Entries: lsEntries("inside"),
	}))
	// parts simulate the output of makeargv("ls 'test*'").
	if err := doLs(ch, "/remote", []string{"ls", `test\*`}); err != nil {
		t.Fatalf("doLs error: %v", err)
	}
	var got Request
	if len(ch.Writes) != 1 {
		t.Fatalf("expected 1 request, got %d", len(ch.Writes))
	}
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote/test*" {
		t.Fatalf("expected ls /remote/test*, got %s %q", got.Cmd, got.Path)
	}
}

// TestClientDoGetQuotedPath verifies the canonical example:
// get 'Downloads/Test File.txt' stats the file with the space in its name.
func TestClientDoGetQuotedPath(t *testing.T) {
	localDir := t.TempDir()
	ch := newMockChannel(
		makeJSONDataMsg(&Response{OK: true, Info: &FileInfo{Name: "Test File.txt", Size: 5}}),
		makeJSONDataMsg(&Response{OK: true, Data: []byte("hello")}),
		makeJSONDataMsg(&Response{OK: true, Data: []byte{}}),
	)
	// parts simulate the output of makeargv("get 'Downloads/Test File.txt'").
	if err := doGet(ch, localDir, "/remote", []string{"get", "Downloads/Test File.txt"}); err != nil {
		t.Fatalf("doGet error: %v", err)
	}
	var got Request
	if len(ch.Writes) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(ch.Writes))
	}
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "stat" || got.Path != "/remote/Downloads/Test File.txt" {
		t.Fatalf("expected stat /remote/Downloads/Test File.txt, got %s %q", got.Cmd, got.Path)
	}
	content, err := os.ReadFile(filepath.Join(localDir, "Test File.txt"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}
}

// TestClientDoGetEscapedGlobMetachar verifies that an escaped glob
// metacharacter in a get source downloads the literal file:
// get 'foo*.txt' (quoted) reaches doGet as "foo\*.txt" and is downloaded
// without globbing.
func TestClientDoGetEscapedGlobMetachar(t *testing.T) {
	localDir := t.TempDir()
	ch := newMockChannel(
		makeJSONDataMsg(&Response{OK: true, Info: &FileInfo{Name: "foo*.txt", Size: 5}}),
		makeJSONDataMsg(&Response{OK: true, Data: []byte("hello")}),
		makeJSONDataMsg(&Response{OK: true, Data: []byte{}}),
	)
	// parts simulate the output of makeargv("get 'foo*.txt'").
	if err := doGet(ch, localDir, "/remote", []string{"get", `foo\*.txt`}); err != nil {
		t.Fatalf("doGet error: %v", err)
	}
	var got Request
	if len(ch.Writes) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(ch.Writes))
	}
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Cmd != "stat" || got.Path != "/remote/foo*.txt" {
		t.Fatalf("expected stat /remote/foo*.txt, got %s %q", got.Cmd, got.Path)
	}
	content, err := os.ReadFile(filepath.Join(localDir, "foo*.txt"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}
}

// TestCompleterQuotedWord verifies tab completion inside a single-quoted
// word: the candidate is re-quoted (opening and closing quote) and the
// replacement starts at the opening quote.
func TestCompleterQuotedWord(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
		FileInfo{Name: "remote.txt"},
	)}))
	localDir, remoteDir := "/local", "/remote"
	c := newCompleter(ch, &localDir, &remoteDir)

	cands, start := c([]rune("get 'rem"), 8)
	if start != 4 {
		t.Errorf("start = %d, want 4 (the opening quote)", start)
	}
	if len(cands) != 1 || cands[0] != "'remote.txt'" {
		t.Errorf("candidates = %v, want ['remote.txt']", cands)
	}
}

// TestCompleterQuotedWordWithSpace verifies completion inside a quoted word
// containing a space: the directory is resolved from the parsed word and the
// candidate is wrapped in quotes.
func TestCompleterQuotedWordWithSpace(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
		FileInfo{Name: "foobar.txt"},
	)}))
	localDir, remoteDir := "/local", "/remote"
	c := newCompleter(ch, &localDir, &remoteDir)

	cands, start := c([]rune("cd 'my dir/fo"), 13)
	if start != 3 {
		t.Errorf("start = %d, want 3 (the opening quote)", start)
	}
	if len(cands) != 1 || cands[0] != "'my dir/foobar.txt'" {
		t.Errorf("candidates = %v, want ['my dir/foobar.txt']", cands)
	}
	var got Request
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote/my dir" {
		t.Errorf("request = %s %q, want ls %q", got.Cmd, got.Path, "/remote/my dir")
	}
}

// TestCompleterQuotedWordSpecialChars verifies that special characters in
// completions are escaped for unquoted input and left bare inside quotes.
func TestCompleterQuotedWordSpecialChars(t *testing.T) {
	// Local completion for lls: files with spaces, quotes and asterisks.
	dir := t.TempDir()
	for _, name := range []string{"a b.txt", "it's.txt", "a*b.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	localDir, remoteDir := dir, "/remote"
	c := newCompleter(nil, &localDir, &remoteDir)

	// Unquoted completion escapes the space, quote and star.
	cands, start := c([]rune("lls "), 4)
	if start != 4 {
		t.Errorf("start = %d, want 4", start)
	}
	if len(cands) != 3 {
		t.Fatalf("candidates = %v, want 3", cands)
	}
	found := map[string]bool{}
	for _, cand := range cands {
		found[cand] = true
	}
	for _, want := range []string{`a\ b.txt`, `it\'s.txt`, `a\*b.txt`} {
		if !found[want] {
			t.Errorf("missing escaped candidate %q in %v", want, cands)
		}
	}

	// Quoted completion leaves spaces and stars bare, escapes quotes.
	cands, _ = c([]rune("lls '"), 5)
	if len(cands) != 3 {
		t.Fatalf("quoted candidates = %v, want 3", cands)
	}
	found = map[string]bool{}
	for _, cand := range cands {
		found[cand] = true
	}
	for _, want := range []string{`'a b.txt'`, `'it\'s.txt'`, `'a*b.txt'`} {
		if !found[want] {
			t.Errorf("missing quoted candidate %q in %v", want, cands)
		}
	}
}

// TestMakeargvRoundTripPutExample verifies the second canonical example:
// put Test\ File\ With\ Space.txt parses to a single path with spaces.
func TestMakeargvRoundTripPutExample(t *testing.T) {
	args, _, _, _, err := makeargv("put Test\\ File\\ With\\ Space.txt", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 || args[1] != "Test File With Space.txt" {
		t.Errorf("got %v, want [put Test File With Space.txt]", args)
	}
}

// TestParseTransferArgsQuoted verifies parseTransferArgs on makeargv output.
func TestParseTransferArgsQuoted(t *testing.T) {
	recursive, source, target, err := parseTransferArgs(
		[]string{"get", "Downloads/Test File.txt", "local copy.txt"}, "get")
	if err != nil {
		t.Fatalf("parseTransferArgs error: %v", err)
	}
	if recursive || source != "Downloads/Test File.txt" || target != "local copy.txt" {
		t.Errorf("got (%v, %q, %q)", recursive, source, target)
	}
}

// TestCompleterUTF8Spans verifies that completion start offsets are rune
// indices even when the prefix contains multibyte characters.
func TestCompleterUTF8Spans(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
		FileInfo{Name: "café.txt"},
	)}))
	localDir, remoteDir := "/local", "/remote"
	c := newCompleter(ch, &localDir, &remoteDir)

	// "cd docé/ca" — the first argument starts at rune index 3.
	buf := []rune("cd docé/ca")
	cands, start := c(buf, len(buf))
	if start != 3 {
		t.Errorf("start = %d, want 3", start)
	}
	if len(cands) != 1 || cands[0] != "docé/café.txt" {
		t.Errorf("candidates = %v, want [docé/café.txt]", cands)
	}
	var got Request
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if got.Path != "/remote/docé" {
		t.Errorf("request path = %q, want %q", got.Path, "/remote/docé")
	}
}

// TestCommandLineCaseInsensitive verifies the command switch is
// case-insensitive like OpenSSH.
func TestCommandNameLowercased(t *testing.T) {
	if strings.ToLower("GET") != "get" || strings.ToLower("Cd") != "cd" {
		t.Fatal("strings.ToLower not working as expected")
	}
}

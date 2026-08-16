package sftp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCompletePath verifies that completePath lists the directory the word
// refers to and matches its entries against the word's final component,
// returning full replacements for the word.
func TestCompletePath(t *testing.T) {
	listDir := func(dir string) ([]string, error) {
		switch dir {
		case ".":
			return []string{"alpha.txt", "beta.txt", "docs/"}, nil
		case "docs":
			return []string{"alpha.txt", "beta.txt", "docs/"}, nil
		case "/":
			return []string{"usr/", "var/"}, nil
		case "/usr":
			return []string{"bin/", "lib/", "local/"}, nil
		}
		return nil, os.ErrNotExist
	}

	cases := []struct {
		word string
		want []string
	}{
		{"", []string{"alpha.txt", "beta.txt", "docs/"}},
		{"a", []string{"alpha.txt"}},
		{"doc", []string{"docs/"}},
		{"docs/", []string{"docs/alpha.txt", "docs/beta.txt", "docs/docs/"}},
		{"/usr/l", []string{"/usr/lib/", "/usr/local/"}},
		{"/u", []string{"/usr/"}},
		{"/", []string{"/usr/", "/var/"}},
		{"missing", nil},
	}
	for _, c := range cases {
		got := completePath(c.word, listDir)
		if len(got) != len(c.want) {
			t.Errorf("completePath(%q) = %v, want %v", c.word, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("completePath(%q) = %v, want %v", c.word, got, c.want)
				break
			}
		}
	}
}

func remoteEntries(entries ...FileInfo) []FileInfo {
	return entries
}

func TestCompleterRemote(t *testing.T) {
	resp := makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
		FileInfo{Name: "docs", IsDir: true},
		FileInfo{Name: "file1.txt"},
		FileInfo{Name: "file2.txt"},
	)})
	// One response per completer call that reaches the channel: each of the
	// three calls below issues an ls request.
	ch := newMockChannel(resp, resp, resp)
	localDir, remoteDir := "/local", "/remote"
	c := newCompleter(ch, &localDir, &remoteDir)

	cands, start := c([]rune("cd fi"), 5)
	if start != 3 {
		t.Errorf("start = %d, want 3", start)
	}
	if len(cands) != 2 || cands[0] != "file1.txt" || cands[1] != "file2.txt" {
		t.Errorf("candidates = %v, want [file1.txt file2.txt]", cands)
	}
	var got Request
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if got.Cmd != "ls" || got.Path != "/remote" {
		t.Errorf("request = %s %q, want ls %q", got.Cmd, got.Path, "/remote")
	}

	// Directory entries carry a trailing "/".
	cands, _ = c([]rune("cd d"), 4)
	if len(cands) != 1 || cands[0] != "docs/" {
		t.Errorf("directory candidate = %v, want [docs/]", cands)
	}

	// The word must be the second argument; the first argument is skipped.
	cands, _ = c([]rune("cd x fi"), 7)
	if len(cands) != 2 || cands[0] != "file1.txt" {
		t.Errorf("second-argument candidates = %v", cands)
	}

	// No candidates when the cursor is on the command word itself.
	if cands, start := c([]rune("cd"), 2); cands != nil || start != 0 {
		t.Errorf("command word: got %v start=%d, want nil/0", cands, start)
	}

	// Unknown commands are not completed.
	if cands, _ := c([]rune("frobnicate x"), 12); cands != nil {
		t.Errorf("unknown command: got %v, want nil", cands)
	}
}

func TestCompleterRemoteTrailingSlashListsDir(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
		FileInfo{Name: "main.go"},
		FileInfo{Name: "util.go"},
	)}))
	localDir, remoteDir := "/local", "/remote"
	c := newCompleter(ch, &localDir, &remoteDir)

	cands, start := c([]rune("cd docs/m"), 9)
	if start != 3 {
		t.Errorf("start = %d, want 3", start)
	}
	// "docs/m" must list /remote/docs and match the final component.
	if len(cands) != 1 || cands[0] != "docs/main.go" {
		t.Errorf("candidates = %v, want [docs/main.go]", cands)
	}
	var got Request
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if got.Path != "/remote/docs" {
		t.Errorf("request path = %q, want %q", got.Path, "/remote/docs")
	}
}

func TestCompleterRemoteAbsolute(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
		FileInfo{Name: "var"},
		FileInfo{Name: "usr", IsDir: true},
	)}))
	localDir, remoteDir := "/local", "/remote"
	c := newCompleter(ch, &localDir, &remoteDir)

	cands, _ := c([]rune("ls /u"), 5)
	if len(cands) != 1 || cands[0] != "/usr/" {
		t.Errorf("absolute candidates = %v, want [/usr/]", cands)
	}
	var got Request
	if err := json.Unmarshal(ch.Writes[0], &got); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if got.Path != "/" {
		t.Errorf("request path = %q, want /", got.Path)
	}
}

func TestCompleterRemoteError(t *testing.T) {
	ch := newMockChannel(makeJSONDataMsg(&Response{OK: false, Error: "no such file"}))
	localDir, remoteDir := "/local", "/remote"
	c := newCompleter(ch, &localDir, &remoteDir)

	if cands, _ := c([]rune("cd nope"), 7); cands != nil {
		t.Errorf("error listing: got %v, want nil", cands)
	}
}

func TestCompleterLocal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "one.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	localDir, remoteDir := dir, "/remote"
	c := newCompleter(nil, &localDir, &remoteDir)

	cands, start := c([]rune("lls o"), 5)
	if start != 4 {
		t.Errorf("start = %d, want 4", start)
	}
	if len(cands) != 1 || cands[0] != "one.txt" {
		t.Errorf("local candidates = %v, want [one.txt]", cands)
	}

	cands, _ = c([]rune("lcd s"), 5)
	if len(cands) != 1 || cands[0] != "sub/" {
		t.Errorf("local directory candidate = %v, want [sub/]", cands)
	}
}

func TestCompleterGetPutSides(t *testing.T) {
	// get: the source argument is remote, the target is local.
	// Two completer calls reach the channel (get source and put target), each
	// needs its own ls response.
	ch := newMockChannel(
		makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
			FileInfo{Name: "remote.txt"},
		)}),
		makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
			FileInfo{Name: "remote.txt"},
		)}),
	)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "local.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	localDir, remoteDir := dir, "/remote"
	c := newCompleter(ch, &localDir, &remoteDir)

	cands, _ := c([]rune("get r"), 5)
	if len(cands) != 1 || cands[0] != "remote.txt" {
		t.Errorf("get source (remote) = %v, want [remote.txt]", cands)
	}

	cands, _ = c([]rune("get remote.txt "), 15)
	if len(cands) != 1 || cands[0] != "local.txt" {
		t.Errorf("get target (local) = %v, want [local.txt]", cands)
	}

	// put: the source argument is local, the target is remote.
	cands, _ = c([]rune("put l"), 5)
	if len(cands) != 1 || cands[0] != "local.txt" {
		t.Errorf("put source (local) = %v, want [local.txt]", cands)
	}

	cands, _ = c([]rune("put local.txt r"), 15)
	if len(cands) != 1 || cands[0] != "remote.txt" {
		t.Errorf("put target (remote) = %v, want [remote.txt]", cands)
	}

	// Flags such as -r are skipped when counting the argument.
	cands, _ = c([]rune("put -r l"), 7)
	if len(cands) != 1 || cands[0] != "local.txt" {
		t.Errorf("put -r source (local) = %v, want [local.txt]", cands)
	}
}

// TestEditorRemoteTabCompletion drives the full line editor against a mock
// sftp channel: the first Tab completes to the common prefix of a remote
// listing, the second Tab lists the candidates, and a further Tab on a typed
// suffix completes a unique file inside the resolved directory.
func TestEditorRemoteTabCompletion(t *testing.T) {
	q := newQueuedMockChannel()
	q.enqueue(
		makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
			FileInfo{Name: "src", IsDir: true},
			FileInfo{Name: "src.tar.gz"},
		)}),
		makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
			FileInfo{Name: "src", IsDir: true},
			FileInfo{Name: "src.tar.gz"},
		)}),
		makeJSONDataMsg(&Response{OK: true, Entries: remoteEntries(
			FileInfo{Name: "main.go"},
			FileInfo{Name: "util.go"},
		)}),
	)
	localDir, remoteDir := "/local", "/remote"
	var out bytes.Buffer
	e := &lineEditor{
		reader:    bufio.NewReader(strings.NewReader("cd s\t\t/m\t\r")),
		out:       &out,
		outFd:     -1,
		width:     80,
		prompt:    "sftp> ",
		histPos:   -1,
		completer: newCompleter(q, &localDir, &remoteDir),
	}
	line := readWithTimeout(t, e, 5*time.Second)
	if line != "cd src/main.go " {
		t.Errorf("line = %q, want %q", line, "cd src/main.go ")
	}
	if !strings.Contains(out.String(), "src.tar.gz") {
		t.Errorf("second tab should list candidates, got output %q", out.String())
	}

	// Three ls requests: the working directory (twice, for the completion and
	// the candidate listing) and the resolved subdirectory.
	writes := q.Writes()
	if len(writes) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(writes))
	}
	for i, want := range []string{"/remote", "/remote", "/remote/src"} {
		var got Request
		if err := json.Unmarshal(writes[i], &got); err != nil {
			t.Fatalf("unmarshal request %d: %v", i, err)
		}
		if got.Cmd != "ls" || got.Path != want {
			t.Errorf("request %d = %s %q, want ls %q", i, got.Cmd, got.Path, want)
		}
	}
}

// readWithTimeout runs e.read in a goroutine and fails the test if it does not
// return within the given duration. Completion tests that drive a mock sftp
// channel must fail fast instead of hanging the suite when a request is left
// unanswered.
func readWithTimeout(t *testing.T, e *lineEditor, d time.Duration) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := e.read()
		done <- result{line, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("read: %v", r.err)
		}
		return r.line
	case <-time.After(d):
		t.Fatalf("line editor read timed out after %s", d)
		return ""
	}
}

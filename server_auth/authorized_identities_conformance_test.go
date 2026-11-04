package server_auth

// Who a user is, sshoq learns from two files under that user's home:
// `.ssh3/authorized_identities` and `.ssh/authorized_keys` (`DefaultIdentitiesFileNames`). The
// decision of *which* lines in those files become credentials is `ParseAuthorizedIdentitiesFile`
// and `GetAuthorizedIdentities`, and until this file nothing tested them: the comment grammar, the
// "one bad line does not spoil the file" rule, the "an unreadable file authorizes nobody but forbids
// nothing" rule which a comment in `GetAuthorizedIdentities` says used to be broken, the line-length
// ceiling of the reader, and the question of whose directory the path is relative to -- all asserted
// only by prose (finding **F17**).
//
// The verifier produced for a line is not examined here beyond counting it: what a key credential
// must satisfy is SR-AUTH-12, and what the account gate must say before any of this runs is
// SR-AUTH-11. What belongs to this file is the *file*: its names, its grammar, and what a damaged
// one is allowed to do.

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/h4sh5/sshoq/util/unix_util"
)

// identityLine makes a line the package test suite can recognise as a credential. The stub plugin
// registered in `static_identities_test.go` -- which stands in for the public-key plugin, because
// importing that package from here would be an import cycle -- recognises lines beginning with
// `stubkey `. What a real key line has to satisfy is SR-AUTH-12 and is tested there; what is under
// test here is the file around the line, so the line only has to be distinguishable from a comment,
// a blank and a piece of garbage.
func identityLine(tag string) string {
	return "stubkey " + tag
}

// homeWithIdentities builds a user whose home is a temporary directory containing the given
// relative paths with the given contents.
func homeWithIdentities(t *testing.T, files map[string]string) *unix_util.User {
	t.Helper()
	home := t.TempDir()
	for name, content := range files {
		full := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &unix_util.User{Username: "alice", Dir: home, Uid: 1000}
}

func writeIdentities(t *testing.T, user *unix_util.User, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(user.Dir, ".ssh3"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(user.Dir, ".ssh3", "authorized_identities"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestConformanceIdentityFileNamesAreTheUsersTwoFiles is the least interesting and most load-bearing
// claim: which paths are opened, in which order, and under whose home.
func TestConformanceIdentityFileNamesAreTheUsersTwoFiles(t *testing.T) {
	names := DefaultIdentitiesFileNames(&unix_util.User{Username: "alice", Dir: "/home/alice"})
	want := []string{"/home/alice/.ssh3/authorized_identities", "/home/alice/.ssh/authorized_keys"}
	if len(names) != len(want) {
		t.Fatalf("the server opens %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("name %d = %q, want %q", i, names[i], want[i])
		}
	}

	// Measured, and the reason a service account is worth thinking about: an account with no home
	// directory does not get "no identity files", it gets *relative* ones. `path.Join("", ".ssh",
	// "authorized_keys")` is ".ssh/authorized_keys", which the open resolves against the working
	// directory of the server process. Who can write there is a property of how the server was
	// started, not of the account -- see finding F17.
	relative := DefaultIdentitiesFileNames(&unix_util.User{Username: "svc", Dir: ""})
	for _, name := range relative {
		if filepath.IsAbs(name) {
			t.Errorf("an account with no home produced the absolute name %q; this test records that the names are relative, so that a fix is a decision and not a surprise", name)
		}
	}
}

// TestConformanceAbsentIdentityFilesAreTheNormalCase is the common path: a user with no identity
// files at all is not an error, and gets whatever the server holds in memory.
func TestConformanceAbsentIdentityFilesAreTheNormalCase(t *testing.T) {
	user := &unix_util.User{Username: "fresh", Dir: t.TempDir(), Uid: 1001}
	before := len(StaticAuthorizedIdentities())
	AddStaticAuthorizedIdentities(identityLine("server-held"))
	defer func() { staticIdentities.lines = staticIdentities.lines[:before] }()

	identities, err := GetAuthorizedIdentities(user)
	if err != nil {
		t.Fatalf("a user with no identity files is the normal case, got an error: %v", err)
	}
	if len(identities) != 1 {
		t.Errorf("a user with no files should hold exactly the server's own identity, got %d", len(identities))
	}
}

// TestConformanceUnreadableIdentityFileAuthorizesNobodyButForbidsNothing is the rule the comment in
// GetAuthorizedIdentities says was fixed, and which had no test: a file that cannot be read
// contributes nothing, and must not take away the identities the server holds itself. The file is
// replaced by a *directory* here rather than chmod'd, because these tests run as root, for whom
// permission bits do not refuse a read; opening a directory succeeds and reading it fails, which is
// the same shape of failure -- an I/O error on a file that exists.
func TestConformanceUnreadableIdentityFileAuthorizesNobodyButForbidsNothing(t *testing.T) {
	user := &unix_util.User{Username: "blocked", Dir: t.TempDir(), Uid: 1002}
	if err := os.MkdirAll(filepath.Join(user.Dir, ".ssh3", "authorized_identities"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := len(StaticAuthorizedIdentities())
	AddStaticAuthorizedIdentities(identityLine("server-held"))
	defer func() { staticIdentities.lines = staticIdentities.lines[:before] }()

	identities, err := GetAuthorizedIdentities(user)
	if err != nil {
		t.Errorf("an unreadable identities file must not fail the whole lookup: %v", err)
	}
	if len(identities) != 1 {
		t.Errorf("the unreadable file took the server's own identity with it: %d identities, want 1", len(identities))
	}
}

// TestConformanceFileGrammarIsTheDocumentedOne pins which lines become credentials. The rule that
// matters is the one a user relies on: a file with one unparseable line still authorizes the keys in
// it, and a comment is a comment. The indented comment is measured rather than assumed, because the
// blank-line test above it trims whitespace and the comment test does not.
func TestConformanceFileGrammarIsTheDocumentedOne(t *testing.T) {
	good1 := identityLine("one")
	good2 := identityLine("two")

	cases := []struct {
		name    string
		content string
		want    int
	}{
		{"a single key", good1 + "\n", 1},
		{"two keys", good1 + "\n" + good2 + "\n", 2},
		{"no trailing newline", good1, 1},
		{"blank line between", good1 + "\n\n" + good2 + "\n", 2},
		{"whitespace-only line between", good1 + "\n   \n\t\n" + good2 + "\n", 2},
		{"comment at column zero", "# a note\n" + good1 + "\n", 1},
		{"comment in the middle", good1 + "\n# a note\n" + good2 + "\n", 2},
		// measured: `line[0] == '#'` is the comment test, so an indented comment is not a
		// comment but a line to parse -- which contributes nothing, so the count is unaffected
		// and the log gets an error nobody sees
		{"indented comment", "   # a note\n" + good1 + "\n", 1},
		{"garbage line among keys", "not an identity at all\n" + good1 + "\n", 1},
		{"empty file", "", 0},
		{"only comments", "# one\n# two\n", 0},
		{"CRLF line endings", strings.ReplaceAll(good1+"\n"+good2+"\n", "\n", "\r\n"), 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user := &unix_util.User{Username: "grammar", Dir: t.TempDir(), Uid: 1003}
			writeIdentities(t, user, c.content)
			identities, err := GetAuthorizedIdentities(user)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(identities) != c.want {
				t.Errorf("%d credentials from %q, want %d", len(identities), c.content, c.want)
			}
		})
	}
}

// TestConformanceLongLinesStopTheReaderSilently is the finding. The file is read with a
// bufio.Scanner, whose default maximum token is 64 KiB, and the scanner's error is never examined:
// `ParseAuthorizedIdentitiesFile` returns whatever it collected and a nil error. A line longer than
// that -- a key with a very long comment field, a file into which something large was appended --
// ends the read, and every identity after it is gone with nothing said. The assertions below are the
// measured behaviour, not the wished-for one: the keys before the long line survive, the key after
// it does not, and the caller is told nothing.
func TestConformanceLongLinesStopTheReaderSilently(t *testing.T) {
	before := identityLine("before")
	after := identityLine("after")
	long := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA " + strings.Repeat("x", 70*1024)

	user := &unix_util.User{Username: "longline", Dir: t.TempDir(), Uid: 1004}
	writeIdentities(t, user, before+"\n"+long+"\n"+after+"\n")

	identities, err := GetAuthorizedIdentities(user)
	if err != nil {
		t.Fatalf("the reader reported %v; this test records that it reports nothing, which is the finding", err)
	}
	if len(identities) != 1 {
		t.Fatalf("%d credentials, want exactly the one before the long line (the ceiling is 64 KiB and the line is 70 KiB)", len(identities))
	}

	// and the same file with the long line shortened: both keys come back, so what happened above
	// is the length and not the content
	writeIdentities(t, user, before+"\n"+"# "+strings.Repeat("x", 200)+"\n"+after+"\n")
	identities, err = GetAuthorizedIdentities(user)
	if err != nil || len(identities) != 2 {
		t.Fatalf("with a short line in the middle: %d identities, err %v", len(identities), err)
	}
}

// TestConformanceAnyoneWhoCanWriteTheFileIsYou records the absence of a check rather than a
// behaviour. OpenSSH refuses an authorized_keys file that is group- or world-writable, or not owned
// by the account, because the credentials in it are only as trustworthy as the write permission on
// it. sshoq opens the file and parses what is in it, and asks nothing about it: a mode of 0666 is
// read as a identities file like any other, and so is a file owned by another account. This test
// asserts that today's behaviour is *permissive on purpose of the code, not by accident of a
// permission system*, so that when a check is added this test is the thing that fails and points at
// the decision (finding F17: whose call it is -- a policy switch, not a silent patch).
func TestConformanceAnyoneWhoCanWriteTheFileIsYou(t *testing.T) {
	user := &unix_util.User{Username: "loose", Dir: t.TempDir(), Uid: 1005}
	line := identityLine("loose")
	writeIdentities(t, user, line+"\n")
	full := filepath.Join(user.Dir, ".ssh3", "authorized_identities")
	if err := os.Chmod(full, 0o666); err != nil {
		t.Fatal(err)
	}

	identities, err := GetAuthorizedIdentities(user)
	if err != nil || len(identities) != 1 {
		t.Fatalf("a world-writable identities file: %d identities, err %v", len(identities), err)
	}
	if info, err := os.Stat(full); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm()&0o022 == 0 {
		t.Fatal("the file is not world-writable, so this test proves nothing about StrictModes")
	}

	// and the same for the directory holding it: the server does not ask either
	if err := os.Chmod(filepath.Dir(full), 0o777); err != nil {
		t.Fatal(err)
	}
	if identities, err = GetAuthorizedIdentities(user); err != nil || len(identities) != 1 {
		t.Fatalf("a world-writable ~/.ssh3: %d identities, err %v", len(identities), err)
	}
}

// TestConformanceBothFilesAreReadAndNeitherShadowsTheOther covers the ordering claim implicit in
// GetAuthorizedIdentities: a user with both the sshoq file and an OpenSSH-format file gets the
// credentials of both, so a key kept in ~/.ssh/authorized_keys for sshd also logs in over ssh3.
func TestConformanceBothFilesAreReadAndNeitherShadowsTheOther(t *testing.T) {
	user := &unix_util.User{Username: "both", Dir: t.TempDir(), Uid: 1006}
	home := user.Dir
	if err := os.MkdirAll(filepath.Join(home, ".ssh3"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path.Join(home, ".ssh3", "authorized_identities"), []byte(identityLine("a")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path.Join(home, ".ssh", "authorized_keys"), []byte(identityLine("b")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	identities, err := GetAuthorizedIdentities(user)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 2 {
		t.Errorf("%d credentials from two files, want 2", len(identities))
	}
}

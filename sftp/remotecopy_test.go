package sftp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- host-to-host copy tests ---
//
// The tests below run the copy against two sftp servers living in the test
// process, each rooted at its own directory and serving it as the home of its
// own user. This is the same ServeChannel code a real server runs, so what is
// verified here is the copy itself: which path is read on the source host, what
// is created on the destination host, and what goes through the wire in between.

// remoteCopyHosts wires a client channel to each of two in-process sftp servers,
// the first one rooted at srcDir and the second at dstDir. The returned function
// stops both servers.
func remoteCopyHosts(t *testing.T, srcDir, dstDir string) (src *pipeChannel, dst *pipeChannel, stop func()) {
	t.Helper()
	src, srcServer := newPipePair()
	dst, dstServer := newPipePair()
	stopSrc := servePipe(t, srcServer, srcDir)
	stopDst := servePipe(t, dstServer, dstDir)
	return src, dst, func() {
		stopSrc()
		stopDst()
	}
}

// writeTree creates files (with their content) and directories under root: a
// path ending in "/" creates a directory, anything else a file.
func writeTree(t *testing.T, root string, entries map[string]string) {
	t.Helper()
	for p, content := range entries {
		full := filepath.Join(root, p)
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", full, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

// TestRemoteCopyFile copies one file from one host to the other: the content
// lands in the destination host's filesystem and the source is left alone.
func TestRemoteCopyFile(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"hello.txt": "the quick brown fox"})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "hello.txt"), filepath.Join(dstDir, "copied.txt"))
	if err != nil {
		t.Fatalf("remote copy error: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dstDir, "copied.txt"))
	if err != nil {
		t.Fatalf("read the copied file: %v", err)
	}
	if string(got) != "the quick brown fox" {
		t.Errorf("unexpected content on the destination host: %q", got)
	}
	if _, err := os.Stat(filepath.Join(srcDir, "hello.txt")); err != nil {
		t.Errorf("the source file should be left alone: %v", err)
	}
}

// TestRemoteCopyRelativePaths checks that a path without a leading "/" is read
// and written relative to the home directory of the user on its own host, as it
// is on every other sftp request of the client.
func TestRemoteCopyRelativePaths(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"inbox/note.txt": "relative"})
	writeTree(t, dstDir, map[string]string{"outbox/": ""})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, false, "inbox/note.txt", "outbox"); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, "outbox", "note.txt"))
	if err != nil {
		t.Fatalf("read the copied file: %v", err)
	}
	if string(got) != "relative" {
		t.Errorf("unexpected content: %q", got)
	}
}

// TestRemoteCopyTildeHome checks that the destination "~" is resolved by the
// destination server into the home of the user authenticated on it, and that
// the copied file therefore lands inside that home directory.
func TestRemoteCopyTildeHome(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"report.csv": "a,b,c"})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "report.csv"), "~"); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, "report.csv"))
	if err != nil {
		t.Fatalf("the file should have landed in the destination home directory: %v", err)
	}
	if string(got) != "a,b,c" {
		t.Errorf("unexpected content: %q", got)
	}
}

// TestRemoteCopyEmptyFile checks that an empty source still exists on the
// destination host: writing no data at all would leave nothing behind.
func TestRemoteCopyEmptyFile(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"empty": ""})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "empty"), "empty.copy"); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	info, err := os.Stat(filepath.Join(dstDir, "empty.copy"))
	if err != nil {
		t.Fatalf("the empty file should exist on the destination host: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected an empty file, got %d bytes", info.Size())
	}
}

// TestRemoteCopyLargeFile transfers several chunks so the two pipelined windows
// (reads on the source, writes on the destination) wrap around: a chunk written
// at the wrong offset corrupts the file, which the content check catches.
func TestRemoteCopyLargeFile(t *testing.T) {
	const size = 3*ChunkSize + ChunkSize/2
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i * 7)
	}
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"big.bin": string(content)})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "big.bin"), "big.copy"); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, "big.copy"))
	if err != nil {
		t.Fatalf("read the copied file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch: got %d bytes, want %d", len(got), len(content))
		for i := 0; i < len(got) && i < len(content); i++ {
			if got[i] != content[i] {
				t.Fatalf("first difference at byte %d: got %d, want %d", i, got[i], content[i])
			}
		}
	}
}

// TestRemoteCopyDirectoryWithoutRecursive checks that a directory is refused
// unless -r was given, and that nothing is created on the destination host.
func TestRemoteCopyDirectoryWithoutRecursive(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"tree/a.txt": "a"})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "tree"), filepath.Join(dstDir, "tree"))
	if err == nil {
		t.Fatal("expected a directory copy to be refused without -r")
	}
	if !strings.Contains(err.Error(), "-r") {
		t.Errorf("expected the error to mention -r, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "tree")); !os.IsNotExist(err) {
		t.Errorf("nothing should have been created on the destination host, got %v", err)
	}
}

// TestRemoteCopyRecursive walks a whole directory tree, recreating the
// directories on the destination host and copying every file into them.
func TestRemoteCopyRecursive(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{
		"tree/":            "",
		"tree/top.txt":     "top",
		"tree/sub/mid.txt": "mid",
		"tree/sub/deep/x":  "",
		"tree/other.yml":   "key: value",
	})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, true, filepath.Join(srcDir, "tree"), filepath.Join(dstDir, "tree")); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	want := map[string]string{
		"tree/top.txt":     "top",
		"tree/sub/mid.txt": "mid",
		"tree/sub/deep/x":  "",
		"tree/other.yml":   "key: value",
	}
	for p, content := range want {
		got, err := os.ReadFile(filepath.Join(dstDir, p))
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if string(got) != content {
			t.Errorf("%s: got %q, want %q", p, got, content)
		}
	}
}

// TestRemoteCopyIntoExistingDirectory checks scp's rule that a destination
// naming an existing directory takes the source under its own basename, and
// that a destination ending with "/" does the same without having to exist.
func TestRemoteCopyIntoExistingDirectory(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"notes.md": "# notes"})
	writeTree(t, dstDir, map[string]string{"docs/": ""})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "notes.md"), filepath.Join(dstDir, "docs")); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "docs", "notes.md")); err != nil {
		t.Errorf("expected docs/notes.md on the destination host: %v", err)
	}

	// A trailing separator says the destination is a directory, so the basename
	// is appended to it: as with scp, the directory itself is not created, and
	// the copy fails when it is not there.
	err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "notes.md"), filepath.Join(dstDir, "fresh")+"/")
	if err == nil {
		t.Fatal("expected the copy to fail when the destination directory does not exist")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "fresh", "notes.md")); !os.IsNotExist(err) {
		t.Errorf("nothing should have been created for the missing directory, got %v", err)
	}
}

// TestRemoteCopyIntoMissingDirectoryWithRecursive checks that a recursive copy
// does create the directories it needs on the destination host, which an
// ordinary file copy of scp does not do.
func TestRemoteCopyIntoMissingDirectoryWithRecursive(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"tree/a.txt": "a"})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, true, filepath.Join(srcDir, "tree"), filepath.Join(dstDir, "fresh")+"/"); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, "fresh", "tree", "a.txt"))
	if err != nil {
		t.Fatalf("read the copied file: %v", err)
	}
	if string(got) != "a" {
		t.Errorf("unexpected content: %q", got)
	}
}

// TestRemoteCopyMissingSource checks that a source the source host cannot find
// is reported as an error and creates nothing on the destination host.
func TestRemoteCopyMissingSource(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "nope.txt"), filepath.Join(dstDir, "nope.copy"))
	if err == nil {
		t.Fatal("expected an error for a missing source file")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "nope.copy")); !os.IsNotExist(err) {
		t.Errorf("nothing should have been created on the destination host, got %v", err)
	}
}

// TestRemoteCopySourceIsDirectoryOnDestination checks the case where the
// destination exists and is a directory but the source is a file: the file is
// copied into it, never written over the directory.
func TestRemoteCopyOverExistingFile(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"data": "new content"})
	writeTree(t, dstDir, map[string]string{"data": "old"})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "data"), filepath.Join(dstDir, "data")); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, "data"))
	if err != nil {
		t.Fatalf("read the destination file: %v", err)
	}
	if string(got) != "new content" {
		t.Errorf("expected the destination file to be replaced, got %q", got)
	}
}

// TestRemoteCopySymlinkToTargetContent copies a symbolic link by its target's
// content, since the link's own path only exists on the source host: what is
// read must be the target, and what is written an ordinary file.
func TestRemoteCopySymlinkToTargetContent(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"real.txt": "the real thing"})
	if err := os.Symlink("real.txt", filepath.Join(srcDir, "link.txt")); err != nil {
		t.Skipf("cannot create a symbolic link: %v", err)
	}
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, false, filepath.Join(srcDir, "link.txt"), filepath.Join(dstDir, "link.copy")); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, "link.copy"))
	if err != nil {
		t.Fatalf("read the copied file: %v", err)
	}
	if string(got) != "the real thing" {
		t.Errorf("unexpected content: %q", got)
	}
	// the copy asks the source host for the resolved target, not for the link
	if !containsPath(requestPaths(src.Writes()), "get:"+filepath.Join(srcDir, "real.txt")) {
		t.Errorf("expected the resolved target to be read, requests: %v", requestPaths(src.Writes()))
	}
}

// TestRemoteCopyRecursiveFollowsFileSymlinks copies a link inside a tree under
// the link's own name, with the content of its target.
func TestRemoteCopyRecursiveFollowsFileSymlinks(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"tree/target.txt": "linked content"})
	if err := os.Symlink("target.txt", filepath.Join(srcDir, "tree", "link.txt")); err != nil {
		t.Skipf("cannot create a symbolic link: %v", err)
	}
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, true, filepath.Join(srcDir, "tree"), filepath.Join(dstDir, "tree")); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, "tree", "link.txt"))
	if err != nil {
		t.Fatalf("the link should have been copied under its own name: %v", err)
	}
	if string(got) != "linked content" {
		t.Errorf("unexpected content: %q", got)
	}
}

// TestRemoteCopyRecursiveDoesNotFollowDirectorySymlinks verifies that a link
// pointing back up the tree does not make the walk never end: such a link is
// reported and skipped, while the rest of the tree is copied.
func TestRemoteCopyRecursiveDoesNotFollowDirectorySymlinks(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"tree/a.txt": "a", "tree/sub/b.txt": "b"})
	if err := os.Symlink("..", filepath.Join(srcDir, "tree", "parent")); err != nil {
		t.Skipf("cannot create a symbolic link: %v", err)
	}
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, true, filepath.Join(srcDir, "tree"), filepath.Join(dstDir, "tree")); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}
	for _, p := range []string{"tree/a.txt", "tree/sub/b.txt"} {
		if _, err := os.Stat(filepath.Join(dstDir, p)); err != nil {
			t.Errorf("%s should have been copied: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dstDir, "tree", "parent")); !os.IsNotExist(err) {
		t.Errorf("the link to a directory should not have been followed, got %v", err)
	}
}

// TestRemoteCopyUsesTwoChannels checks that the copy really goes through both
// hosts: the source host only ever sees read requests, the destination host
// only ever sees the writes that create the file.
func TestRemoteCopyUsesTwoChannels(t *testing.T) {
	srcDir, dstDir := t.TempDir(), t.TempDir()
	writeTree(t, srcDir, map[string]string{"src.txt": "some bytes"})
	src, dst, stop := remoteCopyHosts(t, srcDir, dstDir)
	defer stop()

	if err := runRemoteCopy(src, dst, false, "src.txt", "dst.txt"); err != nil {
		t.Fatalf("remote copy error: %v", err)
	}

	// the paths are the ones the client sent, relative here, and each server
	// resolves them against the home of its own user
	srcPaths, dstPaths := requestPaths(src.Writes()), requestPaths(dst.Writes())
	if !containsPath(srcPaths, "get:src.txt") {
		t.Errorf("expected the source host to be read, requests: %v", srcPaths)
	}
	if !containsPath(dstPaths, "put:dst.txt") {
		t.Errorf("expected the destination host to be written, requests: %v", dstPaths)
	}
	// neither host is asked to touch the other one's filesystem
	for _, p := range srcPaths {
		if strings.HasPrefix(p, "put:") || strings.HasPrefix(p, "mkdir:") {
			t.Errorf("the source host should not be written to, request: %s", p)
		}
	}
	for _, p := range dstPaths {
		if strings.HasPrefix(p, "get:") {
			t.Errorf("the destination host should not be read, request: %s", p)
		}
	}
}

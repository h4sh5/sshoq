package util

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenSecretFileCreatesPrivateToOwner(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "sshoq.log")
	file, err := OpenSecretAppendFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("a username, a peer address\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// the umask of the process must not decide who can read the log: 0666&^umask used to
	// make it world-readable whenever the umask was permissive
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("a secret-bearing file was created with mode %o", perm)
	}
}

func TestOpenSecretFileTightensAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keylog")
	// a file written by a previous version of the software, or by another program
	if err := os.WriteFile(path, []byte("master secrets\n"), 0644); err != nil {
		t.Fatal(err)
	}

	file, err := CreateSecretFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("an exposed secret file should have been tightened, it is still %o", perm)
	}
}

func TestOpenSecretFileAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshoq.log")
	for _, line := range []string{"first\n", "second\n"} {
		file, err := OpenSecretAppendFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString(line); err != nil {
			t.Fatal(err)
		}
		file.Close()
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "first\nsecond\n" {
		t.Fatalf("a log file must be appended to, got %q", content)
	}
}

func TestOpenSecretFileCreatesItsDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "sshoq.log")
	file, err := OpenSecretAppendFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()

	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		t.Fatalf("a directory holding secrets must not be readable by others, it is %o", perm)
	}
}

func TestOpenSecretFileDoesNotTouchOtherFileTypes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/dev/null does not exist on Windows")
	}
	// /dev/null is a legitimate target for a log file and is world-writable on purpose:
	// tightening it because its mode looks too open would break the system for everybody
	// else, and it holds nothing to protect anyway
	before, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	file, err := OpenSecretAppendFile(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	after, err := os.Stat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Fatalf("%s permissions were changed from %s to %s", os.DevNull, before.Mode(), after.Mode())
	}
}

package ssh3

import (
	"os"
	"path"
	"testing"
)

func TestNewDefaultPrivkeyFileAuthMethods_NoSSHDir(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	methods := NewDefaultPrivkeyFileAuthMethods()
	if len(methods) != 0 {
		t.Fatalf("expected no default auth methods when ~/.ssh does not exist, got %d", len(methods))
	}
}

func TestNewDefaultPrivkeyFileAuthMethods_EmptySSHDir(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	if err := os.MkdirAll(path.Join(tmpDir, ".ssh"), 0700); err != nil {
		t.Fatalf("could not create ~/.ssh: %s", err)
	}

	methods := NewDefaultPrivkeyFileAuthMethods()
	if len(methods) != 0 {
		t.Fatalf("expected no default auth methods when ~/.ssh is empty, got %d", len(methods))
	}
}

func TestNewDefaultPrivkeyFileAuthMethods_ExistingKeys(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	sshDir := path.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("could not create ~/.ssh: %s", err)
	}
	for _, name := range []string{"id_rsa", "id_ed25519", "id_ecdsa"} {
		if err := os.WriteFile(path.Join(sshDir, name), []byte("test"), 0600); err != nil {
			t.Fatalf("could not write %s: %s", name, err)
		}
	}
	// a directory named like a default key must not be considered as a key
	if err := os.MkdirAll(path.Join(sshDir, "id_dsa"), 0700); err != nil {
		t.Fatalf("could not create id_dsa directory: %s", err)
	}

	methods := NewDefaultPrivkeyFileAuthMethods()
	if len(methods) != 3 {
		t.Fatalf("expected 3 default auth methods, got %d", len(methods))
	}
	// order must follow the OpenSSH default order
	expected := []string{
		path.Join(sshDir, "id_ecdsa"),
		path.Join(sshDir, "id_ed25519"),
		path.Join(sshDir, "id_rsa"),
	}
	for i, method := range methods {
		if method.Filename() != expected[i] {
			t.Errorf("method %d: expected %s, got %s", i, expected[i], method.Filename())
		}
	}
}

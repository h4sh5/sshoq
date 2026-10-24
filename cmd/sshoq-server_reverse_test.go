package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseReverseTunnelSpec_Defaults(t *testing.T) {
	cfg, err := parseReverseTunnelSpec("user@example.com:4443/sshoq-remote%4444", "[::]:443")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !strings.Contains(cfg.url, "example.com:4443") || !strings.Contains(cfg.url, "/sshoq-remote") {
		t.Errorf("bad remote url %s", cfg.url)
	}
	if cfg.remoteBind.Port != 4444 || !cfg.remoteBind.IP.IsLoopback() {
		t.Errorf("expected the remote to bind its localhost:4444, got %s", cfg.remoteBind)
	}
	// the local destination defaults to the server's own -bind port
	if cfg.localDest.Port != 443 || !cfg.localDest.IP.IsLoopback() {
		t.Errorf("expected the local destination to be 127.0.0.1:443, got %s", cfg.localDest)
	}
}

func TestParseReverseTunnelSpec_ExplicitLocalDestination(t *testing.T) {
	cfg, err := parseReverseTunnelSpec("user@example.com/sshoq-remote%4444@127.0.0.2@8443", "0.0.0.0:443")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if cfg.remoteBind.Port != 4444 {
		t.Errorf("bad remote bind port: %s", cfg.remoteBind)
	}
	if cfg.localDest.String() != "127.0.0.2:8443" {
		t.Errorf("bad local destination: %s", cfg.localDest)
	}
}

func TestParseReverseTunnelSpec_Errors(t *testing.T) {
	for _, spec := range []string{
		"example.com:4443/sshoq-remote",   // no % separator
		"%4444",                           // no URL
		"example.com:4443%4444",           // no URL path
		"example.com:4443/srv%4444",       // no username in the URL
		"u@example.com:4443/srv%0",        // port out of range
		"u@example.com:4443/srv%abc",      // not a number
		"u@example.com:4443/srv%4444@1.2.3.4", // incomplete local destination
	} {
		if _, err := parseReverseTunnelSpec(spec, "0.0.0.0:443"); err == nil {
			t.Errorf("expected an error for %q, got nil", spec)
		}
	}
}

func TestParseRemotePublicKey_InlineAndFile(t *testing.T) {
	// inline keys, one per algorithm family supported by ssh.ParseAuthorizedKey
	inline := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC62komtsOzLL7TiE9TDpN3CdUubXVY6RDTY/vy/EPmV a comment"
	normalized, err := parseRemotePublicKey(inline)
	if err != nil {
		t.Fatalf("inline ed25519 key rejected: %s", err)
	}
	if normalized != inline {
		t.Errorf("ed25519 key was mangled: %q", normalized)
	}

	// every algorithm family must be accepted: generate a real RSA and a real
	// ECDSA public key and hand them over inline
	for _, gen := range []func() (string, error){generateRSAKeyLine, generateECDSAKeyLine} {
		line, err := gen()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseRemotePublicKey(line); err != nil {
			t.Errorf("inline key rejected (%s): %s", line, err)
		}
	}

	dir := t.TempDir()
	pub := filepath.Join(dir, "id_test.pub")
	content := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC62komtsOzLL7TiE9TDpN3CdUubXVY6RDTY/vy/EPmV file comment\n"
	if err := os.WriteFile(pub, []byte("# comment\n"+content), 0600); err != nil {
		t.Fatal(err)
	}
	normalizedFile, err := parseRemotePublicKey(pub)
	if err != nil {
		t.Fatalf("public key file rejected: %s", err)
	}
	if normalizedFile != strings.TrimSpace(content) {
		t.Errorf("bad normalization of the file key: %q", normalizedFile)
	}

	// a filename which does not exist is an error, not a key
	if _, err := parseRemotePublicKey(filepath.Join(dir, "does_not_exist.pub")); err == nil {
		t.Error("expected an error for a missing file")
	}
	// garbage is an error
	if _, err := parseRemotePublicKey("not a key, not a file"); err == nil {
		t.Error("expected an error for garbage")
	}
}

func generateRSAKeyLine() (string, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	pub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

func generateECDSAKeyLine() (string, error) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	pub, err := ssh.NewPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

func TestCollectStaticAuthorizedIdentities(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "keys.pub")
	ed25519Line := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC62komtsOzLL7TiE9TDpN3CdUubXVY6RDTY/vy/EPmV alice@laptop"
	if err := os.WriteFile(file, []byte("# a comment\n"+ed25519Line+"\n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rsaLine, err := generateRSAKeyLine()
	if err != nil {
		t.Fatal(err)
	}

	// one inline key and one file, the file carrying a comment and empty lines
	lines, err := collectStaticAuthorizedIdentities([]string{rsaLine, file})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 identity lines, got %d: %v", len(lines), lines)
	}
	if lines[1] != ed25519Line {
		t.Errorf("bad normalization of the file key: %q", lines[1])
	}

	if _, err := collectStaticAuthorizedIdentities([]string{"garbage /not/a/file"}); err == nil {
		t.Error("expected an error for a bogus argument")
	}
	if _, err := collectStaticAuthorizedIdentities(nil); err != nil {
		t.Errorf("no arguments must not be an error: %s", err)
	}
}

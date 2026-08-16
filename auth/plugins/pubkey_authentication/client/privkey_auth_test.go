package client_pubkey_authentication

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/h4sh5/sshoq"
)

func TestPrepareRequestForAuth_NonExistentKey(t *testing.T) {
	authMethod := NewPrivkeyFileAuthMethod("/path/to/nonexistent/key_id_rsa")
	req := &http.Request{
		Header: make(http.Header),
		URL:    &url.URL{Path: "/ssh3"},
	}
	conv := &ssh3.Conversation{}

	err := authMethod.PrepareRequestForAuth(req, nil, nil, "testuser", conv)
	if err == nil {
		t.Fatalf("expected error for non-existent key file, got nil")
	}
}

func TestPrepareRequestForAuth_CorruptedKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "corrupted_key")
	if err := os.WriteFile(keyPath, []byte("invalid-corrupted-key-payload"), 0600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	authMethod := NewPrivkeyFileAuthMethod(keyPath)
	req := &http.Request{
		Header: make(http.Header),
		URL:    &url.URL{Path: "/ssh3"},
	}
	conv := &ssh3.Conversation{}

	err := authMethod.PrepareRequestForAuth(req, nil, nil, "testuser", conv)
	if err == nil {
		t.Fatalf("expected error for corrupted key file, got nil")
	}
}

func TestPrepareRequestForAuth_ValidKey(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  string([]byte{'P', 'R', 'I', 'V', 'A', 'T', 'E', ' ', 'K', 'E', 'Y'}),
		Bytes: pkcs8Bytes,
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "valid_key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("failed to write valid test key: %v", err)
	}

	authMethod := NewPrivkeyFileAuthMethod(keyPath)
	req := &http.Request{
		Header: make(http.Header),
		URL:    &url.URL{Path: "/ssh3"},
	}
	conv := &ssh3.Conversation{}

	err = authMethod.PrepareRequestForAuth(req, nil, nil, "testuser", conv)
	if err != nil {
		t.Fatalf("expected success for valid key, got error: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Fatalf("expected Authorization header to be set, got empty")
	}
}

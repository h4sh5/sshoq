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
	client_config "github.com/h4sh5/sshoq/client/config"
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

// Identity paths coming from the SSH config file must be expanded the way
// OpenSSH expands them ("~/...", "~user/..." and "$HOME/...").
func TestPrivkeyOptionParserExpandsIdentityPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	parser := &PrivkeyOptionParser{}
	option, err := parser.Parse([]string{
		"~/.ssh/id_example",
		"$HOME/.ssh/id_example2",
		`"~/.ssh/id_example3"`,
		"/etc/ssh/id_static",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{
		filepath.Join(home, ".ssh/id_example"),
		filepath.Join(home, ".ssh/id_example2"),
		filepath.Join(home, ".ssh/id_example3"),
		"/etc/ssh/id_static",
	}
	got := option.(*PrivkeyAuthOption).Filenames()
	if len(got) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("identity %d: expected %q, got %q", i, expected[i], got[i])
		}
	}
}

// The auth methods built by the plugin from the config-derived option must use
// expanded paths, otherwise the key files are never found.
func TestPrivkeyPluginFuncUsesExpandedPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}

	option, err := (&PrivkeyOptionParser{}).Parse([]string{"~/.ssh/id_example"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	clientConfig, err := client_config.NewConfig(
		"testuser", "example.com", 443, "/",
		nil,
		map[client_config.OptionName]client_config.Option{PRIVKEY_OPTION_NAME: option},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := &http.Request{Header: make(http.Header), URL: &url.URL{Path: "/"}}
	methods, err := privkeyPluginFunc(req, nil, clientConfig, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(methods))
	}
	authMethod, ok := methods[0].(*PrivkeyFileAuthMethod)
	if !ok {
		t.Fatalf("unexpected auth method type %T", methods[0])
	}
	if want := filepath.Join(home, ".ssh/id_example"); authMethod.Filename() != want {
		t.Errorf("expected filename %q, got %q", want, authMethod.Filename())
	}
}

// A "~" in an identity path must never reach the filesystem untouched.
func TestNewPrivkeyFileAuthMethodExpandsTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got, want := NewPrivkeyFileAuthMethod("~/.ssh/id_example").Filename(), filepath.Join(home, ".ssh/id_example"); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
	if got, want := NewPrivkeyFileAuthMethod("$HOME/.ssh/id_example").Filename(), filepath.Join(home, ".ssh/id_example"); got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

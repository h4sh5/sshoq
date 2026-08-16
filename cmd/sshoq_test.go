package cmd

import (
	"net/url"
	"os"
	"path"
	"testing"

	"github.com/h4sh5/sshoq"
	client_pubkey_authentication "github.com/h4sh5/sshoq/auth/plugins/pubkey_authentication/client"
	"github.com/h4sh5/sshoq/client/config"
	"github.com/kevinburke/ssh_config"
)

func testOptionParsers() map[config.OptionName]config.OptionParser {
	return map[config.OptionName]config.OptionParser{
		client_pubkey_authentication.PRIVKEY_OPTION_NAME: &client_pubkey_authentication.PrivkeyOptionParser{},
		client_pubkey_authentication.PUBKEY_OPTION_NAME:  &client_pubkey_authentication.PubkeyOptionParser{},
	}
}

// When no identity is configured anywhere, the default private keys from
// ~/.ssh must be used.
func TestGetConnectionMaterialFromURL_DefaultKeysFromDotSSH(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	sshDir := path.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path.Join(sshDir, "id_rsa"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	hostUrl, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, options, err := getConnectionMaterialFromURL(hostUrl, nil, nil, nil, testOptionParsers())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	methods := options.AuthMethods()
	if len(methods) != 1 {
		t.Fatalf("expected exactly 1 default auth method, got %d", len(methods))
	}
	privkeyMethod, ok := methods[0].(*ssh3.PrivkeyFileAuthMethod)
	if !ok {
		t.Fatalf("expected *ssh3.PrivkeyFileAuthMethod, got %T", methods[0])
	}
	expected := path.Join(sshDir, "id_rsa")
	if privkeyMethod.Filename() != expected {
		t.Errorf("expected %s, got %s", expected, privkeyMethod.Filename())
	}
}

// When no identity is configured and ~/.ssh contains no key, no auth method
// must be produced (the connection will fail later with a clean error).
func TestGetConnectionMaterialFromURL_NoDefaultKeys(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	hostUrl, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, options, err := getConnectionMaterialFromURL(hostUrl, nil, nil, nil, testOptionParsers())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(options.AuthMethods()) != 0 {
		t.Fatalf("expected no auth methods, got %d", len(options.AuthMethods()))
	}
}

// Unset plugin flags are gathered as nil values in cliOptions (see
// ClientMain): they must NOT be mistaken for an explicitly specified
// identity, otherwise default ~/.ssh keys would not be tried.
func TestGetConnectionMaterialFromURL_NilCLIOptionsDoNotSuppressDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	sshDir := path.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path.Join(sshDir, "id_ed25519"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	// simulate unset plugin flags: present in the map but with a nil value
	cliOptions := map[config.OptionName]config.Option{
		client_pubkey_authentication.PRIVKEY_OPTION_NAME: nil,
		client_pubkey_authentication.PUBKEY_OPTION_NAME:  nil,
	}

	hostUrl, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, options, err := getConnectionMaterialFromURL(hostUrl, nil, nil, cliOptions, testOptionParsers())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(options.AuthMethods()) != 1 {
		t.Fatalf("expected 1 default auth method, got %d", len(options.AuthMethods()))
	}
	if m, ok := options.AuthMethods()[0].(*ssh3.PrivkeyFileAuthMethod); !ok || m.Filename() != path.Join(sshDir, "id_ed25519") {
		t.Errorf("expected default key %s to be tried, got %v", path.Join(sshDir, "id_ed25519"), options.AuthMethods()[0])
	}
}

// When -i is provided on the command line, it must be the only
// identity-related auth material: default keys from ~/.ssh are not used,
// config IdentityFile entries are discarded and config-derived auth methods
// are dropped.
func TestGetConnectionMaterialFromURL_ICLIOptionIsOnlyMethod(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	sshDir := path.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path.Join(sshDir, "id_rsa"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	// the ssh config also references an IdentityFile
	configContent := "Host example.com\n  HostName example.com\n  Port 443\n  User testuser\n  IdentityFile /tmp/config_key\n"
	sshCfg, err := ssh_config.DecodeBytes([]byte(configContent))
	if err != nil {
		t.Fatal(err)
	}

	cliPrivkeyOption, err := (&client_pubkey_authentication.PrivkeyOptionParser{}).Parse([]string{"/tmp/cli_key"})
	if err != nil {
		t.Fatal(err)
	}
	cliOptions := map[config.OptionName]config.Option{
		client_pubkey_authentication.PRIVKEY_OPTION_NAME: cliPrivkeyOption,
	}

	hostUrl, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, options, err := getConnectionMaterialFromURL(hostUrl, sshCfg, nil, cliOptions, testOptionParsers())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// no legacy auth method (neither from the ssh config nor from ~/.ssh)
	// must survive when -i is used
	if len(options.AuthMethods()) != 0 {
		t.Errorf("expected no legacy auth methods when -i is used, got %d", len(options.AuthMethods()))
	}

	// the only IdentityFile-backed option that must remain is the CLI one
	for name := range options.Options() {
		switch name {
		case client_pubkey_authentication.PRIVKEY_OPTION_NAME:
			// ok: the CLI-provided identity file
		case client_pubkey_authentication.PUBKEY_OPTION_NAME:
			t.Errorf("config-derived PUBKEY option should have been removed when -i is used")
		default:
			t.Errorf("unexpected option %s", name)
		}
	}
}

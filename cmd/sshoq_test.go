package cmd

import (
	"net"
	"net/url"
	"os"
	"path"
	"strings"
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

// --- config-dir resolution tests ---

// When -config-dir is empty, the default ~/.ssh3 directory must be used.
func TestResolveConfigDirDefault(t *testing.T) {
	// homedir() prefers os/user.Current().HomeDir and ignores the HOME env
	// var when the current user can be resolved, so compute the expected value
	// from homedir() itself.
	expected := path.Join(homedir(), ".ssh3")
	got := resolveConfigDir("")
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

// When -config-dir is provided, it must be used as-is instead of the default.
func TestResolveConfigDirCustom(t *testing.T) {
	custom := path.Join(t.TempDir(), "my-custom-config")
	got := resolveConfigDir(custom)
	if got != custom {
		t.Errorf("expected %s, got %s", custom, got)
	}
}

// The custom config dir must be used even when HOME points elsewhere.
func TestResolveConfigDirCustomOverridesHome(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	custom := path.Join(t.TempDir(), "other")
	got := resolveConfigDir(custom)
	if got != custom {
		t.Errorf("expected %s, got %s", custom, got)
	}
	if got == path.Join(tmpDir, ".ssh3") {
		t.Errorf("custom config dir should not fall back to ~/.ssh3")
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

// --- scp argument parsing tests ---

func TestParseScpArgsUpload(t *testing.T) {
	upload, localPath, remotePath, urlParam, err := parseScpArgs([]string{"localfile", "user@remote:443/sshoq-server%/tmp/remotefile"})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !upload {
		t.Errorf("expected upload direction, got download")
	}
	if localPath != "localfile" {
		t.Errorf("expected localPath localfile, got %s", localPath)
	}
	if remotePath != "/tmp/remotefile" {
		t.Errorf("expected remotePath /tmp/remotefile, got %s", remotePath)
	}
	if urlParam != "user@remote:443/sshoq-server" {
		t.Errorf("expected urlParam user@remote:443/sshoq-server, got %s", urlParam)
	}
}

func TestParseScpArgsDownload(t *testing.T) {
	upload, localPath, remotePath, urlParam, err := parseScpArgs([]string{"user@remote:443/sshoq-server%.ssh/authorized_keys", "."})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if upload {
		t.Errorf("expected download direction, got upload")
	}
	if localPath != "." {
		t.Errorf("expected localPath ., got %s", localPath)
	}
	if remotePath != ".ssh/authorized_keys" {
		t.Errorf("expected remotePath .ssh/authorized_keys, got %s", remotePath)
	}
	if urlParam != "user@remote:443/sshoq-server" {
		t.Errorf("expected urlParam user@remote:443/sshoq-server, got %s", urlParam)
	}
}

func TestParseScpArgsRecursiveDownload(t *testing.T) {
	upload, localPath, remotePath, urlParam, err := parseScpArgs([]string{"user@remote:443/sshoq-server%/etc/nginx", "."})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if upload {
		t.Errorf("expected download direction, got upload")
	}
	if localPath != "." {
		t.Errorf("expected localPath ., got %s", localPath)
	}
	if remotePath != "/etc/nginx" {
		t.Errorf("expected remotePath /etc/nginx, got %s", remotePath)
	}
	if urlParam != "user@remote:443/sshoq-server" {
		t.Errorf("expected urlParam user@remote:443/sshoq-server, got %s", urlParam)
	}
}

func TestParseScpArgsWrongArgCount(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"onlyone"},
		{"a", "b", "c"},
	} {
		if _, _, _, _, err := parseScpArgs(args); err == nil {
			t.Errorf("expected error for args %v", args)
		}
	}
}

func TestParseScpArgsNoSeparator(t *testing.T) {
	if _, _, _, _, err := parseScpArgs([]string{"localfile", "user@remote:443/sshoq-server"}); err == nil {
		t.Error("expected error when no '%' separator is present")
	}
}

func TestParseScpArgsEmptyUrlPart(t *testing.T) {
	if _, _, _, _, err := parseScpArgs([]string{"localfile", "%/tmp/remotefile"}); err == nil {
		t.Error("expected error when the URL part is empty")
	}
}

func TestParseScpArgsEmptyRemotePath(t *testing.T) {
	if _, _, _, _, err := parseScpArgs([]string{"localfile", "user@remote:443/sshoq-server%"}); err == nil {
		t.Error("expected error when the remote path is empty")
	}
}

func TestParseScpArgsRemotePathContainsPercent(t *testing.T) {
	upload, localPath, remotePath, urlParam, err := parseScpArgs([]string{"localfile", "user@remote:443/sshoq-server%/tmp/100%25done"})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !upload {
		t.Errorf("expected upload direction")
	}
	if localPath != "localfile" {
		t.Errorf("expected localPath localfile, got %s", localPath)
	}
	if remotePath != "/tmp/100%25done" {
		t.Errorf("expected remotePath /tmp/100%%25done, got %s", remotePath)
	}
	if urlParam != "user@remote:443/sshoq-server" {
		t.Errorf("expected urlParam user@remote:443/sshoq-server, got %s", urlParam)
	}
}

func TestParseAddrPort(t *testing.T) {
	const syntaxError = "Use [bindip:]localport@remoteip@remoteport (bindip is optional), same as openssh but with @ instead of :"

	t.Run("valid 3-part syntax without bind IP", func(t *testing.T) {
		localIP, localPort, remoteIP, remotePort, err := parseAddrPort("8080@127.0.0.1@9090")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !localIP.Equal(net.ParseIP("127.0.0.1")) {
			t.Errorf("expected local IP 127.0.0.1, got %s", localIP)
		}
		if localPort != 8080 {
			t.Errorf("expected local port 8080, got %d", localPort)
		}
		if !remoteIP.Equal(net.ParseIP("127.0.0.1")) {
			t.Errorf("expected remote IP 127.0.0.1, got %s", remoteIP)
		}
		if remotePort != 9090 {
			t.Errorf("expected remote port 9090, got %d", remotePort)
		}
	})

	t.Run("valid 4-part syntax with bind IP", func(t *testing.T) {
		localIP, localPort, remoteIP, remotePort, err := parseAddrPort("0.0.0.0@8080@::1@9090")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !localIP.Equal(net.ParseIP("0.0.0.0")) {
			t.Errorf("expected local IP 0.0.0.0, got %s", localIP)
		}
		if localPort != 8080 {
			t.Errorf("expected local port 8080, got %d", localPort)
		}
		if !remoteIP.Equal(net.ParseIP("::1")) {
			t.Errorf("expected remote IP ::1, got %s", remoteIP)
		}
		if remotePort != 9090 {
			t.Errorf("expected remote port 9090, got %d", remotePort)
		}
	})

	t.Run("rejects too few parts with syntax error", func(t *testing.T) {
		_, _, _, _, err := parseAddrPort("8080@127.0.0.1")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), syntaxError) {
			t.Errorf("error message should mention the correct @ syntax, got: %s", err)
		}
	})

	t.Run("rejects too many parts with syntax error", func(t *testing.T) {
		_, _, _, _, err := parseAddrPort("0.0.0.0@8080@127.0.0.1@9090@extra")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), syntaxError) {
			t.Errorf("error message should mention the correct @ syntax, got: %s", err)
		}
	})

	t.Run("rejects invalid IP", func(t *testing.T) {
		_, _, _, _, err := parseAddrPort("8080@not-an-ip@9090")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("rejects invalid port", func(t *testing.T) {
		_, _, _, _, err := parseAddrPort("notaport@127.0.0.1@9090")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("rejects port too large", func(t *testing.T) {
		_, _, _, _, err := parseAddrPort("70000@127.0.0.1@9090")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})
}

package cmd

import (
	"flag"
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

// unsetEnvForTest ensures an environment variable is truly unset for the
// duration of the test (restoring the previous value afterwards). It must be
// used instead of t.Setenv(name, ""), which would *set* the variable to an
// empty value rather than unsetting it.
func unsetEnvForTest(t *testing.T, key string) {
	t.Helper()
	if prev, ok := os.LookupEnv(key); ok {
		t.Cleanup(func() { os.Setenv(key, prev) })
	}
	os.Unsetenv(key)
}

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

// SetEnv and SendEnv directives from the ssh config must end up in the
// client config, to be sent to the server before the session starts.
// Unset SendEnv variables must not appear, SetEnv duplicates are last-wins.
func TestGetConnectionMaterialFromURL_SetEnvSendEnv(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("SSH_AUTH_SOCK", "") // no ssh agent in tests
	t.Setenv("SSHOQ_TEST_CLI_SENDENV", "from-local-env")
	unsetEnvForTest(t, "SSHOQ_TEST_CLI_UNSET")

	configContent := "Host example.com\n" +
		"  HostName example.com\n" +
		"  Port 443\n" +
		"  User testuser\n" +
		"  URLPath /\n" +
		"  SetEnv FOO=bar\n" +
		"  SetEnv DUP=one\n" +
		"  SetEnv DUP=two\n" +
		"  SendEnv SSHOQ_TEST_CLI_SENDENV\n" +
		"  SendEnv SSHOQ_TEST_CLI_UNSET\n"
	sshCfg, err := ssh_config.DecodeBytes([]byte(configContent))
	if err != nil {
		t.Fatal(err)
	}

	hostUrl, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, options, err := getConnectionMaterialFromURL(hostUrl, sshCfg, nil, nil, testOptionParsers())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	got := options.EnvVars()
	expected := []string{
		"FOO=bar",
		"DUP=two", // the last SetEnv entry for a name wins
		"SSHOQ_TEST_CLI_SENDENV=from-local-env",
	}
	if len(got) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
	for i, kv := range expected {
		if got[i] != kv {
			t.Errorf("env var %d: expected %q, got %q", i, kv, got[i])
		}
	}
}

// With no SetEnv/SendEnv directives, no environment variable must be produced.
func TestGetConnectionMaterialFromURL_NoEnvDirectives(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("SSH_AUTH_SOCK", "")

	configContent := "Host example.com\n  HostName example.com\n  Port 443\n  User testuser\n  URLPath /\n"
	sshCfg, err := ssh_config.DecodeBytes([]byte(configContent))
	if err != nil {
		t.Fatal(err)
	}

	hostUrl, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, options, err := getConnectionMaterialFromURL(hostUrl, sshCfg, nil, nil, testOptionParsers())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if got := options.EnvVars(); len(got) != 0 {
		t.Errorf("expected no env vars, got %v", got)
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

func TestParseDynamicForwardingSpec(t *testing.T) {
	t.Run("accepts bare port", func(t *testing.T) {
		bindAddr, port, err := parseDynamicForwardingSpec("8080")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if bindAddr != "127.0.0.1" {
			t.Fatalf("expected default loopback bind address, got %q", bindAddr)
		}
		if port != 8080 {
			t.Fatalf("expected port 8080, got %d", port)
		}
	})

	t.Run("accepts explicit bind host and port", func(t *testing.T) {
		bindAddr, port, err := parseDynamicForwardingSpec("0.0.0.0:9000")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if bindAddr != "0.0.0.0" {
			t.Fatalf("expected bind address 0.0.0.0, got %q", bindAddr)
		}
		if port != 9000 {
			t.Fatalf("expected port 9000, got %d", port)
		}
	})

	t.Run("accepts ipv6 bind host with brackets", func(t *testing.T) {
		bindAddr, port, err := parseDynamicForwardingSpec("[::1]:8123")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if bindAddr != "::1" {
			t.Fatalf("expected bind address ::1, got %q", bindAddr)
		}
		if port != 8123 {
			t.Fatalf("expected port 8123, got %d", port)
		}
	})

	t.Run("rejects empty spec", func(t *testing.T) {
		if _, _, err := parseDynamicForwardingSpec(""); err == nil {
			t.Fatal("expected an error for an empty dynamic forwarding spec")
		}
	})

	t.Run("rejects invalid contents", func(t *testing.T) {
		if _, _, err := parseDynamicForwardingSpec("not-a-port"); err == nil {
			t.Fatal("expected an error for an invalid dynamic forwarding spec")
		}
	})

	t.Run("rejects ports out of range", func(t *testing.T) {
		if _, _, err := parseDynamicForwardingSpec("70000"); err == nil {
			t.Fatal("expected an error for an out-of-range port")
		}
	})
}

// A -D bind address must reach the listener as a numerical IP: a nil IP inside a
// net.TCPAddr means "any interface", so a host name which is not an address
// literal has to be resolved explicitly instead of silently binding everything.
func TestDynamicForwardAddr(t *testing.T) {
	t.Run("numerical IPv4 address is kept as-is", func(t *testing.T) {
		ip, err := dynamicForwardAddr("127.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("expected 127.0.0.1, got %v", ip)
		}
	})

	t.Run("numerical IPv6 address is kept as-is", func(t *testing.T) {
		ip, err := dynamicForwardAddr("::1")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if ip == nil || !ip.IsLoopback() {
			t.Fatalf("expected the IPv6 loopback address, got %v", ip)
		}
	})

	t.Run("host name is resolved", func(t *testing.T) {
		ip, err := dynamicForwardAddr("localhost")
		if err != nil {
			t.Skipf("no host name resolution in this environment: %s", err)
		}
		if ip == nil || !ip.IsLoopback() {
			t.Fatalf("expected a loopback address for localhost, got %v", ip)
		}
	})

	t.Run("unresolved host is an error", func(t *testing.T) {
		if _, err := dynamicForwardAddr("sshoq-does-not-exist.invalid"); err == nil {
			t.Fatal("expected an error for an address which cannot be resolved")
		}
	})
}

func TestDynamicForwardingAddrs(t *testing.T) {
	t.Run("several -D specs are all returned", func(t *testing.T) {
		addrs, err := dynamicForwardingAddrs([]string{"8080", "127.0.0.2:8081"})
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if len(addrs) != 2 {
			t.Fatalf("expected 2 dynamic forwardings, got %d", len(addrs))
		}
		if addrs[0].String() != "127.0.0.1:8080" {
			t.Fatalf("expected 127.0.0.1:8080, got %s", addrs[0])
		}
		if addrs[1].String() != "127.0.0.2:8081" {
			t.Fatalf("expected 127.0.0.2:8081, got %s", addrs[1])
		}
	})

	t.Run("comma separated specs are expanded", func(t *testing.T) {
		addrs, err := dynamicForwardingAddrs([]string{"8080,8081"})
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if len(addrs) != 2 {
			t.Fatalf("expected 2 dynamic forwardings, got %d", len(addrs))
		}
	})

	t.Run("the same socket requested twice is rejected", func(t *testing.T) {
		// both spellings bind 127.0.0.1:8080: the second bind would fail with
		// "bind: address already in use" and look like an external process holding
		// the port
		_, err := dynamicForwardingAddrs([]string{"8080", "127.0.0.1:8080"})
		if err == nil {
			t.Fatal("expected an error when the same socket is requested twice")
		}
		if !strings.Contains(err.Error(), "more than once") {
			t.Fatalf("expected a duplicate socket error, got %s", err)
		}
	})

	t.Run("an invalid spec is reported", func(t *testing.T) {
		if _, err := dynamicForwardingAddrs([]string{"8080", "not-a-port"}); err == nil {
			t.Fatal("expected an error for an invalid dynamic forwarding spec")
		}
	})
}

// IdentityFile entries of the SSH config that use the "~" or "$HOME"
// constructs must resolve against the real home directory, both for the
// plugin-based auth options and for the legacy auth methods.
func TestGetConnectionMaterialFromURL_IdentityFileTildeExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("SSH_AUTH_SOCK", "")
	sshDir := path.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}

	configContent := "Host example.com\n" +
		"  HostName example.com\n" +
		"  Port 443\n" +
		"  User testuser\n" +
		"  URLPath /\n" +
		"  IdentityFile ~/.ssh/id_example\n" +
		"  IdentityFile $HOME/.ssh/id_example2\n" +
		"  IdentityFile \"~/.ssh/id_example3\"\n"
	sshCfg, err := ssh_config.DecodeBytes([]byte(configContent))
	if err != nil {
		t.Fatal(err)
	}

	hostUrl, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, options, err := getConnectionMaterialFromURL(hostUrl, sshCfg, nil, nil, testOptionParsers())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	expected := []string{
		path.Join(sshDir, "id_example"),
		path.Join(sshDir, "id_example2"),
		path.Join(sshDir, "id_example3"),
	}

	opt, ok := options.Options()[client_pubkey_authentication.PRIVKEY_OPTION_NAME]
	if !ok {
		t.Fatalf("expected a %s option, got %v", client_pubkey_authentication.PRIVKEY_OPTION_NAME, options.Options())
	}
	got := opt.(*client_pubkey_authentication.PrivkeyAuthOption).Filenames()
	if len(got) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, got)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("identity %d: expected %q, got %q", i, expected[i], got[i])
		}
	}

	if len(options.AuthMethods()) != len(expected) {
		t.Fatalf("expected %d auth methods, got %d", len(expected), len(options.AuthMethods()))
	}
	for i, method := range options.AuthMethods() {
		authMethod, ok := method.(*ssh3.PrivkeyFileAuthMethod)
		if !ok {
			t.Fatalf("unexpected auth method type %T", method)
		}
		if authMethod.Filename() != expected[i] {
			t.Errorf("auth method %d: expected %q, got %q", i, expected[i], authMethod.Filename())
		}
	}
}

// -i on the command line must support the "~" construct too (e.g. when it is
// quoted so the shell does not expand it).
func TestGetConnectionMaterialFromURL_CLIIdentityFileTilde(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("SSH_AUTH_SOCK", "")

	cliPrivkeyOption, err := (&client_pubkey_authentication.PrivkeyOptionParser{}).Parse([]string{"~/.ssh/id_cli"})
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
	_, options, err := getConnectionMaterialFromURL(hostUrl, nil, nil, cliOptions, testOptionParsers())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	want := path.Join(tmpDir, ".ssh/id_cli")
	got := options.Options()[client_pubkey_authentication.PRIVKEY_OPTION_NAME].(*client_pubkey_authentication.PrivkeyAuthOption).Filenames()
	if len(got) != 1 || got[0] != want {
		t.Errorf("expected %q, got %v", want, got)
	}
}

// --- SSH agent forwarding CLI flags ---

// parseAgentForwardingFlag registers the agent forwarding flags on a private
// flag set and parses args with them, returning the resulting value and the
// remaining positional arguments.
func parseAgentForwardingFlag(t *testing.T, args ...string) (forward bool, rest []string) {
	t.Helper()
	fs := flag.NewFlagSet("sshoq-agent-flag-test", flag.ContinueOnError)
	forwardSSHAgent := registerAgentForwardingFlag(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("could not parse %v: %s", args, err)
	}
	return *forwardSSHAgent, fs.Args()
}

// OpenSSH uses -A to enable agent forwarding: the flag must be accepted and must
// enable forwarding even though the long -forward-agent spelling exists too.
func TestAgentForwardingFlagShortAlias(t *testing.T) {
	forward, rest := parseAgentForwardingFlag(t, "-A", "user@example.org:443/sshoq-server")
	if !forward {
		t.Fatal("expected -A to enable agent forwarding")
	}
	// -A is a switch, not a flag with a value: the remote host must stay a
	// positional argument, otherwise "sshoq -A host" would lose its host.
	if len(rest) != 1 || rest[0] != "user@example.org:443/sshoq-server" {
		t.Fatalf("expected the remote host to remain a positional argument, got %v", rest)
	}
}

// The pre-existing long spelling keeps working and both spellings must drive the
// same value: mixing them cannot silently turn forwarding back off.
func TestAgentForwardingFlagLongForm(t *testing.T) {
	forward, _ := parseAgentForwardingFlag(t, "-forward-agent")
	if !forward {
		t.Fatal("expected -forward-agent to enable agent forwarding")
	}
	forward, _ = parseAgentForwardingFlag(t, "-A", "-forward-agent")
	if !forward {
		t.Fatal("expected -forward-agent combined with -A to enable agent forwarding")
	}
}

// Without either flag, agent forwarding must stay off: it is opt-in, like in
// OpenSSH.
func TestAgentForwardingFlagDisabledByDefault(t *testing.T) {
	forward, rest := parseAgentForwardingFlag(t, "user@example.org")
	if forward {
		t.Fatal("agent forwarding must be off unless -A or -forward-agent is given")
	}
	if len(rest) != 1 {
		t.Fatalf("expected the remote host to be the only positional argument, got %v", rest)
	}
}

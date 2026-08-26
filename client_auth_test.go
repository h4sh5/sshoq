package ssh3

import (
	"os"
	"path"
	"testing"

	"github.com/kevinburke/ssh_config"
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
	// order must follow the default key order
	expected := []string{
		path.Join(sshDir, "id_ed25519"),
		path.Join(sshDir, "id_rsa"),
		path.Join(sshDir, "id_ecdsa"),
	}
	for i, method := range methods {
		if method.Filename() != expected[i] {
			t.Errorf("method %d: expected %s, got %s", i, expected[i], method.Filename())
		}
	}
}

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

func testSSHConfig(t *testing.T, content string) *ssh_config.Config {
	t.Helper()
	cfg, err := ssh_config.DecodeBytes([]byte(content))
	if err != nil {
		t.Fatalf("could not decode test ssh config: %s", err)
	}
	return cfg
}

// Without a config file, no environment variable must be produced.
func TestGetConfigForHost_NoConfigNoEnv(t *testing.T) {
	_, _, _, _, _, _, envVars, err := GetConfigForHost("example.com", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(envVars) != 0 {
		t.Errorf("expected no env vars with a nil config, got %v", envVars)
	}
}

// SetEnv entries must be returned as "NAME=VALUE" pairs, in config order,
// keeping everything after the first '=' as the value (like OpenSSH).
func TestGetConfigForHost_SetEnv(t *testing.T) {
	cfg := testSSHConfig(t, "Host example.com\n  HostName example.com\n  User test\n  URLPath /\n  SetEnv foo=bar\n  SetEnv GREETING=hello world\n  SetEnv EQUALS=a=b=c\n")

	_, _, _, _, _, _, envVars, err := GetConfigForHost("example.com", cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	expected := []string{"foo=bar", "GREETING=hello world", "EQUALS=a=b=c"}
	if len(envVars) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, envVars)
	}
	for i, kv := range expected {
		if envVars[i] != kv {
			t.Errorf("env var %d: expected %q, got %q", i, kv, envVars[i])
		}
	}
}

// A SetEnv entry with the same name given twice must be last-wins.
func TestGetConfigForHost_SetEnvDuplicatesLastWins(t *testing.T) {
	cfg := testSSHConfig(t, "Host example.com\n  HostName example.com\n  User test\n  URLPath /\n  SetEnv foo=first\n  SetEnv foo=second\n")

	_, _, _, _, _, _, envVars, err := GetConfigForHost("example.com", cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(envVars) != 1 || envVars[0] != "foo=second" {
		t.Errorf("expected [foo=second], got %v", envVars)
	}
}

// A malformed SetEnv entry (no '=') must be silently ignored, like OpenSSH.
func TestGetConfigForHost_SetEnvMalformedSkipped(t *testing.T) {
	cfg := testSSHConfig(t, "Host example.com\n  HostName example.com\n  User test\n  URLPath /\n  SetEnv nocomma\n  SetEnv valid=yes\n")

	_, _, _, _, _, _, envVars, err := GetConfigForHost("example.com", cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(envVars) != 1 || envVars[0] != "valid=yes" {
		t.Errorf("expected [valid=yes], got %v", envVars)
	}
}

// SendEnv variables must be resolved from the local environment. Unset
// variables must not be sent (OpenSSH behaviour); set ones (even with an
// empty value) must be sent with their value.
func TestGetConfigForHost_SendEnv(t *testing.T) {
	t.Setenv("SSHOQ_TEST_SENDENV_SET", "sent-value")
	// os.Setenv is needed to test the "set but empty" case: t.Setenv(name, "")
	// would *set* an empty value too, but the previous value must be unset
	// first so that the test does not depend on the host environment.
	unsetEnvForTest(t, "SSHOQ_TEST_SENDENV_EMPTY")
	if err := os.Setenv("SSHOQ_TEST_SENDENV_EMPTY", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Unsetenv("SSHOQ_TEST_SENDENV_EMPTY") })
	unsetEnvForTest(t, "SSHOQ_TEST_SENDENV_UNSET")

	cfg := testSSHConfig(t, "Host example.com\n  HostName example.com\n  User test\n  URLPath /\n  SendEnv SSHOQ_TEST_SENDENV_SET\n  SendEnv SSHOQ_TEST_SENDENV_UNSET\n  SendEnv SSHOQ_TEST_SENDENV_EMPTY\n  SetEnv STATIC=fixed\n")

	_, _, _, _, _, _, envVars, err := GetConfigForHost("example.com", cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// SetEnv entries come first, then the set SendEnv entries, in config order
	expected := []string{
		"STATIC=fixed",
		"SSHOQ_TEST_SENDENV_SET=sent-value",
		"SSHOQ_TEST_SENDENV_EMPTY=",
	}
	if len(envVars) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, envVars)
	}
	for i, kv := range expected {
		if envVars[i] != kv {
			t.Errorf("env var %d: expected %q, got %q", i, kv, envVars[i])
		}
	}
}

// Options of other hosts must not leak into this host's environment.
func TestGetConfigForHost_EnvScopedToHost(t *testing.T) {
	cfg := testSSHConfig(t, "Host other-host\n  HostName other.example.com\n  SetEnv FOO=should-not-appear\nHost example.com\n  HostName example.com\n")

	_, _, _, _, _, _, envVars, err := GetConfigForHost("example.com", cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(envVars) != 0 {
		t.Errorf("expected no env vars for example.com, got %v", envVars)
	}
}

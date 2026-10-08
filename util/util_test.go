package util

import (
	"os"
	osuser "os/user"
	"path"
	"testing"
)

// unsetEnvForTest ensures an environment variable is truly unset for the
// duration of the test (restoring the previous value afterwards).
func unsetEnvForTest(t *testing.T, key string) {
	t.Helper()
	if prev, ok := os.LookupEnv(key); ok {
		t.Cleanup(func() { os.Setenv(key, prev) })
	}
	os.Unsetenv(key)
}

func TestExpandPathTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cases := map[string]string{
		"~/.ssh/id_example":           path.Join(home, ".ssh/id_example"),
		"$HOME/.ssh/id_example":       path.Join(home, ".ssh/id_example"),
		"${HOME}/.ssh/id_example":     path.Join(home, ".ssh/id_example"),
		`"~/.ssh/id_example"`:         path.Join(home, ".ssh/id_example"),
		"'~/.ssh/id_example'":         path.Join(home, ".ssh/id_example"),
		" ~/./.ssh/id_example ":       path.Join(home, ".ssh/id_example"),
		"~":                           home,
		"~/":                          home,
		"~/relative/file":             path.Join(home, "relative/file"),
		"/etc/ssh/ssh_host_rsa_key":   "/etc/ssh/ssh_host_rsa_key",
		"./relative_id":               "./relative_id",
		"":                            "",
		"~/.ssh/../id_rsa":            path.Join(home, "id_rsa"),
		"~/$SSHOQ_TEST_SUBDIR/id":     path.Join(home, "sub/id"),
		"$UNSET_VAR_FOR_TEST/id_rsa":  "${UNSET_VAR_FOR_TEST}/id_rsa",
		"~user_that_does_not_exist_x": "~user_that_does_not_exist_x",
	}

	t.Setenv("SSHOQ_TEST_SUBDIR", "sub")
	unsetEnvForTest(t, "UNSET_VAR_FOR_TEST")
	for input, expected := range cases {
		if got := ExpandPath(input); got != expected {
			t.Errorf("ExpandPath(%q) = %q, expected %q", input, got, expected)
		}
	}
}

// The "~user" construct must resolve to the home directory of the given user,
// like OpenSSH does.
func TestExpandPathTildeUser(t *testing.T) {
	current, err := osuser.Current()
	if err != nil {
		t.Skipf("could not determine the current user: %s", err)
	}
	// HOME must not be used for an explicit "~user" construct
	t.Setenv("HOME", t.TempDir())

	expected := path.Join(current.HomeDir, ".ssh/id_example")
	if got := ExpandPath("~" + current.Username + "/.ssh/id_example"); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
	if got := ExpandPath("~" + current.Username); got != current.HomeDir {
		t.Errorf("expected %q, got %q", current.HomeDir, got)
	}
}

// HomeDir must prefer HOME over the password database entry.
func TestHomeDirPrefersEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if got := HomeDir(); got != home {
		t.Errorf("expected %s, got %s", home, got)
	}
}

// With HOME unset, HomeDir must fall back on the password database.
func TestHomeDirFallbackOnPasswd(t *testing.T) {
	if prev, ok := os.LookupEnv("HOME"); ok {
		t.Cleanup(func() { os.Setenv("HOME", prev) })
	}
	os.Unsetenv("HOME")

	current, err := osuser.Current()
	if err != nil {
		t.Skipf("could not determine the current user: %s", err)
	}
	if got := HomeDir(); got != current.HomeDir {
		t.Errorf("expected %s, got %s", current.HomeDir, got)
	}
}

// The deprecated alias must behave like ExpandPath.
func TestExpandTildeWithHomeDirAlias(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	for _, input := range []string{"~/.ssh/id_example", "$HOME/.ssh/id_example", "/absolute/path"} {
		if ExpandTildeWithHomeDir(input) != ExpandPath(input) {
			t.Errorf("ExpandTildeWithHomeDir(%q) != ExpandPath(%q)", input, input)
		}
	}
}

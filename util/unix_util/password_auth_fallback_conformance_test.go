//go:build unix && (!linux || disable_password_auth)

package unix_util

// The other side of the build-tag pair. On a system where this package has no way to read a
// password hash -- any Unix that is not Linux, or Linux built with `-tags
// disable_password_auth` -- the question is what a password attempt does. It must not succeed, and
// it must not succeed *silently*: `cmd/sshoq-server.go` consults `PasswordAuthAvailable()` before
// it registers the password handler, and `userPasswordAuthentication` refuses with an error so that
// a caller which ignores the availability flag still cannot open a session.
//
// Nothing ran this file before `make proof-conformance` grew a second command line for it, which
// means the fallback build was compiled by nobody and asserted by nobody: a `return true` there, or
// a `(false, nil)` that a caller reads as "the account is closed" rather than "this build cannot
// authenticate", would have been invisible.

import "testing"

func TestConformanceFallbackBuildRefusesPasswordAuthentication(t *testing.T) {
	if PasswordAuthAvailable() {
		t.Fatal("the fallback build claims password authentication is available")
	}

	ok, err := UserPasswordAuthentication("root", "whatever")
	if ok {
		t.Error("the fallback build authenticated a password")
	}
	if err == nil {
		t.Fatal("the fallback build refused without saying why; a caller cannot tell an unusable account from an unavailable scheme")
	}

	// A user that does not exist is refused the same way; the fallback must not turn a lookup
	// problem into an accept either.
	if ok, _ := UserPasswordAuthentication("no-such-user-anywhere-42", ""); ok {
		t.Error("an unknown user authenticated in the fallback build")
	}
}

// TestConformanceFallbackBuildStillResolvesUsers is why the fallback exists at all: key-based
// logins need the uid, gid and home directory, and they do not need a password.
func TestConformanceFallbackBuildStillResolvesUsers(t *testing.T) {
	user, err := GetUser("root")
	if err != nil {
		t.Skipf("no root account readable here: %v", err)
	}
	if user.Uid != 0 {
		t.Errorf("root resolved to uid %d", user.Uid)
	}
	if user.Dir == "" {
		t.Error("root resolved with no home directory, so no authorized_identity file can be found")
	}
}

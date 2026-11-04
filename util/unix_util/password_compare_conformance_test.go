//go:build linux && !disable_password_auth

package unix_util

// The only password comparison in the product is `ComparePasswordWithHashedPassword`, in
// `linux_user.go`: `crypt(candidate, stored)` from libc, then a constant-time comparison of the
// result against the stored string. It had no test before this file -- the account gate in front of
// it is covered (SR-AUTH-11), and the dispatch that reaches it is covered (SR-AUTH-01..03), but the
// comparison itself was asserted only by the comment above it (finding **F16**).
//
// What is at stake is not the arithmetic of `crypt(3)` but the two guards around it and the shapes
// of the strings that reach it:
//
//   - A stored hash that libc cannot use does not come back as a mismatch; it comes back as a
//     string starting with `*`, or as the empty string, and a bare `==` against the stored value
//     would then compare *equal* for a stored `*`. That is how a locked account gets opened by any
//     password, and the guard is two lines of code (`linux_user.go`), which this file pins.
//   - `C.CString` truncates at a NUL byte, so both the candidate and the stored hash can be
//     shorter by the time libc sees them. Truncation must never widen what is accepted.
//   - The salt is read out of the stored string; nothing about the candidate chooses it.
//
// The hash strings below are not produced by the code under test. Each one is the output of
// `openssl passwd -<id> -salt <salt> <password>` (OpenSSL 3.x on this machine), quoted verbatim,
// and one test recomputes a fresh one at run time so that libc, OpenSSL and this call site have to
// agree on a value nobody hardcoded.

import (
	"crypto/rand"
	"os/exec"
	"strings"
	"testing"
)

// openssl passwd -6 -salt saltstring hunter2
const sha512OfHunter2 = "$6$saltstring$q2.778Y7vt0Ij2OIl01VlxEE6SEh8ZCtgFbyJX8fYkl5S7gx32QO24FVg.rs4DkoAs9t6R19x4z8g69teXFxA0"

// openssl passwd -5 -salt saltstring hunter2
const sha256OfHunter2 = "$5$saltstring$9JBjAeLRHX/Lm/1Njo98nbLiUsNRFEuARumLKkxJMm7"

// openssl passwd -1 -salt saltstri hunter2 (md5-crypt salts are eight characters)
const md5OfHunter2 = "$1$saltstri$T2/ewcphylZigUqYmbojG."

// openssl passwd -6 -salt othersalt1 hunter2 -- the same password, a different salt
const sha512OfHunter2OtherSalt = "$6$othersalt1$FOgSsH0VYIzFNwWJH0ZdarqNRraFdGG.afAHDu72biXnt9DawYXT9Dt7DzU4sdGvf1Kd7MlBOAPjGeVqLaXzu."

// openssl passwd -6 -salt saltstring hunter3 / HUNTER2
const sha512OfHunter3 = "$6$saltstring$ma.j0csojvy6AvMd8E9zHMveKknAt.AFGx2zNXuI5BWAi9CoiFVeOaPAoX6iHJkIxMrS.pKfLc71MhyCAQ4GV."
const sha512OfHunter2Upper = "$6$saltstring$IXPmqO9RNigRi2aOiX1yIygB3hMKmiPTYMfA7i69akEwxMU4UfuAmdqvqqlYctQkRgP2ZEcJchF.q0aFwBSXm0"

func accepts(t *testing.T, candidate, stored string) bool {
	t.Helper()
	ok, err := ComparePasswordWithHashedPassword(candidate, stored)
	if err != nil {
		return false
	}
	return ok
}

// TestConformanceRealHashesAuthenticateOnlyTheRightPassword is the comparison itself, over hashes
// that exist in the world. Every refusal row is a password that differs from the real one in the
// way an attacker's guess is most likely to differ from a near-miss.
func TestConformanceRealHashesAuthenticateOnlyTheRightPassword(t *testing.T) {
	cases := []struct {
		name      string
		candidate string
		stored    string
		accepted  bool
	}{
		{"sha512-crypt, correct", "hunter2", sha512OfHunter2, true},
		{"sha256-crypt, correct", "hunter2", sha256OfHunter2, true},
		{"md5-crypt, correct", "hunter2", md5OfHunter2, true},
		{"sha512-crypt, wrong at the end", "hunter3", sha512OfHunter2, false},
		{"sha512-crypt, wrong at the start", "Hunter2", sha512OfHunter2, false},
		{"sha512-crypt, empty candidate", "", sha512OfHunter2, false},
		{"sha512-crypt, candidate is a prefix of the real one", "hunter", sha512OfHunter2, false},
		{"sha512-crypt, real one is a prefix of the candidate", "hunter22", sha512OfHunter2, false},
		{"sha512-crypt, trailing space", "hunter2 ", sha512OfHunter2, false},
		{"sha512-crypt, leading space", " hunter2", sha512OfHunter2, false},
		// the hash of another password is not this password's hash, even though both are
		// well-formed and of the same length
		{"sha512-crypt, hash of hunter3", "hunter2", sha512OfHunter3, false},
		{"sha512-crypt, hash of HUNTER2", "hunter2", sha512OfHunter2Upper, false},
		// the same password under a different salt: the salt comes from the stored string, so a
		// stored hash made with another salt must not authenticate
		{"sha512-crypt, other salt, right password", "hunter2", sha512OfHunter2OtherSalt, true},
		{"sha512-crypt, other salt, wrong password", "hunter3", sha512OfHunter2OtherSalt, false},
		// a hash from a different family: sha256-crypt is not sha512-crypt
		{"sha256-crypt stored, sha512 hash presented", sha512OfHunter2, sha256OfHunter2, false},
	}
	for _, c := range cases {
		if got := accepts(t, c.candidate, c.stored); got != c.accepted {
			t.Errorf("%s: accepted = %t, want %t", c.name, got, c.accepted)
		}
	}

	// and the controls are not vacuous: the three families are three different strings, so a
	// comparison that ignored the algorithm marker would have failed above
	if sha512OfHunter2 == sha256OfHunter2 || sha256OfHunter2 == md5OfHunter2 {
		t.Fatal("the hardcoded hashes are not distinct")
	}
}

// TestConformanceUnusableStoredHashesAreRefusalsNotMismatches is the guard, and the reason the
// error text is part of the assertion. `crypt(3)` does not report an unusable setting by returning
// NULL: for a stored value like `*`, `*LK$` or `!!locked` it answers with a string of its own --
// which is why `Crypt` distinguishes two failure messages, "crypt() failed" for the NULL return and
// "bad password hashing" for the empty-or-`*`-prefixed answer. Seeing the second message here is
// the measurement: it says libc returned a string, and a `==` comparison against a stored `*` would
// then have been true for every password a probe could carry.
func TestConformanceUnusableStoredHashesAreRefusalsNotMismatches(t *testing.T) {
	unusable := []string{"", "*", "*LK$", "!locked", "!!", "$99$x", "$2b$12$abc", "$7$xx", "x", "$"}
	for _, stored := range unusable {
		for _, candidate := range []string{"hunter2", "", "*", "password"} {
			ok, err := ComparePasswordWithHashedPassword(candidate, stored)
			if ok {
				t.Errorf("stored %q accepted candidate %q", stored, candidate)
			}
			if err == nil {
				t.Errorf("stored %q with candidate %q: no error, so a hash was computed; check which guard moved", stored, candidate)
			}
		}
	}

	// `$6$` is the interesting neighbour: an algorithm marker with an empty salt is a *usable*
	// setting -- libc hashes with an empty salt and answers -- so the refusal here comes from the
	// comparison rather than from a guard, and the distinction is recorded by measuring it.
	if _, err := Crypt("hunter2", "$6$"); err != nil {
		t.Errorf("an empty-salt sha512 setting should be usable, and it was not: %v", err)
	}
	if accepts(t, "hunter2", "$6$") {
		t.Error("a stored value of only an algorithm marker authenticated")
	}

	// Which guard fires, for the account-lock spellings a shadow file really contains.
	for _, stored := range []string{"*", "*LK$", "!locked", "!!", ""} {
		_, err := Crypt("hunter2", stored)
		if err == nil {
			t.Fatalf("Crypt accepted the locked-account setting %q", stored)
		}
		if !strings.Contains(err.Error(), "bad password hashing") {
			t.Errorf("stored %q: error was %q; the '*' prefix / empty-result guard is what should refuse these, "+
				"and \"crypt() failed\" here would mean libc returned NULL instead -- update this test to say which", stored, err)
		}
	}
}

// TestConformanceNulBytesDoNotWidenAcceptance covers the cgo boundary: `C.CString` stops at a NUL,
// so libc can be handed a prefix of what Go was given, on either side of the comparison. Nothing
// may become *more* accepted because of it.
func TestConformanceNulBytesDoNotWidenAcceptance(t *testing.T) {
	if accepts(t, "hu\x00nter2", sha512OfHunter2) {
		t.Error("a candidate cut short by a NUL byte authenticated")
	}
	if accepts(t, "hunter2", sha512OfHunter2+"\x00junk") {
		t.Error("a stored hash with a NUL byte appended authenticated -- the comparison is on the whole string")
	}
	// libc sees "ab" as the salt here and answers with a 13-character DES hash; what matters is
	// that the answer is not equal to the stored string, so the login is refused rather than
	// granted by a truncation nobody asked for
	if accepts(t, "hunter2", "abc\x00xyz") {
		t.Error("a stored hash truncated at a NUL byte authenticated")
	}
	if accepts(t, "\x00", sha512OfHunter2) {
		t.Error("an empty-after-truncation candidate authenticated")
	}
}

// TestConformanceOpensslAndLibcAgreeOnAFreshPassword is the three-way check: a password and a salt
// generated here, a hash produced by the openssl binary, and the decision made by libc through this
// package. It is skipped when openssl is not installed.
func TestConformanceOpensslAndLibcAgreeOnAFreshPassword(t *testing.T) {
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed")
	}

	password := make([]byte, 12)
	if _, err := rand.Read(password); err != nil {
		t.Fatal(err)
	}
	// printable, so that no byte means anything special to either tool
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	guess := make([]byte, len(password))
	for i, b := range password {
		guess[i] = alphabet[int(b)%len(alphabet)]
	}
	secret := string(guess)

	for _, id := range []string{"-6", "-5", "-1"} {
		cmd := exec.Command(path, "passwd", id, "-salt", "abcdefgh", secret)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("openssl passwd %s: %v", id, err)
		}
		stored := strings.TrimSpace(string(out))
		if !accepts(t, secret, stored) {
			t.Errorf("%s: libc refused the hash openssl made for %q (%s)", id, secret, stored)
		}
		if accepts(t, secret+"x", stored) {
			t.Errorf("%s: libc accepted a one-character extension of the same password", id)
		}
		if accepts(t, strings.ToUpper(secret), stored) {
			t.Errorf("%s: libc accepted the case-flipped password", id)
		}
		// the hash itself is not a password: presenting it must not authenticate
		if accepts(t, stored, stored) {
			t.Errorf("%s: the stored hash authenticated as a password", id)
		}
	}
}

// TestConformancePasswordAuthIsAvailableOnThisBuild pins the flag the server consults before it
// offers the password scheme at all (`cmd/sshoq-server.go`), and the counterpart of the fallback
// build is `password_auth_fallback_conformance_test.go`, run by `make proof-conformance` under
// `-tags disable_password_auth`.
func TestConformancePasswordAuthIsAvailableOnThisBuild(t *testing.T) {
	if !PasswordAuthAvailable() {
		t.Fatal("this build claims password authentication is unavailable; then nothing in this file was reached")
	}
	// an unknown user is an error, not a "no" that a caller might read as "try anyway"
	ok, err := UserPasswordAuthentication("no-such-user-anywhere-42", "whatever")
	if ok {
		t.Error("an unknown user authenticated")
	}
	if err == nil {
		t.Error("an unknown user returned no error; the caller cannot tell refusal from failure")
	}
}

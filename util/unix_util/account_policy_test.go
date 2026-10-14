package unix_util

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// useTestShells points the login-shell check at a file the test controls, and returns a
// function restoring the real paths.
func useTestShells(t *testing.T, listing string) (shell string) {
	t.Helper()
	dir := t.TempDir()
	shells := filepath.Join(dir, "shells")
	if err := os.WriteFile(shells, []byte(listing), 0644); err != nil {
		t.Fatal(err)
	}
	previousShells := shellsFilePath
	shellsFilePath = shells
	nologinFilePaths = []string{filepath.Join(dir, "nologin")}
	t.Cleanup(func() {
		shellsFilePath = previousShells
		nologinFilePaths = []string{"/etc/nologin", "/etc/SH/no-login"}
	})
	return "/bin/bash"
}

// basePolicy is an account which must be usable: unlocked password, no expiry, a login
// shell which is in the test list of shells.
func basePolicy(shell string) AccountPolicy {
	return AccountPolicy{
		PasswordHash: "$6$rounds=656000$salt$hash",
		LastChange:   0,
		MaxAge:       -1,
		ExpireDate:   -1,
		// what glibc really reports for an ordinary account: sp_flag is empty in shadow(5)
		// and reads back as all bits set
		Flags: flagValueIsUnset,
		Shell: shell,
	}
}

func TestCheckAccountUsableAcceptsAPlainAccount(t *testing.T) {
	shell := useTestShells(t, "# valid login shells\n/bin/bash\n/bin/sh\n")
	if err := CheckAccountUsable(basePolicy(shell), time.Now()); err != nil {
		t.Fatalf("a normal account must be usable: %s", err)
	}
}

func TestCheckAccountUsableRefusesLockedPasswords(t *testing.T) {
	shell := useTestShells(t, "/bin/bash\n")
	// every one of these means "no password can be used on this account": they used to be
	// denied only by accident, because crypt() answers with a "*" string
	for name, hash := range map[string]string{
		"empty":            "",
		"exclamation":      "!",
		"never set":        "!!",
		"locked with hash": "!!$6$rounds=656000$salt$hash",
		"locked by -L":     "!$6$rounds=656000$salt$hash",
		"starred":          "*",
		"no login":         "!N5qf1bQeSLj6",
	} {
		policy := basePolicy(shell)
		policy.PasswordHash = hash
		if err := CheckAccountUsable(policy, time.Now()); err == nil {
			t.Errorf("%s: a locked password field must refuse the login", name)
		}
	}

	policy := basePolicy(shell)
	policy.Flags = flagLoginFacilityLocked // an sp_flag explicitly set to "login is locked"
	if err := CheckAccountUsable(policy, time.Now()); err == nil {
		t.Error("an sp_flag locking the account must refuse the login")
	}
}

// TestCheckAccountUsableAcceptsUnsetFlag covers what glibc really reports in sp_flag: the
// field is empty in shadow(5) for every ordinary account and reads back as all bits set.
// Reading those bits as a set of flags refuses the password of everybody on the system,
// which an early version of the check did - the lab caught it, the unit tests written
// against an assumed 0 did not.
func TestCheckAccountUsableAcceptsUnsetFlag(t *testing.T) {
	shell := useTestShells(t, "/bin/bash\n")
	policy := basePolicy(shell)
	policy.Flags = flagValueIsUnset
	if err := CheckAccountUsable(policy, time.Now()); err != nil {
		t.Fatalf("an account with an unset sp_flag (%x) is a normal account, it must be usable: %s",
			policy.Flags, err)
	}
}

func TestCheckAccountUsableRefusesExpiredAccounts(t *testing.T) {
	shell := useTestShells(t, "/bin/bash\n")
	now := time.Now()

	expired := basePolicy(shell)
	expired.ExpireDate = daysSinceEpoch(now) - 1
	if err := CheckAccountUsable(expired, now); err == nil {
		t.Fatal("an account whose sp_expire day has passed must be refused (chage -E)")
	}

	expiringToday := basePolicy(shell)
	expiringToday.ExpireDate = daysSinceEpoch(now)
	if err := CheckAccountUsable(expiringToday, now); err == nil {
		t.Fatal("the account expires today, it must already be refused")
	}

	notYet := basePolicy(shell)
	notYet.ExpireDate = daysSinceEpoch(now) + 10
	if err := CheckAccountUsable(notYet, now); err != nil {
		t.Fatalf("an account which expires in 10 days must stay usable: %s", err)
	}
}

func TestCheckAccountUsableRefusesExpiredPasswords(t *testing.T) {
	shell := useTestShells(t, "/bin/bash\n")
	now := time.Now()
	today := daysSinceEpoch(now)

	expired := basePolicy(shell)
	expired.LastChange = today - 30
	expired.MaxAge = 10
	if err := CheckAccountUsable(expired, now); err == nil {
		t.Fatal("a password expired since sp_lstchg+sp_max must be refused: this server cannot ask for a new one")
	}

	fresh := basePolicy(shell)
	fresh.LastChange = today - 1
	fresh.MaxAge = 30
	if err := CheckAccountUsable(fresh, now); err != nil {
		t.Fatalf("a password which is 1 day old with a 30 days validity must be accepted: %s", err)
	}

	// sp_max unset (-1) means the password never expires
	neverExpires := basePolicy(shell)
	neverExpires.LastChange = today - 1000
	neverExpires.MaxAge = -1
	if err := CheckAccountUsable(neverExpires, now); err != nil {
		t.Fatalf("an account whose password never expires must stay usable: %s", err)
	}
}

func TestCheckAccountUsableRefusesNonLoginShells(t *testing.T) {
	shell := useTestShells(t, "/bin/bash\n/bin/sh\n")

	for _, bad := range []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""} {
		policy := basePolicy(shell)
		policy.Shell = bad
		if err := CheckAccountUsable(policy, time.Now()); err == nil {
			t.Errorf("the login shell %q does not open a session and must be refused", bad)
		}
	}

	// a shell which exists but is not in /etc/shells: nologin(8) refuses it, so must this
	// server, which hands out a shell of its own
	policy := basePolicy(shell)
	policy.Shell = "/bin/tcsh"
	if err := CheckAccountUsable(policy, time.Now()); err == nil {
		t.Fatal("a shell absent from /etc/shells must be refused")
	}

	relative := basePolicy(shell)
	relative.Shell = "bash"
	if err := CheckAccountUsable(relative, time.Now()); err == nil {
		t.Fatal("a relative login shell must be refused")
	}
}

func TestCheckAccountUsableWithoutShellsFile(t *testing.T) {
	dir := t.TempDir()
	previousShells := shellsFilePath
	shellsFilePath = filepath.Join(dir, "missing", "shells")
	previousNologin := nologinFilePaths
	nologinFilePaths = []string{filepath.Join(dir, "nologin")}
	t.Cleanup(func() {
		shellsFilePath = previousShells
		nologinFilePaths = previousNologin
	})

	// a system with no /etc/shells restricts nothing: refusing every login would lock
	// everybody out, which is not what the absence of the file means
	if err := CheckAccountUsable(basePolicy("/bin/whatever"), time.Now()); err != nil {
		t.Fatalf("no /etc/shells must mean no restriction on login shells: %s", err)
	}
}

func TestCheckAccountUsableRespectsNologin(t *testing.T) {
	shell := useTestShells(t, "/bin/bash\n")
	dir := t.TempDir()
	nologin := filepath.Join(dir, "nologin")
	if err := os.WriteFile(nologin, []byte("maintenance"), 0644); err != nil {
		t.Fatal(err)
	}
	nologinFilePaths = []string{nologin}

	policy := basePolicy(shell)
	if err := CheckAccountUsable(policy, time.Now()); err == nil {
		t.Fatal("logins must be refused while the nologin file exists")
	}

	// the super-user is let in, as nologin(8) does
	root := basePolicy(shell)
	root.IsRoot = true
	if err := CheckAccountUsable(root, time.Now()); err != nil {
		t.Fatalf("the super-user must be allowed despite the nologin file: %s", err)
	}
}

func TestDaysSinceEpochAndDate(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	if daysSinceEpoch(epoch) != 0 {
		t.Fatal("the epoch is day 0")
	}
	oneDay := epoch.Add(24 * time.Hour)
	if daysSinceEpoch(oneDay) != 1 {
		t.Fatal("24h after the epoch is day 1")
	}
	if !dayToDate(1).Equal(oneDay) {
		t.Fatalf("dayToDate must invert daysSinceEpoch, got %s", dayToDate(1))
	}
}

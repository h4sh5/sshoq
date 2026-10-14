package unix_util

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AccountPolicy is the part of an account definition which decides whether a login is
// allowed at all, independently of the password being right: the password hash field of
// the shadow entry, the aging fields, and the login shell.
//
// Password authentication used to look at the password and nothing else, so an account
// which is locked, expired, or has no shell at all (`usermod -s /usr/sbin/nologin`) still
// accepted its password and handed out a full shell. OpenSSH/PAM refuse those logins; so
// must this server, and by default, since the fields are unreadable-but-ignored in the
// previous code.
type AccountPolicy struct {
	// PasswordHash is sp_pwdp: the hashed password, or one of the markers which say the
	// account has no usable password.
	PasswordHash string
	// LastChange is sp_lstchg: the day of the last password change, as days since
	// 1970-01-01, or -1 when unset.
	LastChange int64
	// MaxAge is sp_max: how many days the password is valid after a change, or -1 when
	// the password never expires.
	MaxAge int64
	// ExpireDate is sp_expire: the day from which the account is no longer accessible, as
	// days since 1970-01-01, or -1 when the account never expires.
	ExpireDate int64
	// Flags is sp_flag: the reserved account flag field of shadow(5). Linux does not use
	// it, and glibc reports all bits set when the field is empty in the file, which is
	// the normal case; see flagValueIsUnset.
	Flags uint32
	// Shell is pw_shell: the login shell of the account.
	Shell string
	// IsRoot tells whether the account is the super-user, which nologin(8) lets in even
	// when /etc/nologin exists.
	IsRoot bool
}

const (
	// flagValueIsUnset is what glibc hands back in sp_flag when the field is empty in
	// shadow(5), which is the case of every ordinary account: the field is documented as
	// reserved and Linux leaves it alone, so it reads as all bits set. Comparing it
	// against the flag bits as if it were a set of them would report every account of the
	// system as locked out of password login, which is what an earlier version of this
	// check did.
	flagValueIsUnset = ^uint32(0)
	// flagAccountNotValid is the AGTF_AUTHDEAD bit of the (SCO derived) flag field: the
	// account is not valid any more. Only honoured when the field is actually set.
	flagAccountNotValid = 1 << 3
	// flagLoginFacilityLocked is the AGTF_AUTHINFOLOCK bit: the login facility itself is
	// locked for this account.
	flagLoginFacilityLocked = 1 << 5
	// lockFlags gathers the flag bits which, when the field is set, deny a login.
	lockFlags = flagAccountNotValid | flagLoginFacilityLocked
)

// paths, overridable in tests
var (
	shellsFilePath = "/etc/shells"
	// nologinFilePaths are the paths nologin(8) looks at, in order: the Debian one first.
	nologinFilePaths = []string{"/etc/nologin", "/etc/SH/no-login"}
)

// CheckAccountUsable tells whether logging in is permitted for the account described by
// policy, at time now. It refuses the accounts which are locked, expired, without a
// password, without a login shell, or which nologin(8) would refuse. It is checked
// before the password, so that a correct password is not enough to open a session on an
// account the system considers closed.
func CheckAccountUsable(policy AccountPolicy, now time.Time) error {
	if locked, reason := lockedPasswordReason(policy.PasswordHash, policy.Flags); locked {
		return fmt.Errorf("the account is locked: %s", reason)
	}

	today := daysSinceEpoch(now)

	// a negative sp_expire means the account never expires; day 0 is a real date (the
	// epoch), not an unset value
	if policy.ExpireDate >= 0 && today >= policy.ExpireDate {
		return fmt.Errorf("the account expired on %s (shadow field sp_expire)", dayToDate(policy.ExpireDate))
	}

	// A password which expired would normally have to be changed at this very login,
	// which this server cannot do: it has no interactive password change. Refusing the
	// login is the only answer which does not silently keep an expired password working.
	// negative sp_max or sp_lstchg mean the field is unset, i.e. no restriction
	if policy.MaxAge >= 0 && policy.LastChange >= 0 {
		expiry := policy.LastChange + policy.MaxAge
		if today >= expiry {
			return fmt.Errorf("the password of the account expired on %s and this server cannot ask for a new one "+
				"(shadow fields sp_lstchg and sp_max)", dayToDate(expiry))
		}
	}

	if err := checkLoginShell(policy.Shell); err != nil {
		return err
	}

	if !policy.IsRoot {
		if exists, path := nologinFileExists(); exists {
			return fmt.Errorf("logins are currently disabled (%s exists), and this is not the super-user", path)
		}
	}

	return nil
}

// lockedPasswordReason tells whether a shadow password field is one of the markers which
// say the account has no usable password, instead of a hash.
func lockedPasswordReason(hash string, flags uint32) (bool, string) {
	if flags != flagValueIsUnset && flags&lockFlags != 0 {
		return true, "the account is flagged as not usable (shadow field sp_flag)"
	}
	switch {
	case hash == "":
		return true, "the shadow password field is empty"
	case hash == "!":
		return true, `the shadow password field is "!" (no password set)`
	case hash == "!!":
		return true, `the shadow password field is "!!" (the password was never set)`
	case strings.HasPrefix(hash, "!!"):
		return true, `the shadow password field starts with "!!" (the account is locked)`
	case strings.HasPrefix(hash, "!"):
		return true, `the shadow password field starts with "!" (the account was locked, e.g. by usermod -L)`
	case strings.HasPrefix(hash, "*"):
		return true, `the shadow password field starts with "*" (no login with a password)`
	}
	return false, ""
}

// checkLoginShell refuses the shells which do not open a session: nologin(8) and false
// obviously, and any shell which is not listed in /etc/shells when that file exists, as
// nologin(8) does.
func checkLoginShell(shell string) error {
	if shell == "" {
		return fmt.Errorf("the account has no login shell")
	}
	if !filepath.IsAbs(shell) {
		return fmt.Errorf("the login shell %q of the account is not an absolute path", shell)
	}
	switch filepath.Base(shell) {
	case "nologin", "false", "sync", "shutdown", "halt", "reboot":
		return fmt.Errorf("the login shell of the account is %s, which does not open a session", shell)
	}
	listed, err := shellIsListedIn(shellsFilePath, shell)
	if err != nil {
		// the list of login shells exists but cannot be read: it would be wrong to
		// pretend the shell was not allowed, and wrong to ignore the check; what the
		// system intends cannot be known, so the safe answer is to refuse and say why
		return fmt.Errorf("could not read the list of login shells %s: %w", shellsFilePath, err)
	}
	if !listed {
		return fmt.Errorf("the login shell %s of the account is not listed in %s, which nologin(8) requires", shell, shellsFilePath)
	}
	return nil
}

// shellIsListedIn tells whether shell appears in the shells(5) file at path. A missing
// file means the system does not restrict login shells, and is reported as "not listed"
// without error: callers decide.
func shellIsListedIn(path string, shell string) (bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		// no policy on this system: accept the shell rather than lock everybody out
		return true, nil
	} else if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// a trailing argument ("bash --login") is not part of the path
		if fields := strings.Fields(line); len(fields) > 0 {
			line = fields[0]
		}
		if line == shell {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// nologinFileExists looks for the file which disables logins, as nologin(8) does.
func nologinFileExists() (bool, string) {
	for _, path := range nologinFilePaths {
		if _, err := os.Stat(path); err == nil {
			return true, path
		}
	}
	return false, ""
}

// daysSinceEpoch is what shadow(5) stores: complete days since 1970-01-01 (UTC).
func daysSinceEpoch(t time.Time) int64 {
	return t.UTC().Unix() / secondsPerDay
}

const secondsPerDay = int64(24 * 60 * 60)

// dayToDate turns a shadow(5) day count back into a readable date.
func dayToDate(days int64) time.Time {
	return time.Unix(days*secondsPerDay, 0).UTC()
}

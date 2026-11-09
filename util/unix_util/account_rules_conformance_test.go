package unix_util

// Correspondence checks for account_rules.go: the verified decisions must be the ones
// CheckAccountUsable still applies, and the two pieces of `filepath` that file used before
// they were reimplemented must be the same functions.
//
// The gate here is the one that decides whether a login happens at all, independently of the
// password being right, so the tests are written to catch the mistakes that lock a system out
// rather than the ones that let someone in: the unset-flag reading, the -1-means-never rules,
// the expiry day itself, and a shell named with a trailing slash.

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConformancePathBaseNameIsFilepathBase(t *testing.T) {
	paths := []string{
		"/bin/bash", "/usr/sbin/nologin", "/usr/sbin/nologin/", "/usr/sbin/nologin//",
		"/", "//", "///", "", ".", "..", "bash", "./bash", "../bin/false",
		"/bin/", "/bin/false/", "/bin/false//", "/sbin/shutdown", "halt", "/reboot",
		"/opt/very/long/path/to/a/shell", "/bin/bash --login", " ", "/ ", "/space dir/sh",
	}
	for _, path := range paths {
		got, want := pathBaseName(path), filepath.Base(path)
		if got != want {
			t.Errorf("pathBaseName(%q) = %q, filepath.Base says %q", path, got, want)
		}
		// the clause the prover drops: a name is a name, so it holds no separator
		if strings.Contains(got, "/") && got != "/" {
			t.Errorf("pathBaseName(%q) = %q, which still contains a slash", path, got)
		}
		if got == "" {
			t.Errorf("pathBaseName(%q) returned the empty string", path)
		}
	}
}

func TestConformancePathIsAbsoluteIsFilepathIsAbs(t *testing.T) {
	for _, path := range []string{"/bin/bash", "bin/bash", "", "/", "//x", "./x", " /x", "/"} {
		if got, want := pathIsAbsolute(path), filepath.IsAbs(path); got != want {
			t.Errorf("pathIsAbsolute(%q) = %t, filepath.IsAbs says %t", path, got, want)
		}
	}
}

// TestConformanceLockedPasswordFieldDecisionMatchesTheReason checks the seam between the proved
// decision and the message-generating switch: they must agree on *whether* a field is a lock
// marker, because the switch is the only thing that keeps the five spellings readable in the log
// and the proved predicate is the only thing that decides the login.
func TestConformanceLockedPasswordFieldDecisionMatchesTheReason(t *testing.T) {
	hashes := []string{
		"", "!", "!!", "!!!", "!locked", "! ", "*", "*lock", "*", "$6$rounds=656000$salt$hash",
		"x", "x!", "x*", " £!", "$2b$12$abc", "!", "y",
	}
	flags := []uint32{flagValueIsUnset, 0, flagAccountNotValid, flagLoginFacilityLocked,
		flagAccountNotValid | flagLoginFacilityLocked, 1, 1 << 4, math.MaxUint32, math.MaxUint32 - 1}
	for _, hash := range hashes {
		for _, flag := range flags {
			locked := passwordFieldIsLocked(hash, flag)
			_, reason := lockedPasswordReason(hash, flag)
			if locked != (reason != "") {
				t.Errorf("passwordFieldIsLocked(%q, %d) = %t but lockedPasswordReason gave reason %q",
					hash, flag, locked, reason)
			}
			if isHash := passwordFieldIsAHash(hash, flag); isHash == locked {
				t.Errorf("passwordFieldIsAHash(%q, %d) = %t is not the complement of locked", hash, flag, isHash)
			}
		}
	}
}

// TestConformanceWhichFieldsAreLockMarkers is the decision itself, spelled out: every value that
// begins with `!`, and only those plus the empty field and the `*`, mean there is no password to
// check. `x!` and `x*` are hashes: the marker is the first byte, not a substring.
func TestConformanceWhichFieldsAreLockMarkers(t *testing.T) {
	cases := map[string]bool{
		"": true, "!": true, "!!": true, "!!S": true, "!anything": true, "*": true, "*LOCK*": true,
		"$6$a$b": false, "x!": false, "x*": false, " !": false, "£": false, "\x00!": false,
	}
	for hash, want := range cases {
		if got := passwordFieldIsLocked(hash, flagValueIsUnset); got != want {
			t.Errorf("passwordFieldIsLocked(%q, unset flags) = %t, want %t", hash, got, want)
		}
	}
}

// TestConformanceUnsetFlagFieldLocksNobody is the bug that an earlier draft of this check had:
// glibc reports every bit set for an empty sp_flag, so the flag bits count only when the field is
// actually set. The test is written on the two bits that matter and on the values a real shadow
// file produces.
func TestConformanceUnsetFlagFieldLocksNobody(t *testing.T) {
	hash := "$6$rounds=656000$salt$hash"
	if passwordFieldIsLocked(hash, flagValueIsUnset) {
		t.Error("an account whose sp_flag is unset must not be locked by its flags")
	}
	if passwordFieldIsLocked(hash, 0) {
		t.Error("a set but empty sp_flag (zero) locks nothing")
	}
	for _, flag := range []uint32{flagAccountNotValid, flagLoginFacilityLocked,
		flagAccountNotValid | flagLoginFacilityLocked, flagAccountNotValid | 1<<7} {
		if !passwordFieldIsLocked(hash, flag) {
			t.Errorf("sp_flag %d carries a lock bit and must refuse the login", flag)
		}
	}
	// bits outside the two the check honours change nothing
	for _, flag := range []uint32{1, 1 << 1, 1 << 2, 1 << 4, 1 << 6, 1 << 31} {
		if passwordFieldIsLocked(hash, flag) {
			t.Errorf("sp_flag %d carries none of the lock bits and must not refuse the login", flag)
		}
	}
}

func TestConformanceAccountExpiryBoundaryIsTheExpiryDay(t *testing.T) {
	for today := int64(-2); today <= 2; today++ {
		for expire := int64(-2); expire <= 2; expire++ {
			want := expire >= 0 && today >= expire
			if got := accountIsExpired(today, expire); got != want {
				t.Errorf("accountIsExpired(today=%d, expire=%d) = %t, want %t", today, expire, got, want)
			}
		}
	}
	// -1 is "never"; day 0 is the epoch, a date like any other
	if accountIsExpired(math.MaxInt64, -1) {
		t.Error("sp_expire = -1 must never expire")
	}
	if !accountIsExpired(0, 0) {
		t.Error("an account expiring on day 0 is expired on day 0")
	}
	// monotonicity, over the boundary in particular
	for expire := int64(-2); expire <= 2; expire++ {
		for earlier := int64(-2); earlier <= 2; earlier++ {
			for later := earlier; later <= 2; later++ {
				if !accountExpiryIsMonotone(earlier, later, expire) {
					t.Errorf("expiry went backwards: expire=%d, earlier=%d, later=%d", expire, earlier, later)
				}
			}
		}
	}
}

func TestConformancePasswordExpiryBoundaryAndUnsetFields(t *testing.T) {
	for today := int64(-1); today <= 3; today++ {
		for change := int64(-1); change <= 2; change++ {
			for maxAge := int64(-1); maxAge <= 2; maxAge++ {
				want := maxAge >= 0 && change >= 0 && today >= change+maxAge
				if got := passwordIsExpired(today, change, maxAge); got != want {
					t.Errorf("passwordIsExpired(%d, %d, %d) = %t, want %t", today, change, maxAge, got, want)
				}
			}
		}
	}
	// either field unset means no rule, whatever the other says
	for _, today := range []int64{0, 1000, math.MaxInt64} {
		if passwordIsExpired(today, 0, -1) || passwordIsExpired(today, -1, 90) {
			t.Error("an unset sp_max or sp_lstchg must not refuse a login")
		}
	}
}

// TestConformancePasswordExpiryOverflowRefuses is the edge the prover cannot see: its integers are
// unbounded, the Go ones wrap, and a `sp_max` big enough to overflow the sum lands the expiry on a
// negative day number. What matters is the direction -- the wrapped answer refuses rather than
// admits, so a shadow file with an absurd field locks the account out instead of making the
// password immortal.
func TestConformancePasswordExpiryOverflowRefuses(t *testing.T) {
	if !passwordIsExpired(1, 1, math.MaxInt64) {
		t.Error("a wrapped password expiry must refuse the login rather than admit it")
	}
	if !passwordIsExpired(0, math.MaxInt64, math.MaxInt64) {
		t.Error("a wrapped password expiry must refuse the login rather than admit it")
	}
	// and the same shape end to end, through the gate the server calls
	shell := useTestShells(t, "/bin/bash\n")
	policy := basePolicy(shell)
	policy.LastChange = 1
	policy.MaxAge = math.MaxInt64
	if err := CheckAccountUsable(policy, time.Now()); err == nil {
		t.Error("CheckAccountUsable accepted an account whose password expiry wrapped")
	}
}

// TestConformanceLoginShellDecisionIsTheGate'sFirstHalf runs the proved rule and checkLoginShell
// over the same shells, with an /etc/shells that lists every path in the table so that the only
// refusals left are the ones the rule makes.
func TestConformanceLoginShellDecisionIsTheGateFirstHalf(t *testing.T) {
	shells := []string{
		"/bin/bash", "/bin/bash/", "/bin/false", "/usr/sbin/nologin", "/usr/sbin/nologin/",
		"/sbin/shutdown", "/bin/sync", "/bin/halt", "/bin/reboot", "/bin/zsh",
		"bin/bash", "", "/", "//", " /bin/bash",
	}
	// "/bin/bash --login" is deliberately not in this table. It is refused, and by the half of
	// checkLoginShell that is a premise rather than by the rule: as a *shell path* it is not the
	// path any shells(5) line names, because in that file the argument belongs to the line and not
	// to the path. TestConformanceShellsFileParsing is where that form is exercised.

	var listing string
	for _, shell := range shells {
		listing += shell + "\n"
	}
	useTestShells(t, listing)

	for _, shell := range shells {
		want := loginShellNeedsRefusing(shell, pathBaseName(shell))
		got := checkLoginShell(shell) != nil
		if got != want {
			t.Errorf("checkLoginShell(%q) refused = %t, the verified rule says %t", shell, got, want)
		}
	}
	// the names that deny a session, and the ones that do not
	for _, name := range []string{"nologin", "false", "sync", "shutdown", "halt", "reboot"} {
		if !baseNameDeniesASession(name) {
			t.Errorf("%s must deny a session", name)
		}
		if loginShellNeedsRefusing("/bin/"+name, pathBaseName("/bin/"+name)) != true {
			t.Errorf("/bin/%s must be refused", name)
		}
	}
	for _, name := range []string{"bash", "nolog", "truex", "sh", "nologin.real", ""} {
		if baseNameDeniesASession(name) {
			t.Errorf("%s is not one of the programs that deny a session", name)
		}
	}
}

// TestConformanceShellsFileParsing is the other half: how a line of shells(5) becomes a path. The
// helpers must agree with the strings package they replaced, and the file must then be honoured by
// the gate end to end -- an entry with an argument still admits its path, a comment admits nothing.
func TestConformanceShellsFileParsing(t *testing.T) {
	for _, line := range []string{"", " ", "\t", "#", "# /bin/bash", "/bin/bash", "/bin/bash --login", "  \t/x"} {
		trimmed := strings.TrimSpace(line)
		wantNoPath := trimmed == "" || strings.HasPrefix(trimmed, "#")
		if got := shellsLineCarriesNoPath(trimmed); got != wantNoPath {
			t.Errorf("shellsLineCarriesNoPath(%q) = %t, want %t", trimmed, got, wantNoPath)
		}
		field := firstSpaceSeparatedField(trimmed)
		if fields := strings.Fields(trimmed); len(fields) > 0 {
			if field != fields[0] {
				t.Errorf("firstSpaceSeparatedField(%q) = %q, strings.Fields says %q", trimmed, field, fields[0])
			}
		} else if field != "" {
			t.Errorf("firstSpaceSeparatedField(%q) = %q for a line with no fields", trimmed, field)
		}
		if strings.ContainsAny(field, " \t") {
			t.Errorf("firstSpaceSeparatedField(%q) = %q still holds a blank", trimmed, field)
		}
	}

	// end to end: the argument form admits the shell, the comment form does not
	withArgument := useTestShells(t, "# login shells\n  /bin/bash --login  \n")
	policy := basePolicy(withArgument)
	if err := CheckAccountUsable(policy, time.Now()); err != nil {
		t.Errorf("a shells(5) entry with an argument must admit its path: %s", err)
	}
	commentedOut := useTestShells(t, "# /bin/bash\n")
	policy = basePolicy(commentedOut)
	if err := CheckAccountUsable(policy, time.Now()); err == nil {
		t.Error("a commented-out shells(5) entry must not admit the shell")
	}
}

// TestConformanceGateStillRefusesEndToEnd is the requirement as a whole, through the function the
// server calls: every one of the closed-account shapes is refused with the right password in
// place, and a normal account is not. The password itself is compared elsewhere; what this row is
// about is that none of these can be bought by knowing it.
func TestConformanceGateStillRefusesEndToEnd(t *testing.T) {
	shell := useTestShells(t, "/bin/bash\n/bin/sh\n")
	now := time.Now()
	today := daysSinceEpoch(now)

	refusals := map[string]func(p *AccountPolicy){
		"locked by its password field": func(p *AccountPolicy) { p.PasswordHash = "!" },
		"locked by never having one":   func(p *AccountPolicy) { p.PasswordHash = "!!" },
		"locked by its flags":          func(p *AccountPolicy) { p.Flags = flagLoginFacilityLocked },
		"expired yesterday":            func(p *AccountPolicy) { p.ExpireDate = today - 1 },
		"expired today":                func(p *AccountPolicy) { p.ExpireDate = today },
		"with an expired password":     func(p *AccountPolicy) { p.LastChange = today - 90; p.MaxAge = 30 },
		"with no login shell at all":   func(p *AccountPolicy) { p.Shell = "" },
		"with nologin as its shell":    func(p *AccountPolicy) { p.Shell = "/usr/sbin/nologin" },
		"with a shell ending in a slash naming nologin": func(p *AccountPolicy) {
			p.Shell = "/usr/sbin/nologin/"
		},
		"with a relative login shell": func(p *AccountPolicy) { p.Shell = "bin/bash" },
		"with a shell nobody listed":  func(p *AccountPolicy) { p.Shell = "/opt/ghost/sh" },
	}
	for name, close := range refusals {
		policy := basePolicy(shell)
		close(&policy)
		if err := CheckAccountUsable(policy, now); err == nil {
			t.Errorf("an account %s was accepted", name)
		} else if !strings.Contains(err.Error(), "account") && !strings.Contains(err.Error(), "login") &&
			!strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "shell") {
			t.Errorf("an account %s was refused for an unrecognisable reason: %s", name, err)
		}
	}

	// an account that is merely old, or expires tomorrow, is usable
	for name, adjust := range map[string]func(p *AccountPolicy){
		"expires tomorrow":  func(p *AccountPolicy) { p.ExpireDate = today + 1 },
		"password due soon": func(p *AccountPolicy) { p.LastChange = today - 89; p.MaxAge = 90 },
		"never expires":     func(p *AccountPolicy) { p.ExpireDate = -1; p.MaxAge = -1; p.LastChange = -1 },
	} {
		policy := basePolicy(shell)
		adjust(&policy)
		if err := CheckAccountUsable(policy, now); err != nil {
			t.Errorf("an account %s was refused: %s", name, err)
		}
	}

	// nologin(8): the file refuses everybody but root
	dir := t.TempDir()
	nologin := filepath.Join(dir, "no-login")
	if err := os.WriteFile(nologin, []byte("down\n"), 0644); err != nil {
		t.Fatal(err)
	}
	previousShells, previousPaths := shellsFilePath, nologinFilePaths
	shellsFilePath = filepath.Join(dir, "shells")
	if err := os.WriteFile(shellsFilePath, []byte(shell+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	nologinFilePaths = []string{nologin}
	t.Cleanup(func() { shellsFilePath, nologinFilePaths = previousShells, previousPaths })

	policy := basePolicy(shell)
	if err := CheckAccountUsable(policy, now); err == nil {
		t.Error("the nologin file must refuse an ordinary account")
	} else if !strings.Contains(err.Error(), nologin) {
		t.Errorf("the refusal must name the file it found, said %q", err)
	}
	policy.IsRoot = true
	if err := CheckAccountUsable(policy, now); err != nil {
		t.Errorf("nologin(8) lets the super-user in, refused root with %s", err)
	}
}

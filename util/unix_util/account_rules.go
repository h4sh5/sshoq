package unix_util

// The account rules that decide a login, verified where they run.
//
// `CheckAccountUsable` is the gate that refuses an account the system considers closed -- locked, expired,
// without a password, without a login shell, or blocked by `/etc/nologin` -- *before* the password is
// looked at, so that a correct password is not enough to open a session. Its decisions are arithmetic on
// shadow(5) fields and tests on a handful of byte patterns, which is exactly what a deductive prover can
// hold; the reason they are not annotated where they are written is that the file around them reads files
// with `os` and `bufio` and formats errors with `fmt`, none of which Gobra v26.09 can parse. So the
// decisions are lifted here -- same package, same behaviour, same call sites -- and the messages, the file
// reads and the clock stay there. `account_rules_conformance_test.go` is the seam that says the two halves
// still fit together.
//
// The properties worth having are the ones a shadow file can surprise you with, and each of them was a real
// bug class in this check's first draft:
//
//   * `sp_flag` reads as all-bits-set on every ordinary account (glibc's reserved field), so the flag bits
//     are honoured only when the field is actually set -- taken at face value it locks out the system;
//   * `-1` means "unset" in the aging fields, but `0` is a real date: the epoch. A test written as
//     `if field` refuses every account whose field is unset and admits none whose expiry is the epoch;
//   * a locked password field is any value starting with `!` plus the empty string and `*`, not the two
//     spellings the man page happens to show;
//   * the login-shell check has to agree with `nologin(8)`, which means agreeing with `filepath` about what
//     a file name is -- `/usr/sbin/nologin/` names `nologin`.

// The three constants the lock decision needs. They live here rather than in `account_policy.go` because a
// verified file must resolve everything it names: `-i` checks one file's package and reports a
// package-mate it cannot see as "got unknown identifier".
const (
	// flagValueIsUnset is what glibc hands back in sp_flag when the field is empty in shadow(5), which is
	// the case of every ordinary account: the field is documented as reserved and Linux leaves it alone, so
	// it reads as all bits set. Comparing it against the flag bits as if it were a set of them would report
	// every account of the system as locked out of password login, which is what an earlier version of this
	// check did.
	flagValueIsUnset = ^uint32(0)
	// flagAccountNotValid is the AGTF_AUTHDEAD bit of the (SCO derived) flag field.
	flagAccountNotValid = 1 << 3
	// flagLoginFacilityLocked is the AGTF_AUTHINFOLOCK bit.
	flagLoginFacilityLocked = 1 << 5
	// lockFlags gathers the flag bits which, when the field is set, deny a login.
	lockFlags = flagAccountNotValid | flagLoginFacilityLocked
)

// passwordFieldIsLocked tells whether a shadow password field is one of the markers that say the account
// has no usable password, instead of a hash, or whether the flag field says the account is closed.
//
// The contract is the whole decision in one line, and it is shorter than the code it describes because the
// marker spellings the man page lists -- `!`, `!!`, and a leading `!` from `usermod -L` -- collapse to "the
// first byte is `!`", next to the empty field and the `*` of an account with no password login. Stating it
// that way is what makes the code's five `case` arms checkable: they enumerate the *reasons*, and this says
// when there is one at all.
//
// The body is one expression because a `pure` function -- which is what lets the contracts below speak of
// this one -- may be nothing else in Gobra v26.09; `len(hash) == 0` comes before `hash[0]` so that the
// short-circuit is what keeps an empty field from indexing out of range.
//
// @ ensures locked == (flags != flagValueIsUnset && (flags & lockFlags) != 0 || len(hash) == 0 || hash[0] == '!' || hash[0] == '*')
// @ pure
// @ decreases
func passwordFieldIsLocked(hash string, flags uint32) (locked bool) {
	return flags != flagValueIsUnset && flags&lockFlags != 0 || len(hash) == 0 || hash[0] == '!' || hash[0] == '*'
}

// passwordFieldIsAHash is the other answer: a field that is neither of the marker shapes is something a
// password can be checked against. It is stated because the two answers must partition the inputs -- an
// account that is neither locked nor checkable would be neither refused nor authenticated, which is the
// shape of every "why can nobody log in" story.
//
// @ ensures isHash == !passwordFieldIsLocked(hash, flags)
// @ decreases
func passwordFieldIsAHash(hash string, flags uint32) (isHash bool) {
	return !passwordFieldIsLocked(hash, flags)
}

// accountIsExpired is the sp_expire rule: a negative value means the account never expires, and every
// other value is a day number on which the account stops being accessible -- including 0, which is the
// epoch and not an unset marker. The comparison is `>=`: on the expiry day itself the account is gone, as
// shadow(5) has it, and getting that boundary the other way round grants one extra day of access to every
// expired account on the system.
//
// @ ensures expired == (expireDate >= 0 && today >= expireDate)
// @ pure
// @ decreases
func accountIsExpired(today int64, expireDate int64) (expired bool) {
	return expireDate >= 0 && today >= expireDate
}

// accountExpiryIsMonotone says the shape of that answer over time: an account that has expired has expired
// forever after, and one that has not yet expired is not expired earlier. It is the property the boundary
// above is easy to break while fixing something else.
//
// `holds` is the implication "expired at the earlier moment, or not expired at the later one", which is
// monotonicity in the only shape a function can return.
//
// @ requires earlier <= later
// @ ensures holds == (!accountIsExpired(earlier, expireDate) || accountIsExpired(later, expireDate))
// @ pure
// @ decreases
func accountExpiryIsMonotone(earlier int64, later int64, expireDate int64) (holds bool) {
	return !accountIsExpired(earlier, expireDate) || accountIsExpired(later, expireDate)
}

// passwordIsExpired is the sp_lstchg/sp_max rule: the password died `MaxAge` days after it was last
// changed, and either field being negative means there is no such rule. Refusing rather than forcing a
// change is a decision, not an oversight -- this server has no interactive password change, and the
// alternative to refusing is an expired password that keeps working forever.
//
// The integers here are unbounded in the prover and wrap in Go, so the one edge where
// `lastChange + maxAge` runs past the largest day number cannot be stated in this contract; it is fail
// closed (a wrapped expiry is a negative day number, and every real today is at or after it), and
// `TestConformancePasswordExpiryOverflowRefuses` is what says so about the Go arithmetic.
//
// @ ensures expired == (maxAge >= 0 && lastChange >= 0 && today >= lastChange + maxAge)
// @ pure
// @ decreases
func passwordIsExpired(today int64, lastChange int64, maxAge int64) (expired bool) {
	return maxAge >= 0 && lastChange >= 0 && today >= lastChange+maxAge
}

// passwordExpiryNeedsBothFields is the part of that rule that a reader has to get right to read a shadow
// file at all: no rule without both fields, so an unset `sp_max` (never expires) or an unset `sp_lstchg`
// (never changed) never refuses.
//
// @ requires maxAge < 0 || lastChange < 0
// @ ensures !expired
// @ decreases
func passwordExpiryNeedsBothFields(today int64, lastChange int64, maxAge int64) (expired bool) {
	return passwordIsExpired(today, lastChange, maxAge)
}

// pathIsAbsolute is `filepath.IsAbs` for the slash-separated paths this package ever sees: an absolute path
// is one that starts with a slash. The file-name rules below depend on it, and `checkLoginShell` refuses a
// relative shell because a shell named by a relative path is a shell whose location depends on the working
// directory of whoever started the server.
//
// @ ensures absolute == (len(path) > 0 && path[0] == '/')
// @ pure
// @ decreases
func pathIsAbsolute(path string) (absolute bool) {
	return len(path) > 0 && path[0] == '/'
}

// stringHasByte tells whether b appears anywhere in s. It is the vocabulary the name rules below speak, and
// it is here rather than `strings.Contains` because a spec that can reason about a helper can only do so if
// the helper has a contract: the stdlib's `strings` stub says what `Contains` takes, not what it finds.
//
// It is not `pure` -- a looping body is not the single return Gobra allows in a pure function -- so it
// cannot appear in the contracts of others either, which is why the name rules below quantify over indices
// instead of calling it.
//
// @ ensures found == (exists i int :: 0 <= i && i < len(s) && s[i] == b)
// @ decreases len(s)
func stringHasByte(s string, b byte) (found bool) {
	// @ invariant 0 <= i && i <= len(s)
	// @ invariant (exists j int :: 0 <= j && j < i && s[j] == b) == false
	// @ decreases len(s) - i
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}

// pathBaseName is `filepath.Base` for slash-separated paths, which is what `nologin(8)` and the shadow
// check need: the trailing slashes go first -- `/usr/sbin/nologin/` names `nologin` -- and then whatever
// follows the last remaining slash. Empty input names `.` and a path of nothing but slashes names `/`,
// both exactly as `filepath` does, because the point of reimplementing a rule this small is not to have a
// second one but to have one that can be proved and then checked against the stdlib's.
//
// The contract says what can be said without a theory of characters: the name is never empty, it is no
// longer than the path, it is a suffix of the path when the path had a trailing-slash or last-slash shape,
// and it contains no slash. `TestConformancePathBaseNameIsFilepathBase` is what says it is the same
// function as `filepath.Base`.
//
// It is not `pure` either -- two loops, and a pure body has to be a single return -- which is why the
// shell decision below takes the name as an argument instead of computing it, and why the seam between the
// two is closed by `TestConformancePathBaseNameIsFilepathBase` rather than by a lemma. That is the shape of
// premise this repository accepts when the prover cannot hold a loop and a theory of characters at once: the
// decision is proved *given* the name, the name is proved to have the shape the decision assumes and
// tested to be the stdlib's own.
//
// The contract keeps the two clauses the prover accepts (the name is never empty; it is no longer than the
// path, and `path == ""` is allowed to be the degenerate case) and drops the third, which is the one a
// reader would ask for -- *the name contains no slash*. It is true, and the loop invariant that would prove
// it is written below; what the prover will not do is carry a fact about `trimmed[j]` across the point where
// the return value becomes a suffix of `trimmed`, because `name[i]` and `trimmed[i0+1+i]` are the same byte
// and not the same term. `TestConformancePathBaseNameIsFilepathBase` states it over a table instead, and
// compares against the stdlib in the same breath.
//
// @ ensures len(name) >= 1
// @ ensures len(name) <= len(path) || len(path) == 0
// @ decreases
func pathBaseName(path string) (name string) {
	trimmed := path
	// drop trailing slashes; a path of nothing but slashes becomes the root
	// @ invariant len(trimmed) <= len(path) && len(trimmed) >= 0
	// @ invariant len(trimmed) == 0 ==> len(path) == 0
	// @ decreases len(trimmed)
	for len(trimmed) > 1 && trimmed[len(trimmed)-1] == '/' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	// the root, spelled as a byte test so that "the last byte is not a slash" survives the branch below for
	// the one-character case; after the trim above, `trimmed == "/"` and this are the same test
	if len(trimmed) == 1 && trimmed[0] == '/' {
		return "/"
	}
	// written as a length test rather than `trimmed == ""`, which the prover cannot turn into a fact about
	// length because a string of length zero need not be equal to the empty string in its logic
	if len(trimmed) == 0 {
		return "."
	}
	// what follows the last slash, or the whole thing if there is none
	// @ invariant 0 <= i && i < len(trimmed) || i < 0
	// @ invariant len(trimmed) <= len(path)
	// @ invariant len(trimmed) >= 1 && trimmed[len(trimmed)-1] != '/'
	// @ invariant !(exists j int :: 0 <= j && i < j && j < len(trimmed) && trimmed[j] == '/')
	// @ decreases i + 1
	for i := len(trimmed) - 1; i >= 0; i-- {
		if trimmed[i] == '/' {
			// @ assert i < len(trimmed)
			return trimmed[i+1:]
		}
	}
	return trimmed
}

// baseNameDeniesASession is the list of programs that accept a login and open no session, which is the list
// `nologin(8)` refuses by name. They are compared as names, not paths, so `/sbin/false`, `/bin/false` and a
// `false` reached through a symlink named differently are all refused -- and so a program of your own
// called `sync` will not get a session either, which is the price of matching the tool everybody else
// matches.
//
// @ ensures denies == (name == "nologin" || name == "false" || name == "sync" || name == "shutdown" || name == "halt" || name == "reboot")
// @ pure
// @ decreases
func baseNameDeniesASession(name string) (denies bool) {
	return name == "nologin" || name == "false" || name == "sync" || name == "shutdown" || name == "halt" || name == "reboot"
}

// loginShellNeedsRefusing is the pure half of `checkLoginShell`: no shell at all, a shell named by a
// relative path, or a shell whose program opens no session. What is left in `checkLoginShell` is the
// question that can only be asked of the machine -- whether `/etc/shells` lists the path, and what to do
// when that file exists but cannot be read -- and that question stays a premise, named in the row of
// `proof/SECURITY_REQUIREMENTS.md`.
//
// `name` is the program the shell path runs, which the caller extracts with `pathBaseName`. Taking it as an
// argument is the premise: the prover cannot see through the two loops of `pathBaseName`, so what is proved
// here is the decision *given* a name, and what the tests add is that the name passed is the base name, and
// that `pathBaseName` is `filepath.Base`.
//
// @ ensures refuses == (len(shell) == 0 || !pathIsAbsolute(shell) || baseNameDeniesASession(name))
// @ ensures len(shell) > 0 && pathIsAbsolute(shell) ==> (refuses == baseNameDeniesASession(name))
// @ pure
// @ decreases
func loginShellNeedsRefusing(shell string, name string) (refuses bool) {
	return len(shell) == 0 || !pathIsAbsolute(shell) || baseNameDeniesASession(name)
}

// shellsLineCarriesNoPath is the first test `shells(5)` needs: blank lines and `#` comments carry no shell,
// after the leading and trailing whitespace is dropped. Getting this wrong in the admitting direction puts
// a comment in the list of login shells, which admits nothing; getting it wrong in the refusing direction
// makes a real entry unreadable, which locks the account out -- so the blank test is written to ignore
// surrounding blanks rather than to require an empty line.
//
// @ ensures noPath == (len(line) == 0 || line[0] == '#')
// @ decreases
func shellsLineCarriesNoPath(line string) (noPath bool) {
	if len(line) == 0 {
		return true
	}
	return line[0] == '#'
}

// firstSpaceSeparatedField is the second test: a line of `shells(5)` may carry an argument
// ("/bin/bash --login"), and the argument is not part of the path. This is the field before the first
// space or tab of a line whose surrounding blanks have been dropped, so it is a prefix of its input and
// contains no blank -- which is what lets `shellIsListedIn` compare it against a path exactly.
//
// @ ensures len(field) <= len(line)
// @ ensures !(exists i int :: 0 <= i && i < len(field) && (line[i] == ' ' || line[i] == '\t'))
// @ decreases len(line)
func firstSpaceSeparatedField(line string) (field string) {
	// @ invariant 0 <= i && i <= len(line)
	// @ invariant (exists j int :: 0 <= j && j < i && (line[j] == ' ' || line[j] == '\t')) == false
	// @ decreases len(line) - i
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' {
			return line[:i]
		}
	}
	return line
}

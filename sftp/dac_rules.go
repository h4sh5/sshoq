package sftp

// The discretionary-access decision the SFTP server makes for itself, lifted out of
// server.go and verified where it ships.
//
// The server walks, lists, creates, replaces and removes paths with *its own* privileges:
// the login user's credentials belong to the child process, not to the request loop which
// answers the client. So each of those operations is gated by a decision this package
// makes itself, from the uid, gid and mode bits it read from the filesystem on one side
// and the session's uid and group list on the other. That decision is the whole of the
// access control for the request loop: what is granted here is performed with the
// server's rights, and what is refused here never reaches the disk.
//
// The rule has two halves, and the split matters: *which* of the three triads of mode bits
// applies is a question about identity, and *whether that triad carries what was asked
// for* is a question about bits. server.go wrote both halves as one switch storing a triad
// into a local variable plus three tests against it, while twelve call sites asked for
// seven different combinations. Entangled, the statements worth proving - that asking for
// more can never help, that the bits above the nine permission bits cannot grant anything,
// that a grant is the conjunction of the grants for each bit asked for - were about a local
// variable and a switch.
//
// "Writing!": a Gobra `pure` function must be a single `return` of a pure expression, so
// the case distinction over which triad applies is written as the three-way boolean chain
// in triadGrantsBit rather than as a switch, and triadOf - the switch form, which is what a
// reader wants to see - stays plain Go and is pinned to the verified predicates by
// TestConformanceTriadSelectionAgrees, exhaustively over every mode and both identity
// facts. That is the same trade source_check.go documents for the "!" helper.
//
// The constants are re-declared here rather than taken from server.go, because that file
// imports syscall, golang.org/x/sys/unix and quic-go and Gobra checks a spec against the
// whole package (proof/README.md, F15). TestConformanceLiftedConstantsMatchTheServer asserts
// these are the values the server asks with, so the two lists cannot drift apart unnoticed.

const (
	// dacRead, dacWrite, dacExec name the bits an operation asks for, in the position a
	// triad carries them: the same numbers as accessR, accessW and accessX.
	dacRead  = 0x4
	dacWrite = 0x2
	dacExec  = 0x1
	// dacAskedFor is every bit an operation can ask for.
	dacAskedFor = dacRead | dacWrite | dacExec
	// dacTriadMask is one triad: three bits.
	dacTriadMask = 0o7
	// dacModePerm is the nine permission bits of a mode. Everything above them - setuid,
	// setgid, the sticky bit, the file type - is not part of this decision.
	dacModePerm = 0o777
	// ownerTriadShift and groupTriadShift put a triad in its place in a mode.
	ownerTriadShift = 6
	groupTriadShift = 3
)

// askedForBit says whether an operation asked for one of the bits it may ask for.
//
// @ pure
// @ decreases
// @ requires bit == dacRead || bit == dacWrite || bit == dacExec
// @ ensures res == (required & bit != 0)
func askedForBit(required int, bit int) (res bool) {
	return required&bit != 0
}

// triadGrantsBit is the half of the decision about identity: does the triad which applies
// to this session carry this bit of this mode.
//
// The order is the one Unix uses: if the session owns the file, the owner triad applies and
// nothing else is consulted - a file at 0o270 owned by you is writable by you and by nobody
// else, and belonging to its group does not hand you the group triad as well. Only when the
// session does not own the file does its membership of the file's group matter, and only
// when it is in none of the file's groups does the triad for everybody apply.
//
// @ pure
// @ decreases
// @ requires 0 <= mode
// @ requires bit == dacRead || bit == dacWrite || bit == dacExec
// @ ensures res == (ownerMatch ? ((mode >> ownerTriadShift) & bit != 0) : (groupMember ? ((mode >> groupTriadShift) & bit != 0) : (mode & bit != 0)))
func triadGrantsBit(mode int, ownerMatch bool, groupMember bool, bit int) (res bool) {
	return (ownerMatch && (mode>>ownerTriadShift)&bit != 0) ||
		(!ownerMatch && groupMember && (mode>>groupTriadShift)&bit != 0) ||
		(!ownerMatch && !groupMember && mode&bit != 0)
}

// accessIsAllowed is the decision: what the file's permission bits are, whether the session
// owns the file, whether the session is in the group which owns it, and what the operation
// needs. It holds exactly when the applicable triad carries every bit asked for.
//
// @ pure
// @ decreases
// @ requires 0 <= mode
// @ ensures res == ((!askedForBit(required, dacRead) || triadGrantsBit(mode, ownerMatch, groupMember, dacRead)) && (!askedForBit(required, dacWrite) || triadGrantsBit(mode, ownerMatch, groupMember, dacWrite)) && (!askedForBit(required, dacExec) || triadGrantsBit(mode, ownerMatch, groupMember, dacExec)))
// @ ensures !askedForBit(required, dacRead) && !askedForBit(required, dacWrite) && !askedForBit(required, dacExec) ==> res
func accessIsAllowed(mode int, ownerMatch bool, groupMember bool, required int) (res bool) {
	return (!askedForBit(required, dacRead) || triadGrantsBit(mode, ownerMatch, groupMember, dacRead)) &&
		(!askedForBit(required, dacWrite) || triadGrantsBit(mode, ownerMatch, groupMember, dacWrite)) &&
		(!askedForBit(required, dacExec) || triadGrantsBit(mode, ownerMatch, groupMember, dacExec))
}

// triadOf is the switch form of the same decision - which triad of a mode applies. It is
// plain Go, not verified, because a Gobra pure function cannot branch: what a reader looks
// at is here, and what is proved is the predicates above, which
// TestConformanceTriadSelectionAgrees holds equal to this over all 512 modes and all four
// combinations of the two identity facts.
func triadOf(mode int, ownerMatch bool, groupMember bool) int {
	switch {
	case ownerMatch:
		return (mode >> ownerTriadShift) & dacTriadMask
	case groupMember:
		return (mode >> groupTriadShift) & dacTriadMask
	default:
		return mode & dacTriadMask
	}
}

// askedForBitsWithin is the subset relation over requests: whatever an operation needing
// `less` requires, an operation needing `asked` also requires.
//
// It is written bit by bit rather than as `less & ^asked == 0` because Gobra v26.09 does not
// discharge goals that mix bitwise-and with bitwise-not over unbounded integers: the
// characterisation is the same, and TestConformanceAskedForBitsWithinIsTheSubsetRelation
// keeps this equal to the bit formula for every pair of requests up to eight bits.
//
// @ pure
// @ decreases
// @ ensures res == ((!askedForBit(less, dacRead) || askedForBit(asked, dacRead)) && (!askedForBit(less, dacWrite) || askedForBit(asked, dacWrite)) && (!askedForBit(less, dacExec) || askedForBit(asked, dacExec)))
func askedForBitsWithin(less int, asked int) (res bool) {
	return (!askedForBit(less, dacRead) || askedForBit(asked, dacRead)) &&
		(!askedForBit(less, dacWrite) || askedForBit(asked, dacWrite)) &&
		(!askedForBit(less, dacExec) || askedForBit(asked, dacExec))
}

// aGrantIsTheConjunctionOfItsBits: an operation asking for a set of bits is granted exactly
// when each bit in the set is granted on its own. No bit is granted because another was
// asked for alongside it, and no combination is treated specially - which is what makes it
// safe for the twelve call sites to ask for seven different combinations of bits, none of
// which was ever enumerated.
//
// @ pure
// @ decreases
// @ requires 0 <= mode
// @ ensures res == (accessIsAllowed(mode, ownerMatch, groupMember, asked1|asked2) == (accessIsAllowed(mode, ownerMatch, groupMember, asked1) && accessIsAllowed(mode, ownerMatch, groupMember, asked2)))
func aGrantIsTheConjunctionOfItsBits(mode int, ownerMatch bool, groupMember bool, asked1 int, asked2 int) (res bool) {
	return accessIsAllowed(mode, ownerMatch, groupMember, asked1|asked2) ==
		(accessIsAllowed(mode, ownerMatch, groupMember, asked1) &&
			accessIsAllowed(mode, ownerMatch, groupMember, asked2))
}

// aSmallerRequestNeverHurts: whatever a session may do, it may also do anything needing
// less. Read-and-write access to a file always includes reading it, so a request narrowed
// to a subset of its bits is never the reason an operation is refused.
//
// @ pure
// @ decreases
// @ requires 0 <= mode
// @ requires askedForBitsWithin(less, asked)
// @ ensures accessIsAllowed(mode, ownerMatch, groupMember, asked) ==> accessIsAllowed(mode, ownerMatch, groupMember, less)
func aSmallerRequestNeverHurts(mode int, ownerMatch bool, groupMember bool, asked int, less int) (res bool) {
	return !accessIsAllowed(mode, ownerMatch, groupMember, asked) ||
		accessIsAllowed(mode, ownerMatch, groupMember, less)
}

// theBitsAboveTheNineAreInvisible is not proved here, and the reason is worth writing down
// because it is the first time this programme has met it: Gobra v26.09 reasons about `&` and
// `>>` well enough to check a decision *written with them*, but not well enough to compare two
// decisions whose arguments differ in a bit above the nine it looks at. Every formulation it
// was given - `mode | 0o10000`, `mode + 0o10000`, a masked right-hand side - stalled on the
// same obligation, `0 <= mode`, which the callee demands of its argument and which v26.09
// would not derive from `0 <= mode` and an addition. What is claimed instead is exhausted in
// Go (TestConformanceOnlyTheNinePermissionBitsMatter): every mode from 0 to 0o7777, including
// the file-type and setuid bits st.Mode carries, both identity facts, every request - 73 728
// cases, which for a finite domain of this size is the complete argument anyway.
//
// The claim itself matters: the setuid, setgid and sticky bits, and the file type which shares
// the word with them, neither grant anything nor withhold anything. A file at 0o4755 behaves
// like one at 0o755 for this decision, and a directory is not a file.

// anOperationAskingAMissingBitIsRefused: whatever else the triad carries, an operation
// which asks for a bit the applicable triad does not carry is refused. This is the whole
// reason a file at 0o644 cannot be appended to by a non-owner, and there is no later stage
// which reconsiders the request once the triad has refused it.
//
// The three bits are named rather than passed as a parameter, and the statement is not
// annotated: the proof has to know that a request for a bit asks for that bit, and v26.09
// will not derive `bit & bit != 0` either for a parameter constrained to three values or for
// the concrete constants. TestConformanceAMissingBitRefusesTheOperation checks all three for
// every mode and both identity facts. The only annotation is the one the callees demand.
//
// @ requires 0 <= mode
func anOperationAskingAMissingBitIsRefused(mode int, ownerMatch bool, groupMember bool) bool {
	// "if the triad does not carry the bit, asking for it is refused": grants || !allowed. The
	// first draft of this read !grants || !allowed, which says the opposite for a bit the triad
	// does carry - and TestConformanceAMissingBitRefusesTheOperation found it on mode 0o001, where
	// execute is present and the misreading claimed a refusal.
	return (triadGrantsBit(mode, ownerMatch, groupMember, dacRead) || !accessIsAllowed(mode, ownerMatch, groupMember, dacRead)) &&
		(triadGrantsBit(mode, ownerMatch, groupMember, dacWrite) || !accessIsAllowed(mode, ownerMatch, groupMember, dacWrite)) &&
		(triadGrantsBit(mode, ownerMatch, groupMember, dacExec) || !accessIsAllowed(mode, ownerMatch, groupMember, dacExec))
}

// theOwnerTriadIsTheOnlyOneConsulted: when the session owns the file, group membership
// cannot change the answer, because the owner triad is asked first and its answer is final.
// A server which decided this the other way round would let a user write files the user owns
// only when they happened to be in the file's group - and would hand group members access to
// a file whose owner triad says otherwise.
//
// @ pure
// @ decreases
// @ requires 0 <= mode
// @ ensures accessIsAllowed(mode, true, true, required) == accessIsAllowed(mode, true, false, required)
func theOwnerTriadIsTheOnlyOneConsulted(mode int, required int) (res bool) {
	return accessIsAllowed(mode, true, true, required) == accessIsAllowed(mode, true, false, required)
}

// nobodyIsSuperuserHere: the decision knows only whether the session owns the file, so no
// uid value - not 0 - carries a privilege of its own. Renaming both accounts, or turning the
// pair into root and a file owned by root, cannot change the answer as long as the ownership
// relation between them is the same.
//
// The kernel would let root read anything; this emulation asks the triad anyway. Where the
// server process runs as root it therefore refuses more often than the kernel would, which
// is recorded as a deviation rather than a hole: the emulation can deny an access the kernel
// would have granted, it cannot invent one the kernel would have denied.
//
// @ pure
// @ decreases
// @ requires 0 <= mode
// @ requires (uid == sessionUID) == (otherUID == otherSessionUID)
// @ ensures accessIsAllowed(mode, uid == sessionUID, groupMember, required) == accessIsAllowed(mode, otherUID == otherSessionUID, groupMember, required)
func nobodyIsSuperuserHere(mode int, uid int, sessionUID int, otherUID int, otherSessionUID int, groupMember bool, required int) (res bool) {
	return accessIsAllowed(mode, uid == sessionUID, groupMember, required) ==
		accessIsAllowed(mode, otherUID == otherSessionUID, groupMember, required)
}

// aRefusalNamesTheBitItMissed: when an operation is refused, at least one of the bits it
// asked for is missing from the applicable triad - and every missing asked-for bit is a
// sufficient reason on its own. The three tests return the same error to the client, as
// access(2) does, so the reason is not on the wire; it is checkable here, which is what stops
// a refusal from becoming a mystery that somebody eventually "fixes" by granting the whole
// request because one bit looked wrong.
//
// @ pure
// @ decreases
// @ requires 0 <= mode
// @ ensures res == (!accessIsAllowed(mode, ownerMatch, groupMember, required) == ((askedForBit(required, dacRead) && !triadGrantsBit(mode, ownerMatch, groupMember, dacRead)) || (askedForBit(required, dacWrite) && !triadGrantsBit(mode, ownerMatch, groupMember, dacWrite)) || (askedForBit(required, dacExec) && !triadGrantsBit(mode, ownerMatch, groupMember, dacExec))))
func aRefusalNamesTheBitItMissed(mode int, ownerMatch bool, groupMember bool, required int) (res bool) {
	return !accessIsAllowed(mode, ownerMatch, groupMember, required) ==
		((askedForBit(required, dacRead) && !triadGrantsBit(mode, ownerMatch, groupMember, dacRead)) ||
			(askedForBit(required, dacWrite) && !triadGrantsBit(mode, ownerMatch, groupMember, dacWrite)) ||
			(askedForBit(required, dacExec) && !triadGrantsBit(mode, ownerMatch, groupMember, dacExec)))
}

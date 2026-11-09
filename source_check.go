package ssh3

// This file holds the decision underneath the source-address restriction (the
// "from=" identity option), separated from the code that turns a decision into
// an error message, and Gobra verifies it in place: the annotations below are
// comments in the file the compiler builds, so the code that runs is the code
// the proof talks about.
//
// Two boundaries decide what is in this file and what stays in
// identity_options.go, and both are the prover's rather than the code's. The
// first is `fmt`: Gobra v26.09 has no specs for it ("We do not support members
// defined in this package"), so a function that builds its own error values
// cannot be verified at all, which is why CheckSource keeps only the messages.
// The second is `net`: its shipped stubs do carry ParseIP, ParseCIDR, IP.Equal
// and IP.String, but each of them demands the address as an ownership predicate
// (len(ip) == 4 || len(ip) == 16 && forall i :: acc(&ip[i])), which is a fact
// about a value that came out of ParseIP rather than about a pattern, and
// net.SplitHostPort has no stub at all. So rather than restate the address model
// here, the parsing and the pattern matching stay where they have always been,
// and what is proved is the rule that combines their answers - which is where
// "an exclusion beats an inclusion", "nothing matching is not accepted" and
// "a restriction with an undecidable address refuses" live, together with the
// one helper that decides whether a pattern is an exclusion at all. That rule is
// the part a reader argues about; the byte-level address work is not.
//
// "Writing!": there is no helper for stripping the "!" even though the rule
// would read better with one. A pure function must have a single `return` of a
// pure expression, and "drop the leading ! if there is one" needs a branch, so
// strings.TrimPrefix stays on the message side and TestConformanceNegationHelpers
// pins the two readings together instead.

// isNegated reports whether a "from=" pattern is an exclusion, i.e. written
// "!pattern". It is strings.HasPrefix(pattern, "!"), named and specified so that
// a proof can talk about it, and the shipped loop calls this rather than the
// strings method so that "which patterns are exclusions" means what is proved;
// TestConformanceNegationHelpers keeps the two readings equal.
//
// @ pure
// @ decreases
// @ ensures res == (len(pattern) > 0 && pattern[0] == '!')
func isNegated(pattern string) (res bool) {
	return len(pattern) > 0 && pattern[0] == '!'
}

// sourceVerdict is the outcome of a source-address check, before it becomes an
// error message. The four cases are the four messages CheckSource can return,
// in the order the check considers them.
type sourceVerdict int

const (
	// sourcePermitted means the connection may proceed.
	sourcePermitted sourceVerdict = iota
	// sourceRefusedNoAddress means a restriction exists but the peer address
	// carries no usable IP: the check fails closed rather than matching
	// against a placeholder.
	sourceRefusedNoAddress
	// sourceRefusedExcluded means an exclusion pattern ("!10.0.0.0/8")
	// matched, which wins over any inclusion.
	sourceRefusedExcluded
	// sourceRefusedNotListed means nothing excluded it, but nothing accepted
	// it either.
	sourceRefusedNotListed
)

// negatedMatch says whether, from position i onwards, some exclusion pattern
// matched. It is stated as a recursion over the index because the alternative -
// writing "exists k :: negated[k] && matched[k]" in the contract of an ordinary
// function - is a permission claim about the caller's array, and Gobra will not
// let a contract make one: slice elements are heap, so even a pure function has
// to be told it may read them, and an impure caller then cannot *hand over* the
// quantified permission it holds (a Silicon limitation with quantified
// permissions, reported here as "Precondition of call might not hold. Permission
// to negated[i] might not suffice"). Hence the split this file makes: the two
// predicates below are pure, take the arrays, and ask for the reads they need;
// the rule underneath the check takes the answers as plain bools and is proved
// without touching a heap at all. The recursion measure is the index, which is
// the same shape glob.go had to adopt for strings.
//
// @ pure
// @ decreases len(negated) - i
// @ requires 0 <= i
// @ requires len(negated) == len(matched)
// @ requires (forall i int :: 0 <= i && i < len(negated) ==> acc(&negated[i]))
// @ requires (forall i int :: 0 <= i && i < len(matched) ==> acc(&matched[i]))
// @ ensures res ==> i < len(negated)
func negatedMatch(negated []bool, matched []bool, i int) (res bool) {
	return i < len(negated) && (negated[i] && matched[i] || negatedMatch(negated, matched, i+1))
}

// inclusionMatch says whether, from position i onwards, some pattern that is not
// an exclusion matched.
//
// @ pure
// @ decreases len(matched) - i
// @ requires 0 <= i
// @ requires len(negated) == len(matched)
// @ requires (forall i int :: 0 <= i && i < len(negated) ==> acc(&negated[i]))
// @ requires (forall i int :: 0 <= i && i < len(matched) ==> acc(&matched[i]))
// @ ensures res ==> i < len(matched)
func inclusionMatch(negated []bool, matched []bool, i int) (res bool) {
	return i < len(matched) && (matched[i] && !negated[i] || inclusionMatch(negated, matched, i+1))
}

// sourceVerdictFor is the decision of a source restriction, given whether one
// exists, whether the peer address could be read at all, whether some exclusion
// pattern matched and whether some inclusion pattern matched - the four facts
// CheckSource collects, in that order of precedence. This is where "an exclusion
// beats an inclusion", "nothing matching is not accepted" and "a restriction with
// no decidable address refuses" live, and they are proved here on the shipped
// code rather than only in the proof/sourcecheck model, which
// TestConformanceSourceVerdictMatchesModel keeps equal to it.
//
// Every clause is bidirectional, so the verdict is not merely sound (each refusal
// has a reason behind it) but exact: the four outcomes partition the four inputs,
// and no case can drift into another without breaking a proof. Note the
// precedence the shape encodes: `!addressKnown` is asked before either match, so
// an address that cannot be parsed refuses even when nothing matched it, which is
// the fail-closed clause of SR-PERM-06.
//
// @ ensures !hasRestriction ==> res == sourcePermitted
// @ ensures hasRestriction && !addressKnown ==> res == sourceRefusedNoAddress
// @ ensures (res == sourceRefusedNoAddress) ==> (hasRestriction && !addressKnown)
// @ ensures (hasRestriction && addressKnown && excluded) ==> res == sourceRefusedExcluded
// @ ensures (res == sourceRefusedExcluded) ==> (hasRestriction && addressKnown && excluded)
// @ ensures (hasRestriction && addressKnown && !excluded && listed) ==> res == sourcePermitted
// @ ensures hasRestriction && (res == sourcePermitted) ==> (addressKnown && !excluded && listed)
// @ ensures (hasRestriction && addressKnown && !excluded && !listed) ==> res == sourceRefusedNotListed
// @ ensures (res == sourceRefusedNotListed) ==> (hasRestriction && addressKnown && !excluded && !listed)
func sourceVerdictFor(hasRestriction bool, addressKnown bool, excluded bool, listed bool) (res sourceVerdict) {
	if !hasRestriction {
		return sourcePermitted
	}
	if !addressKnown {
		return sourceRefusedNoAddress
	}
	if excluded {
		return sourceRefusedExcluded
	}
	if listed {
		return sourcePermitted
	}
	return sourceRefusedNotListed
}

package ssh3

// This file is the "from=" pattern matcher, and it is the first piece of *shipped* sshoq code --
// not a model of it -- that Gobra verifies: the annotations below are comments in the file the
// compiler builds, so the code that runs in production is the code the proof talks about. Moving
// the function out of identity_options.go is what made that possible: Gobra v26.09 ships stubs for
// `strings` and `net` but explicitly no members for `fmt` (.proof-tools/src/gobra/
// src/main/resources/stubs/fmt/fmt.gobra: "We do not support members defined in this package"), and
// identity_options.go builds errors with fmt.Errorf. A file whose logic is pure Go can be verified
// where it lives; a file that formats errors cannot be verified until the formatting is separated
// from the decision. That separation is the practical shape of the roadmap's phase 3.
//
// What is proved here, on the code that ships: SR-PERM-07's *termination* clause -- which matters on
// its own, because the matcher runs on `from=`, an attacker-influenced pattern that arrives with the
// identity line, and the recursion this function replaced was exponential in the number of stars
// (finding F5) -- and two endpoint facts. What is *not* proved here, and cannot be in this toolchain,
// is the equivalence with the declarative `globMatch` below: the step that needs induction ("every
// star earlier than the saved one has already been shown not to help at any longer stretch of the
// text"), and induction over `string` is exactly what Silicon lacks -- it has one over inductive
// datatypes, which is how proof/glob discharges the same claim over its own list model. The meaning
// therefore reaches the shipped function through identity_options_source_conformance_test.go, which
// compares this implementation against the recursion it replaced and against a second linear matcher
// over every short pattern and text, stars included. proof/README.md says which line is which.

// globMatch is the meaning of a glob, stated without an algorithm: '*' stands for any sequence of
// characters (including none), '?' for exactly one character, and anything else for itself. The two
// indices say how much of each string is still to be explained.
//
// The recursion is over the indices, not over the strings: Gobra proves a measure for that
// (termination is checked) and reasons about single steps of it --
// globMatch(pattern, text, pi+1, ti+1) unfolds -- but a claim that needs the recursion carried to a
// length that depends on its input stays out of reach, as does the equivalence with matchGlob.
// It is kept because the endpoint facts below and the tests refer to the same meaning, and because
// stating the meaning apart from the algorithm is the point of the exercise.
//
// @ pure
// @ decreases len(text) - ti, len(pattern) - pi
// @ requires 0 <= pi && pi <= len(pattern) && 0 <= ti && ti <= len(text)
//
//nolint:unused // the specification is used by proofs, not by the runtime
func globMatch(pattern string, text string, pi int, ti int) (res bool) {
	// the star either stands for nothing here, or it swallows one character and is asked again;
	// once the pattern is used up the text has to be used up too
	return pi == len(pattern) && ti == len(text) ||
		pi < len(pattern) && pattern[pi] == '*' &&
			(globMatch(pattern, text, pi+1, ti) ||
				ti < len(text) && globMatch(pattern, text, pi, ti+1)) ||
		pi < len(pattern) && pattern[pi] != '*' && ti < len(text) &&
			(pattern[pi] == '?' || pattern[pi] == text[ti]) &&
			globMatch(pattern, text, pi+1, ti+1)
}

// isSingleStar is the pattern "*".
//
// @ pure
// @ decreases
//
//nolint:unused // the specification is used by proofs, not by the runtime
func isSingleStar(pattern string) (res bool) {
	return len(pattern) == 1 && pattern[0] == '*'
}

// matchGlob is OpenSSH's match_pattern(): "*" stands for any sequence, "?" for a single character.
// Every other character -- including "[" and "]", which OpenSSH would read as a character class --
// is itself. It is applied to the textual address only (never to the port and never to a hostname),
// which is what "from=" globs mean here.
//
// It runs in time linear in len(pattern)+len(text) and needs no stack beyond its own frame: both
// pointers only move forward, and the position of the most recent star is remembered so that the
// one place a match can fail is retried by letting that star swallow exactly one more character.
// That is the whole trick, and it is why this is not the recursive matcher it used to be: trying
// every split of the text among the stars costs time exponential in the number of stars, and the
// pattern here is `from=`, an option that arrives with the identity while the text is the peer
// address. Measured on the old recursion, ten stars against an eighty character text took 4.9s and
// fourteen took 2m56s (finding F5 in proof/SECURITY_REQUIREMENTS.md).
//
// identity_options_source_conformance_test.go is what makes the change of algorithm not a change of
// meaning: it keeps the old recursion next to this one and compares all three implementations -- the
// old recursion, a second linear matcher written differently, and this -- over every pattern of up
// to four characters from {a, b, *, ?, [, .} and every text of up to four from {a, b, ., *}, which is
// 530 255 triples, stars in the text included since finding F6.
//
// What the annotations prove about *this* implementation:
//
// What the annotations prove about *this* implementation, as shipped:
//
//   - it terminates, on a measure that does not depend on the pattern's shape: the loop's two
//     components count the retries still available (len(text) minus the retry position) and, within
//     one retry, the pattern characters still to be consumed; the function's measure bounds them
//     both. Nothing here is exponential, and that is now a theorem rather than a reading of the code
//     (SR-PERM-07).
//   - an empty pattern matches exactly the empty text;
//   - the pattern "*" matches every text.
//
// Two facts that belong to the same list are *not* annotated, because the prover cannot take the
// step: that an empty text matches exactly the all-star patterns (that needs noWildcardsFrom-style
// unfolding to a depth equal to the pattern length) and that a wildcard-free pattern matches only the
// text equal to it (that needs a prefix invariant, and Gobra has no decision procedure for string
// slices: even a[0:0] == b[0:0] is not provable, and there is no extensionality axiom). Both are
// covered by the three-implementation agreement, and both are in proof/glob over a list model where
// foldDown supplies the induction.
//
// @ decreases len(text) * (len(pattern) + 1)
// @ ensures len(pattern) == 0 ==> res == (len(text) == 0)
// @ ensures isSingleStar(pattern) ==> res
func matchGlob(pattern, text string) (res bool) {
	p, t := 0, 0
	star, retryFrom := -1, 0
	// the pointers stay inside their strings; the retry position is inside the text and, while no
	// star has been seen, is still zero; and the saved star is a real index when it is not -1
	// @ invariant 0 <= p && p <= len(pattern) && 0 <= t && t <= len(text)
	// @ invariant 0 <= retryFrom && retryFrom <= len(text)
	// @ invariant star == -1 || 0 <= star && star < len(pattern)
	// @ invariant star == -1 ==> retryFrom == 0
	// @ invariant star == -1 || retryFrom <= t
	// an iteration that completes has consumed something, so with an empty text nothing has moved at
	// all: this is what makes the empty-pattern postcondition provable from the loop
	// @ invariant p == 0 && star == -1 ==> t == 0
	// the shape of the loop for the one pattern the postconditions talk about completely: with the
	// pattern "*", the first iteration saves the star and from then on p is at the end of the pattern
	// and the retry position is where the text has been read to
	// @ invariant isSingleStar(pattern) ==> (p == 0 && star == -1 || p == 1 && star == 0 && retryFrom == t)
	// one retry consumes a character of the text, and inside one retry only consumption moves p:
	// together the measure above strictly decreases
	// @ decreases (len(text) - retryFrom) * (len(pattern) + 1) + (len(pattern) - p)
	for t < len(text) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			// a star stands for anything: remember where it is, and if the rest of the pattern
			// fails, let this star swallow one more character and try the tail again.
			//
			// This case must come first. A "*" in the *text* is an ordinary character, but it is
			// also equal to the "*" in the pattern, so a case that tried literal equality first
			// would consume the star as a literal and never save it -- and if the rest of the
			// pattern then failed there would be nothing to retry against. That was finding F6:
			// matchGlob("a*", "a*b") returned false, where OpenSSH's match_pattern() and the
			// recursion this function replaced both return true. The three-implementation
			// agreement did not see it because the texts it tried contained no star.
			star = p
			retryFrom = t
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == text[t]):
			p++
			t++
		case star >= 0:
			p = star + 1
			retryFrom++
			t = retryFrom
		default:
			return false
		}
	}
	// only stars may be left over, since each of them can stand for nothing
	// @ invariant 0 <= p && p <= len(pattern)
	// @ decreases len(pattern) - p
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

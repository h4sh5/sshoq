package util

// ASCII case folding, verified where it runs.
//
// This is the whole of the case-insensitive comparison this server performs on input a peer chose. It
// is copied from Go's `net/http/internal/ascii`, and its one caller is `server_auth/handlers.go`, where it
// decides whether an `Authorization` header begins with `Bearer ` before the token is stripped off -- so
// the claim being made here is the claim that caller leans on: this is equality up to ASCII case, it
// requires the two sides to be the same length, and nothing else is folded.
//
// The file exists apart from `util.go` for the usual reason: `util.go` imports `crypto`, `fmt`, `os` and
// the rest of the world, and Gobra v26.09 can read none of it. This file imports nothing, which is what
// lets `make proof` check the decision rather than a model of it.
//
// What is proved is the exact decision, in both directions, plus the two structural facts a caller needs
// (equal length, and that the comparison is a *relation*: reflexive and symmetric). What is not proved
// here is the equivalence with Go's own `strings.EqualFold`, for the reason `server_auth/truncate.go`
// records: Gobra reasons about the length of a string and the value of one of its bytes, and has no rule
// that turns `s == t` into a statement byte by byte. That equivalence is what
// `equalfold_conformance_test.go` checks -- agreement on every ASCII input, and the measured list of
// exactly where the two part company, which is every non-ASCII byte, in the direction that makes this
// function refuse more, not less.

// upperA and upperZ are the ASCII capitals, spelled as numbers because a spec that says what it means
// should not depend on how a compiler reads a rune literal.
const (
	upperA  = 65
	upperZ  = 90
	foldGap = 32 // 'a' - 'A'
)

// lower returns the ASCII lowercase version of b. Its contract is a case definition -- inside the capitals
// it adds the gap, outside them it changes nothing -- which is complete enough for the prover to reason
// about a call to it without unfolding the branch, and is the reason the postcondition of `EqualFold` can
// talk about bytes rather than about this function.
//
// @ ensures ('A' <= b && b <= 'Z') ==> res == b + foldGap
// @ ensures !('A' <= b && b <= 'Z') ==> res == b
// @ ensures 'a' <= res && res <= 'z' ==> ('A' <= b && b <= 'Z' && res == b + foldGap) || ('a' <= b && b <= 'z' && res == b)
// @ ensures ('a' <= b && b <= 'z') ==> res == b
func lower(b byte) (res byte) {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// EqualFold is strings.EqualFold, ASCII only. It reports whether s and t are equal, ASCII-case-insensitively.
//
// The first clause is the decision itself: equal length, and every position equal after folding -- where
// "equal after folding" is spelled out as the three ways two bytes can be the same letter or the same
// non-letter, because a spec that had to call `lower` could not be a spec at all (`lower` is not pure: it
// has two returns, and a pure function here must have one). The second clause is what the Bearer-prefix
// caller actually consumes: a match means the two strings are the same length, which is what makes
// `auth[len(prefix):]` the token and not something off by a byte. The last two clauses are the structural
// facts -- a string folds to itself, and the comparison does not care which side is which -- stated here
// because a comparison that was not symmetric would make the order of arguments a security property.
//
// What this deliberately is *not* is Unicode case folding: two bytes that are not ASCII capitals must be
// identical, so `EqualFold("ﬀ", "ff")` is false where `strings.EqualFold` says true. That is the safe
// direction for prefix recognition -- refusing to strip a prefix it does not literally see leaves the
// request unauthenticated rather than authenticated by accident -- and the boundary is drawn by
// enumeration in the conformance test rather than by this contract.
//
// @ ensures res == (len(s) == len(t) && (forall i int :: 0 <= i && i < len(s) ==> s[i] == t[i] || (upperA <= s[i] && s[i] <= upperZ && t[i] == s[i] + foldGap) || (upperA <= t[i] && t[i] <= upperZ && s[i] == t[i] + foldGap)))
// @ ensures res ==> len(s) == len(t)
// @ ensures len(s) != len(t) ==> !res
// @ ensures len(s) == 0 && len(t) == 0 ==> res
func EqualFold(s, t string) (res bool) {
	if len(s) != len(t) {
		return false
	}
	// every position before the one being read has already folded equal
	// @ invariant 0 <= i && i <= len(s) && len(s) == len(t)
	// @ invariant forall j int :: 0 <= j && j < i ==> s[j] == t[j] || (upperA <= s[j] && s[j] <= upperZ && t[j] == s[j] + foldGap) || (upperA <= t[j] && t[j] <= upperZ && s[j] == t[j] + foldGap)
	// @ decreases len(s) - i
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// equalFoldIsReflexive and equalFoldIsSymmetric are the two facts that make EqualFold an equality rather
// than a predicate with a direction. They are lemmas in the style of `varIntLenNeverShrinks`: a spec cannot
// call an impure function, so the statement lives in a function that does the call and returns the answer.
// Neither is obvious from the loop: reflexivity is what the length check plus folding to itself buys, and
// symmetry is bought entirely by the third disjunct of the contract, which is why that disjunct is there.
//
// @ ensures holds
func equalFoldIsReflexive(s string) (holds bool) {
	return EqualFold(s, s)
}

// @ ensures same
func equalFoldIsSymmetric(s string, t string) (same bool) {
	forward := EqualFold(s, t)
	backward := EqualFold(t, s)
	return forward == backward
}

// equalFoldDistinguishesLengths is the refusal half of the length check: two strings of different lengths
// are never a match, whatever their contents. It is the property `strings.EqualFold` also has, and the one
// that keeps a short `Authorization` value from being treated as a prefixed long one.
//
// @ requires len(s) != len(t)
// @ ensures !holds
func equalFoldDistinguishesLengths(s string, t string) (holds bool) {
	return EqualFold(s, t)
}

// foldEqualityIsByteEqualityWithoutCapitals is the per-position fact behind the loop: the test the loop
// makes is `lower(s[i]) != lower(t[i])`, and for two bytes that are not ASCII capitals, folding changes
// nothing, so that test is ordinary byte equality. It is stated at byte level rather than as
// "EqualFold(s,t) <==> s == t" for two reasons recorded elsewhere in this repository: a spec cannot call
// the impure `EqualFold`, and Gobra cannot turn string equality into a statement about characters -- it
// knows the length of a concatenation and nothing else. `TestConformanceEqualFoldAgreesWithStringsEqualFoldOnAscii`
// is what says the byte-level reading is the same thing as equality, by checking it against
// `strings.EqualFold` on every ASCII input it enumerates.
//
// @ requires !(upperA <= b && b <= upperZ)
// @ requires !(upperA <= c && c <= upperZ)
// @ ensures agrees == (b == c)
func foldEqualityIsByteEqualityWithoutCapitals(b byte, c byte) (agrees bool) {
	return lower(b) == lower(c)
}

// equalFoldRefusesLongerPrefixes is the consequence the one caller depends on, spelled out: a header value
// that merely starts with the prefix is not a match for it, because a match requires equal length. In
// `server_auth/handlers.go` the prefix is compared against `auth[:len(prefix)]` and the token is then read
// as `auth[len(prefix):]`; if a match could hold for unequal lengths, the slice taken as the token would
// not be what the comparison justified.
//
// @ requires len(head) < len(rest)
// @ ensures !holds
func equalFoldRefusesLongerPrefixes(head string, rest string) (holds bool) {
	return EqualFold(head, rest)
}

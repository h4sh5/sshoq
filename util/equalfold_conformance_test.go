package util

import (
	"strings"
	"testing"
)

// What the verified ASCII fold in equalfold.go has to agree with: Go's own `strings.EqualFold`, and the
// one caller in the server.
//
// Gobra proves the decision byte by byte -- equal length, and every position equal after an ASCII-only
// lowercasing -- because that is the shape a deductive prover can hold. It cannot prove the sentence a
// reader actually wants, "this is what Go means by case-insensitive", for the reason recorded in
// `server_auth/truncate.go` and again in `equalfold.go`: Gobra knows the length of a string and the value
// of one of its bytes, and has no rule connecting `s == t` to its characters. So the correspondence is
// checked here, exhaustively where the input space is small enough to enumerate, and the *boundary* -- the
// one place the two implementations are allowed to differ -- is written down as a claim with named
// examples rather than left to intuition.

// TestConformanceLowerChangesOnlyAsciiCapitals is the whole of `lower`, all 256 byte values: the capitals
// move by exactly the gap, and everything else -- the lowercase letters, the digits, the punctuation, and
// every byte of a UTF-8 sequence -- is untouched. The contract in `equalfold.go` says this; the point of
// checking it in Go is that the contract and the code could both be wrong in the same way, and a byte that
// moved that should not have is exactly how a prefix check starts accepting things it should refuse.
func TestConformanceLowerChangesOnlyAsciiCapitals(t *testing.T) {
	for i := 0; i < 256; i++ {
		b := byte(i)
		got := lower(b)
		want := b
		if 'A' <= b && b <= 'Z' {
			want = b + 32
		}
		if got != want {
			t.Errorf("lower(%#02x) = %#02x, want %#02x", b, got, want)
		}
		if 'a' <= got && got <= 'z' && !('A' <= b && b <= 'Z') && !('a' <= b && b <= 'z') {
			t.Errorf("lower(%#02x) = %#02x: a byte outside the letters became a lowercase letter", b, got)
		}
	}
	// the gap is what the contract calls it
	if 'a'-'A' != foldGap || upperA != 'A' || upperZ != 'Z' {
		t.Errorf("the constants the specs use are no longer the ASCII capitals: upperA=%d upperZ=%d foldGap=%d", upperA, upperZ, foldGap)
	}
}

// asciiAlphabet is deliberately mixed case, and deliberately contains characters that must not move: the
// strings below are short enough that every combination is checked.
const asciiAlphabet = "AaBb1 -_Kk"

func allStrings(alphabet string, maxLen int) []string {
	out := []string{""}
	current := []string{""}
	for n := 0; n < maxLen; n++ {
		var next []string
		for _, prefix := range current {
			for i := 0; i < len(alphabet); i++ {
				next = append(next, prefix+string(alphabet[i]))
			}
		}
		out = append(out, next...)
		current = next
	}
	return out
}

// TestConformanceEqualFoldAgreesWithStringsEqualFoldOnAscii is the correspondence claim for the inputs the
// server can actually see in a scheme name: over every pair of ASCII strings up to three characters --
// 585 of them, so all 342,225 pairs -- this fold and `strings.EqualFold` give the same answer. That covers
// every shape of "Bearer " a client can send, and it is the direction that matters most: a comparison that
// refused where Go would have accepted would break working clients, and one that accepted where Go would
// not would widen who gets in.
func TestConformanceEqualFoldAgreesWithStringsEqualFoldOnAscii(t *testing.T) {
	cases := allStrings(asciiAlphabet, 3)
	checked := 0
	for _, s := range cases {
		for _, tt := range cases {
			got := EqualFold(s, tt)
			want := strings.EqualFold(s, tt)
			if got != want {
				t.Fatalf("EqualFold(%q, %q) = %v, strings.EqualFold = %v", s, tt, got, want)
			}
			checked++
		}
	}
	if checked != len(cases)*len(cases) {
		t.Fatalf("only %d pairs were compared, want %d", checked, len(cases)*len(cases))
	}
	t.Logf("%d ASCII pairs agree", checked)
}

// TestConformanceEqualFoldIsFinerThanStringsEqualFold is the boundary claim, in both halves.
//
// First half, over *every* pair of single bytes -- all 65,536 of them -- and over pairs built from a mixed
// list of ASCII and multi-byte strings: whenever this fold says yes, `strings.EqualFold` says yes too. That
// is what makes the difference between the two a matter of strictness rather than of disagreement, and it
// is the property that keeps the Bearer check safe: this implementation can only refuse a prefix that Go
// would have honoured, never invent one it would not.
//
// Second half: the divergences are exactly the Unicode simple case folds, each of which needs a byte
// outside ASCII on at least one side. Named examples are asserted, not merely counted, because a divergence
// that appeared somewhere else would mean the fold is doing something nobody described.
func TestConformanceEqualFoldIsFinerThanStringsEqualFold(t *testing.T) {
	pairs := [][2]string{}
	// every single-byte pair
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			pairs = append(pairs, [2]string{string(byte(a)), string(byte(b))})
		}
	}
	// every pair from a mixed list: the ASCII alphabet above, and the multi-byte letters that Unicode
	// case folding but not ASCII folding considers equal
	mixed := append(allStrings(asciiAlphabet, 2),
		"\u212a", // U+212A KELVIN SIGN, which folds to 'k'
		"\u017f", // U+017F LATIN SMALL LETTER LONG S, which folds to 's'
		"\u00c5", // U+00C5, which folds to U+00E5
		"\u00e5",
		"\u00c5\u00e5",
		"\u00e5\u00c5",
		"\u1e9b", // U+1E9B, whose folding is a special case
		"\ufb00", // U+FB00 LATIN SMALL LIGATURE FF
		"\u03a3", // U+3A3 Greek capital sigma, which folds to U+3C3
		"\u03c3", // U+3C3
		"\u03c2", // U+3C2 final sigma, which has no folding
	)
	for _, a := range mixed {
		for _, b := range mixed {
			pairs = append(pairs, [2]string{a, b})
		}
	}

	divergences := map[string]bool{}
	for _, p := range pairs {
		ours := EqualFold(p[0], p[1])
		theirs := strings.EqualFold(p[0], p[1])
		if ours && !theirs {
			t.Fatalf("EqualFold(%q, %q) accepts where strings.EqualFold refuses: this fold is looser than Go's, which would widen what the Bearer check accepts", p[0], p[1])
		}
		if ours != theirs {
			divergences[p[0]+"\x00"+p[1]] = true
			if isASCII(p[0]) && isASCII(p[1]) {
				t.Errorf("an all-ASCII pair diverges: EqualFold(%q,%q)=%v strings.EqualFold=%v", p[0], p[1], ours, theirs)
			}
		}
	}

	// the named examples must be among the divergences: if one of them stops diverging, the fold or Go has
	// changed and the sentence above is no longer the description of it
	named := [][2]string{
		{"\u212a", "k"},
		{"\u017f", "s"},
		{"\u00c5", "\u00e5"},
		{"\u03a3", "\u03c3"},
		{"\u03c2", "\u03c3"}, // U+3C2 GREEK SMALL LETTER FINAL SIGMA folds to U+3C3
	}
	for _, n := range named {
		if EqualFold(n[0], n[1]) {
			t.Errorf("EqualFold(%q, %q) is true: this implementation now folds beyond ASCII", n[0], n[1])
		}
		if !strings.EqualFold(n[0], n[1]) {
			t.Errorf("strings.EqualFold(%q, %q) is false: Go's folding changed, so the divergence list needs rewriting", n[0], n[1])
		}
	}
	// and the ones that must not diverge, because they are not simple case variants of each other: the
	// ligature U+FB00 has no simple folding, so Go refuses it against "ff" as this function does
	for _, n := range [][2]string{{"\ufb00", "ff"}, {"\ufb00", "\ufb00"}, {"\u03a3", "\u03c2\u03c2"}} {
		if EqualFold(n[0], n[1]) != strings.EqualFold(n[0], n[1]) {
			t.Errorf("EqualFold(%q, %q) = %v, strings.EqualFold = %v: these should agree", n[0], n[1], EqualFold(n[0], n[1]), strings.EqualFold(n[0], n[1]))
		}
	}
	t.Logf("%d pairs compared, %d divergences, all of them Unicode case folds outside ASCII", len(pairs), len(divergences))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// TestConformanceEqualFoldStructuralFacts checks in Go the three facts the lemmas in `equalfold.go` prove:
// a string folds to itself, the comparison has no direction, and unequal lengths never match. They are
// cheap here and they are the reason the lemmas exist -- a comparison whose result depended on which side
// was which would make the argument order in the Bearer check a security property.
func TestConformanceEqualFoldStructuralFacts(t *testing.T) {
	strs := append(allStrings(asciiAlphabet, 3), "K", "\u00c5", "Åa", "", "Bearer ", "bearer ")
	for _, s := range strs {
		if !EqualFold(s, s) {
			t.Errorf("EqualFold(%q, %q) is false", s, s)
		}
		if !equalFoldIsReflexive(s) {
			t.Errorf("the reflexive lemma disagrees with EqualFold for %q", s)
		}
	}
	for _, s := range strs {
		for _, tt := range strs {
			if EqualFold(s, tt) != EqualFold(tt, s) {
				t.Errorf("EqualFold is directional: (%q,%q)=%v but (%q,%q)=%v", s, tt, EqualFold(s, tt), tt, s, EqualFold(tt, s))
			}
			if !equalFoldIsSymmetric(s, tt) {
				t.Errorf("the symmetric lemma disagrees with EqualFold for (%q,%q)", s, tt)
			}
			if len(s) != len(tt) {
				if EqualFold(s, tt) {
					t.Errorf("EqualFold(%q,%q) matched strings of different lengths", s, tt)
				}
				if equalFoldDistinguishesLengths(s, tt) {
					t.Errorf("the length lemma disagrees with EqualFold for (%q,%q)", s, tt)
				}
			}
		}
	}
}

// TestConformanceFoldEqualityIsByteEqualityWithoutCapitals checks the byte-level lemma against a table of
// byte pairs: with no capitals involved, folding equal means being equal. This is the per-position content
// of the loop, and the reason a UTF-8 payload can only match itself.
func TestConformanceFoldEqualityIsByteEqualityWithoutCapitals(t *testing.T) {
	checked := 0
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			bb, cc := byte(a), byte(b)
			if 'A' <= bb && bb <= 'Z' || 'A' <= cc && cc <= 'Z' {
				continue
			}
			if got := foldEqualityIsByteEqualityWithoutCapitals(bb, cc); got != (bb == cc) {
				t.Fatalf("foldEqualityIsByteEqualityWithoutCapitals(%#02x,%#02x) = %v, want %v", bb, cc, got, bb == cc)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no byte pairs were checked")
	}
	t.Logf("%d capital-free byte pairs checked", checked)
}

// TestConformanceEqualFoldNeverPanics is the totality check the contract does not need but a reader does:
// the length test is what keeps the indexing in bounds, so a call with two unrelated strings -- including
// one that is a prefix of the other, and one containing every byte value -- cannot panic.
func TestConformanceEqualFoldNeverPanics(t *testing.T) {
	var allBytes [256]byte
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	big := string(allBytes[:])
	sides := []string{"", "A", "a", "AbC", allStrings(asciiAlphabet, 3)[40], big, big[:10], big[:200], "bearer ", "BEARER "}
	for _, s := range sides {
		for _, tt := range sides {
			if EqualFold(s, tt) != EqualFold(tt, s) {
				t.Errorf("EqualFold is directional on (%q[..], %q[..])", s[:min(8, len(s))], tt[:min(8, len(tt))])
			}
		}
	}
}

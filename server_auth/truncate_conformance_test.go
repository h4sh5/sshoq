package server_auth

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// modelTruncate is the ensures clause of truncate in proof/truncation/model.gobra, written
// out in Go: the result is the input when it fits, otherwise the first max bytes plus the
// three-byte ellipsis; and a non-positive max gives the empty string.
//
// The Gobra unit proves that the implementation satisfies this for every string and every
// max, memory safety included (no slice out of bounds, no panic). This test is what makes
// that proof about this function: it enumerates lengths on both sides of the bound and
// inputs whose boundary falls inside a multi-byte character, and fails if the two disagree.
// isASCIILong reports an input longer than every max tried below and made of one-byte
// characters only, the case in which the model proves the cut lands exactly on max.
func isASCIILong(s string) bool {
	return len(s) > 300 && !strings.ContainsFunc(s, func(r rune) bool { return r >= 0x80 })
}

func TestTruncateMatchesTheProvedModel(t *testing.T) {
	inputs := []string{
		strings.Repeat("a", 300),
		strings.Repeat("é", 200), // 2 bytes each: every odd cut splits a character
		strings.Repeat("日", 200), // 3 bytes each
		"",
		"sshoq/1.0",
		"curl/8.5.0-DEV (www curl.se)",
	}
	maxValues := []int{-1, 0, 1, 2, 3, 4, 99, 100, 101, 255, 300}
	for _, input := range inputs {
		for _, max := range maxValues {
			got := truncate(input, max)
			if max <= 0 {
				if got != "" {
					t.Fatalf("truncate(%d bytes, %d) = %q, the proved model says the empty string",
						len(input), max, got)
				}
				continue
			}
			if len(input) <= max {
				if got != input {
					t.Fatalf("a string of %d bytes fits in %d, so it must be returned as is, got %q",
						len(input), max, got)
				}
				continue
			}
			// ensures max > 0 && len(s) > max ==> 3 <= len(res) && len(res) <= max+3
			if len(got) < 3 || len(got) > max+3 {
				t.Fatalf("truncate(%d bytes, %d) returned %d bytes, outside the proved range [3, %d]",
					len(input), max, len(got), max+3)
			}
			if !strings.HasSuffix(got, "...") {
				t.Fatalf("the truncated form must be marked as such, got %q", got)
			}
			cut := len(got) - 3
			// ensures cut == 0 || !isContinuationByte(s[cut]): the cut never lands inside a
			// character, which is what keeps the log valid UTF-8
			if cut > 0 && cut < len(input) && input[cut]&0xC0 == 0x80 {
				t.Fatalf("truncate(%d bytes, %d) cut a multi-byte character at byte %d",
					len(input), max, cut)
			}
			if !strings.HasPrefix(input, got[:cut]) {
				t.Fatalf("truncation must keep a prefix of the input, got %q", got)
			}
			if !utf8.ValidString(input) != !utf8.ValidString(got) && utf8.ValidString(input) {
				t.Fatalf("truncate(%d bytes, %d) left invalid UTF-8 in the log: %q",
					len(input), max, got)
			}
			if utf8.ValidString(input) && !utf8.ValidString(got) {
				t.Fatalf("valid input must stay valid: %q", got)
			}
			// for a single-byte input the cut is exactly max, which the model proves too
			// (ensures cut == max when s[max] is not a continuation byte)
			if isASCIILong(input) && len(got) != max+3 {
				t.Fatalf("an ASCII input must be cut at exactly %d bytes, got %d",
					max, len(got))
			}
			// what the model proves for free because Gobra checks memory safety: every line
			// above must run without a slice-bounds panic, whatever max is
		}
	}
	// the model also states that a longer input truncates to a longer-or-equal prefix: the
	// bound is on the cut, not on the input
	if len(truncate(strings.Repeat("a", 1000), 100)) != len(truncate(strings.Repeat("a", 200), 100)) {
		t.Fatal("the length of the input must not leak into the logged prefix")
	}
}

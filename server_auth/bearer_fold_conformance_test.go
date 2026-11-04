package server_auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/h4sh5/sshoq/util"
)

// newConformanceRequestWithHeader builds a request carrying one Authorization header, including the empty
// one -- which HTTP itself treats as "no value", and which is why `BearerAuth` tests for it separately.
func newConformanceRequestWithHeader(header string) (*http.Request, error) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", header)
	return r, nil
}

func newConformanceRequestWithoutHeader() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/", nil)
}

// The one caller of the verified ASCII fold.
//
// `util/equalfold.go` proves, in place, what `util.EqualFold` decides: equal length, and every position
// equal after an ASCII-only lowercasing. This file is the seam -- it says that `ParseBearerAuth`, which is
// what actually decides whether an `Authorization` header carries a bearer token, uses that decision and
// nothing else, and that the byte arithmetic around it is the arithmetic the proof describes. The header
// value is entirely attacker-chosen, so this is the place where a fold that was looser than it looks would
// turn into somebody authenticating with a prefix they do not have.

const bearerPrefix = "Bearer "

func TestConformanceBearerPrefixUsesTheVerifiedFold(t *testing.T) {
	cases := []struct {
		header string
		token  string
		ok     bool
		why    string
	}{
		{"Bearer eyJhbGci", "eyJhbGci", true, "the spelling the format uses"},
		{"bearer eyJhbGci", "eyJhbGci", true, "all lowercase, which is why the comparison folds"},
		{"BEARER eyJhbGci", "eyJhbGci", true, "all capitals"},
		{"bEaReR eyJhbGci", "eyJhbGci", true, "alternating"},
		{"Bearer ", "", true, "a prefix with nothing after it is still a bearer token, of length zero"},
		{"bearertoken", "", false, "seven bytes that start like the prefix but have no separator"},
		{"Bear x", "", false, "one byte short of the prefix"},
		{"Bearer", "", false, "the prefix without its trailing space"},
		{" bearer x", "", false, "a leading space is not the prefix"},
		{"Bearer\u00a0x", "", false, "a non-breaking space is not the separator"},
		{"\u212earer x", "", false, "U+212A KELVIN SIGN is not a 'B', and this fold does not go looking"},
		{"", "", false, "an empty header value is refused before any comparison"},
		{"Bearer  x", " x", true, "a second space belongs to the token, because exactly one separator is consumed"},
	}
	for _, c := range cases {
		token, ok := ParseBearerAuth(c.header)
		if ok != c.ok || token != c.token {
			t.Errorf("ParseBearerAuth(%q) = (%q, %v), want (%q, %v) -- %s", c.header, token, ok, c.token, c.ok, c.why)
		}
	}
}

// TestConformanceBearerDecisionIsTheVerifiedRuleRecomputed restates the decision from the verified
// primitives -- a length test and one call to `util.EqualFold` -- and requires the shipped parser to agree
// on every header shape this can produce. It is the correspondence in the direction that matters: the
// proof is about `util.EqualFold`, so if the parser's accept/refuse is the same function of the same
// comparison, the proof is about the parser's prefix step too.
func TestConformanceBearerDecisionIsTheVerifiedRuleRecomputed(t *testing.T) {
	pieces := []string{"", "B", "b", "Bearer", "bearer", "BEARER", " ", "x", "eyJ.", "\u00c5", "\u212a", "\ufb00", "0"}
	suffixes := []string{"", " ", "  ", " x", "eyJ", " token/signature"}
	checked := 0
	for _, head := range pieces {
		for _, tail := range suffixes {
			for _, glue := range []string{"", " ", "e"} {
				auth := head + glue + tail
				// the rule as the proof states it
				wantOK := len(auth) >= len(bearerPrefix) && util.EqualFold(auth[:len(bearerPrefix)], bearerPrefix)
				wantToken := ""
				if wantOK {
					wantToken = auth[len(bearerPrefix):]
				}
				gotToken, gotOK := ParseBearerAuth(auth)
				if gotOK != wantOK || gotToken != wantToken {
					t.Fatalf("ParseBearerAuth(%q) = (%q, %v), the verified rule gives (%q, %v)", auth, gotToken, gotOK, wantToken, wantOK)
				}
				// and a match can never be shorter or longer than the prefix plus the token
				if gotOK && len(bearerPrefix)+len(gotToken) != len(auth) {
					t.Errorf("ParseBearerAuth(%q) returned a token of %d bytes for a %d-byte header", auth, len(gotToken), len(auth))
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no headers were checked")
	}

	// The fold is ASCII-only, so on the inputs where Go's own lowercase agrees with it, the decision is also
	// `strings.HasPrefix(strings.ToLower(...))`; where they could differ, this function refuses. That second
	// direction is what keeps a Unicode look-alike prefix out of the authenticated path, and it is asserted
	// rather than assumed.
	lookalikes := []string{"\u212earer x", "\u00c6arer x", "\u0100earer x", "\ufb00earer x"}
	for _, header := range lookalikes {
		if _, ok := ParseBearerAuth(header); ok {
			t.Errorf("ParseBearerAuth(%q) accepted a prefix that is not ASCII \"Bearer\"", header)
		}
		if strings.HasPrefix(strings.ToLower(header), "bearer ") {
			t.Errorf("strings.ToLower would have accepted %q, so the divergence claim in util/equalfold.go needs rewriting", header)
		}
	}
}

// TestConformanceBearerAuthHeaderIsTheSameDecision covers the two lines above the parser: `BearerAuth`
// reads the `Authorization` header and refuses an absent or empty one before the parser is reached, which
// is the only place where a missing header and a malformed one are the same event.
func TestConformanceBearerAuthHeaderIsTheSameDecision(t *testing.T) {
	for _, header := range []string{"Bearer tok", "bearer tok", "Basic dXNlcjpwYXNz", "bearer", "", "Bear x"} {
		r, err := newConformanceRequestWithHeader(header)
		if err != nil {
			t.Fatalf("building a request: %v", err)
		}
		gotToken, gotOK := BearerAuth(r)
		wantToken, wantOK := ParseBearerAuth(header)
		if gotOK != wantOK || gotToken != wantToken {
			t.Errorf("Authorization %q: the header path gives (%q,%v), the parser gives (%q,%v)", header, gotToken, gotOK, wantToken, wantOK)
		}
	}
	// an absent header is an empty one: no authentication material at all
	r := newConformanceRequestWithoutHeader()
	if token, ok := BearerAuth(r); ok || token != "" {
		t.Errorf("an absent Authorization header gave (%q,%v), want an empty refusal", token, ok)
	}
}

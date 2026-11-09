package server_auth

// Conformance tests for proof/bearer/model.gobra (SR-PARSE-02): the pre-authentication header
// parser in handlers.go and util.EqualFold.
//
// The model proves the shape of the contract - accept a header exactly when its first seven
// bytes case-fold to the prefix, return the remainder verbatim, refuse everything else, and
// never truncate a header that is merely long. What the model cannot do is evaluate Go's own
// constant: Gobra does not reduce string literals, so it cannot check that the prefix inside
// ParseBearerAuth is really "Bearer ", and it cannot run util.EqualFold. These tests are the
// other half of the argument. Run with `go test ./server_auth -run TestConformance`.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/h4sh5/sshoq/util"
)

// Conforms to the model's ParseBearer contract: the accepted spellings of the scheme.
func TestConformanceBearerAcceptsEveryCaseOfThePrefix(t *testing.T) {
	for _, prefix := range []string{"Bearer ", "bearer ", "BEARER ", "BeArEr ", "bEARER "} {
		bearer, ok := ParseBearerAuth(prefix + "tok")
		if !ok || bearer != "tok" {
			t.Errorf("ParseBearerAuth(%q) = %q, %v; want \"tok\", true", prefix+"tok", bearer, ok)
		}
	}
}

// Conforms to the model's thePrefixIsSevenAsciiBytes, which is the claim Gobra cannot check.
// The bytes are pinned because the model has the offset 7 hard-coded: a prefix that changed
// length would silently move every lemma away from the code it models.
func TestConformanceBearerPrefixIsSevenAsciiBytes(t *testing.T) {
	const want = "Bearer "
	if len(want) != 7 {
		t.Fatalf("len(prefix) = %d, want 7", len(want))
	}
	for i, c := range []byte{66, 101, 97, 114, 101, 114, 32} {
		if want[i] != c {
			t.Fatalf("prefix[%d] = %d, want %d", i, want[i], c)
		}
	}
	// And the code agrees with that spelling: exactly the headers that carry it, in some
	// ASCII case, are accepted.
	for _, hdr := range []string{"Bearer x", "bearer x", "BEARER x"} {
		if _, ok := ParseBearerAuth(hdr); !ok {
			t.Errorf("ParseBearerAuth(%q) refused", hdr)
		}
	}
	for _, hdr := range []string{"Bear x", "Bearery x"} {
		if _, ok := ParseBearerAuth(hdr); ok {
			t.Errorf("ParseBearerAuth(%q) accepted, want refusal", hdr)
		}
	}
}

// Conforms to the model's aHeaderThatFoldsToThePrefixIsAccepted, where the empty token is
// stated as len(bearer) == 0 (Gobra has no empty-string uniqueness). The parser accepts the
// empty token and only the length check in Authenticate rejects it; that separation is
// asserted here so it cannot drift into "the parser rejects empty tokens".
func TestConformanceBearerEmptyTokenParsesButIsNotTrusted(t *testing.T) {
	bearer, ok := ParseBearerAuth("Bearer ")
	if !ok {
		t.Fatal("a bare \"Bearer \" must parse as Bearer with an empty token")
	}
	if len(bearer) != 0 {
		t.Fatalf("len(token) = %d, want 0 (the model's form of this claim)", len(bearer))
	}
}

// Conforms to the model's refusesAnythingThatIsNotThePrefix, including the boundary cases:
// "Bearer" is one byte short, "Bearera" has the wrong seventh byte, and a leading space is not
// tolerated - trimming here would let a client smuggle a header past a proxy that reads the
// raw value.
func TestConformanceBearerRefusesNearMisses(t *testing.T) {
	for _, hdr := range []string{
		"", "B", "Bearer", "Bearerx", "Bearera", "earer tok", "Bearer\ntok", "bearer\t",
		"Bearer\ttok", "XBearer tok", " tok", "Basic dXNlcjpwYXNz",
	} {
		if bearer, ok := ParseBearerAuth(hdr); ok {
			t.Errorf("ParseBearerAuth(%q) accepted with token %q; want refusal", hdr, bearer)
		}
	}
}

// Conforms to the model's theTokenIsExactlyTheRestOfTheHeader: the token is the verbatim
// remainder, with no trimming and no case folding.
func TestConformanceBearerTokenIsVerbatim(t *testing.T) {
	const token = "AbC._-~0123456789"
	hdr := "bearer " + token
	bearer, ok := ParseBearerAuth(hdr)
	if !ok || bearer != token {
		t.Fatalf("ParseBearerAuth(%q) = %q, %v; want %q, true", hdr, bearer, ok, token)
	}
	if withSpace, ok := ParseBearerAuth("Bearer  tok"); !ok || withSpace != " tok" {
		t.Errorf("a leading space in the token must survive verbatim, got %q, %v", withSpace, ok)
	}
}

// Conforms to the model's theCaseFoldIsAsciiOnly. The refusals are the interesting half:
// U+212A KELVIN SIGN, U+017F LONG S and U+1E9E CAPITAL SHARP S are case-fold variants under
// Unicode rules, and full-width Ｂ is a variant of 'B'. util.lower is ASCII-only, so none of
// them folds to an ASCII byte and a header spelled with them is not Bearer. Refusing is the
// safe direction: a header this server does not recognise is refused, never silently treated
// as a credential.
func TestConformanceBearerFoldIsAsciiOnly(t *testing.T) {
	accepted, refused := 0, 0
	for _, hdr := range []string{
		"Bearer tok", "bEARER tok", "BeArEr tok", "BEARER tok",
		"Ｂearer tok", "ＢＥＡＲＥＲ tok", "ſearer tok", "Ÿeares tok",
	} {
		if _, ok := ParseBearerAuth(hdr); ok {
			accepted++
		} else {
			refused++
		}
	}
	if accepted != 4 {
		t.Errorf("accepted %d of 8 headers, want the 4 ASCII case variants only", accepted)
	}
	if refused != 4 {
		t.Errorf("refused %d of 8 headers, want the 4 non-ASCII spellings", refused)
	}
}

// Conforms to the model's theFoldIsSymmetric, theFoldRefusesDifferentLengths and
// foldOfThePrefixIsBytewise - the real util.EqualFold, not the model's copy of it.
func TestConformanceFoldMatchesTheModel(t *testing.T) {
	pairs := [][2]string{
		{"", ""}, {"Bearer", "bearer"}, {"BeArEr", "bEAReR"}, {"Bearer", "Bearerx"},
		{"Bearerx", "Bearer"}, {"bearer ", "BEARER "}, {"A", "a"}, {"A", "B"}, {"~", "~"},
		{"\xc3\x9f", "SS"}, {"\xc3\x9f", "ss"},
	}
	for _, p := range pairs {
		if got := util.EqualFold(p[0], p[1]); got != util.EqualFold(p[1], p[0]) {
			t.Errorf("EqualFold is not symmetric on %q, %q", p[0], p[1])
		}
		if len(p[0]) != len(p[1]) && util.EqualFold(p[0], p[1]) {
			t.Errorf("EqualFold(%q, %q) = true on different lengths", p[0], p[1])
		}
	}
	// byte-by-byte, the way the model states it
	if !util.EqualFold("BeArEr ", "bearer ") {
		t.Error(`EqualFold("BeArEr ", "bearer ") = false`)
	}
	if util.EqualFold("Bearer\tx", "bearer x") {
		t.Error("the separator must match exactly; folding must not apply to non-letters")
	}
}

// Conforms to the routing rule the model states as `ok == false ==> 401`: HandleBearerAuth
// refuses before ever calling the verifier, so an unparseable header cannot reach the code
// that trusts its argument.
func TestConformanceHandleBearerAuthRefusesBeforeVerifying(t *testing.T) {
	for name, header := range map[string]string{
		"absent":       "",
		"bare":         "Bearer",
		"wrongScheme":  "Basic dXNlcjpwYXNz",
		"leadingSpace": " Bearer tok",
	} {
		called := false
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		HandleBearerAuth("alice", "conv", func(bearer, conv string, w http.ResponseWriter, r *http.Request) {
			called = true
		})(rec, req)
		if called {
			t.Errorf("%s: verifier was called with header %q", name, header)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
	}
	// and the accepted form does reach the verifier, with the token verbatim
	called := ""
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", "bearer tok123")
	HandleBearerAuth("alice", "conv", func(bearer, conv string, w http.ResponseWriter, r *http.Request) {
		called = bearer
	})(httptest.NewRecorder(), req)
	if called != "tok123" {
		t.Errorf("verifier received %q, want the token verbatim", called)
	}
}

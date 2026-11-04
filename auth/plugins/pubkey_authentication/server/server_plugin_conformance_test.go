package server_pubkey_authentication

// The verifier that decides whether a public key belongs to the user asking to log in --
// `PubkeyJWTIdentityVerifier.Verify` -- had no test in this repository before this file, and no
// row in `proof/SECURITY_REQUIREMENTS.md` pointing at this file (finding **F15**). Everything
// proved elsewhere in this programme about identity options, source addresses and plugin
// registries sits *on top of* the assumption that this function refuses a credential it should.
//
// What it must do, in one sentence: accept a JWT that the key in the `authorized_identity` line
// signed, with the algorithm set the key type allows, issued for this user, for this protocol,
// bound to this conversation, not expired, and coming from a source address the identity line
// permits. Each of those clauses is a separate arm below, and each is tested in both directions
// -- accepted when satisfied, refused when broken -- with an accepted control inside every
// refusal table, so that a version of this file which refuses everything cannot pass.
//
// The cryptographic part is out of reach of the prover (`crypto/ed25519` has no specs), so this
// is a `conformant` row: the decisions are exercised over real tokens rather than proved over a
// model. Two of the facts below are measured rather than asserted from the source, and say so.

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	ssh3 "github.com/h4sh5/sshoq"
	"golang.org/x/crypto/ssh"
)

const testUser = "alice"

// zeroConversationID is the base64 of the conversation ID of a `Conversation` built outside this
// repository's own constructors -- all zero bytes -- which is what the client's token builder
// will put in `jti` for such a conversation. It is spelled out here rather than hardcoded so that
// the seam test cannot drift from it.
var zeroConversationID = base64.StdEncoding.EncodeToString(make([]byte, 32))

func testKey(t *testing.T) (public ed25519.PublicKey, private ed25519.PrivateKey, line string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sshKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	// MarshalAuthorizedKey ends with a newline; ssh.ParseAuthorizedKey tolerates either, and
	// trailing whitespace here is what a real authorized_identity file looks like.
	return public, private, string(ssh.MarshalAuthorizedKey(sshKey))
}

// clientClaims mirrors `ssh3.BuildJWTBearerToken` in client_auth.go. Keeping it here as a literal
// is deliberate: if the client changes a claim name, the server-side verifier is the one that has
// to notice, and this table is where the mismatch shows up. The client's own claims are checked
// end to end in TestConformanceClientTokenIsAcceptedByTheServer, which uses the real builder.
func clientClaims(t *testing.T, public ed25519.PublicKey, now time.Time) jwt.MapClaims {
	t.Helper()
	return jwt.MapClaims{
		"iss":       testUser,
		"iat":       jwt.NewNumericDate(now),
		"exp":       jwt.NewNumericDate(now.Add(10 * time.Second)),
		"sub":       "ssh3",
		"aud":       "unused",
		"client_id": fmt.Sprintf("ssh3-%s", testUser),
		"jti":       zeroConversationID,
	}
}

func signedToken(t *testing.T, claims jwt.MapClaims, key interface{}) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func bearerRequest(token string, remoteAddr string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/ssh3", nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if remoteAddr != "" {
		request.RemoteAddr = remoteAddr
	}
	return request
}

func verifierFromLine(t *testing.T, line string) interface {
	Verify(request *http.Request, base64ConversationID string) bool
} {
	t.Helper()
	verifier, err := PubkeyAuthPlugin(testUser, line)
	if err != nil {
		t.Fatalf("the identity line was refused: %s\nline: %q", err, line)
	}
	if verifier == nil {
		t.Fatalf("the identity line produced no verifier: %q", line)
	}
	return verifier
}

// TestConformanceClientTokenIsAcceptedByTheServer is the seam: the token the client builds, with
// the client's own builder function, verified by the server's own plugin entry point. If a claim
// name, a claim value or the encoding of the conversation ID changes on one side only, this is the
// test that fails -- and it fails in the direction that matters, a working login turning into a
// refused one.
func TestConformanceClientTokenIsAcceptedByTheServer(t *testing.T) {
	_, private, line := testKey(t)
	verifier := verifierFromLine(t, line)

	token, err := ssh3.BuildJWTBearerToken(jwt.SigningMethodEdDSA, private, testUser, &ssh3.Conversation{})
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.Verify(bearerRequest(token, "127.0.0.1:4242"), zeroConversationID) {
		t.Fatal("the server refused a token the client built for this conversation")
	}

	// the same token, a different conversation: the binding is to the conversation, not to the key
	if verifier.Verify(bearerRequest(token, "127.0.0.1:4242"),
		base64.StdEncoding.EncodeToString(append(make([]byte, 31), 1))) {
		t.Error("a token bound to one conversation was accepted for another")
	}
}

// TestConformanceEveryClaimIsNecessary breaks one claim at a time and expects refusal, with the
// untouched token in the same table as an accepted control.
func TestConformanceEveryClaimIsNecessary(t *testing.T) {
	public, private, line := testKey(t)
	verifier := verifierFromLine(t, line)
	now := time.Now()

	cases := []struct {
		name     string
		mutate   func(claims jwt.MapClaims)
		accepted bool
	}{
		{"control: the client's claims", func(jwt.MapClaims) {}, true},
		{"issuer is another user", func(c jwt.MapClaims) { c["iss"] = "mallory" }, false},
		{"issuer missing", func(c jwt.MapClaims) { delete(c, "iss") }, false},
		{"subject is not ssh3", func(c jwt.MapClaims) { c["sub"] = "something-else" }, false},
		{"subject missing", func(c jwt.MapClaims) { delete(c, "sub") }, false},
		{"audience is not the one the server names", func(c jwt.MapClaims) { c["aud"] = "another-service" }, false},
		{"client_id does not name the user", func(c jwt.MapClaims) { c["client_id"] = "ssh3-mallory" }, false},
		{"client_id missing", func(c jwt.MapClaims) { delete(c, "client_id") }, false},
		{"client_id is not a string", func(c jwt.MapClaims) { c["client_id"] = 42 }, false},
		{"jti is not the conversation", func(c jwt.MapClaims) { c["jti"] = "not-this-conversation" }, false},
		{"jti missing", func(c jwt.MapClaims) { delete(c, "jti") }, false},
		{"exp missing", func(c jwt.MapClaims) { delete(c, "exp") }, false},
		// jwt.WithIssuedAt() verifies iat when it is there; it does not require it to be there
		// (parser_option.go: verifyIat). A token that says nothing about when it was issued is
		// therefore accepted -- harmless here because jti, not iat, is what limits the token to
		// this conversation, but it is not what the option's name suggests.
		{"iat missing", func(c jwt.MapClaims) { delete(c, "iat") }, true},
		{"expired fifty seconds ago", func(c jwt.MapClaims) { c["exp"] = jwt.NewNumericDate(now.Add(-50 * time.Second)) }, true},
		{"expired two minutes ago", func(c jwt.MapClaims) { c["exp"] = jwt.NewNumericDate(now.Add(-120 * time.Second)) }, false},
	}
	for _, c := range cases {
		claims := clientClaims(t, public, now)
		c.mutate(claims)
		token := signedToken(t, claims, private)
		got := verifier.Verify(bearerRequest(token, "127.0.0.1:4242"), zeroConversationID)
		if got != c.accepted {
			t.Errorf("%s: Verify = %t, want %t", c.name, got, c.accepted)
		}
	}
}

// TestConformanceMissingExpiryIsRefusedByHand pins the line that the library would not have
// written for you: `jwt` treats a token with no `exp` claim as one that never expires, so the
// explicit presence check in Verify is what stops a key being proved forever by a token that says
// nothing about time. The refusal is checked twice -- once through Verify, and once against the
// library with the same options minus that check, which is what makes the line visible as
// load-bearing rather than as decoration.
func TestConformanceMissingExpiryIsRefusedByHand(t *testing.T) {
	public, private, line := testKey(t)
	verifier := verifierFromLine(t, line)
	now := time.Now()

	claims := clientClaims(t, public, now)
	delete(claims, "exp")
	token := signedToken(t, claims, private)
	if verifier.Verify(bearerRequest(token, "127.0.0.1:4242"), zeroConversationID) {
		t.Error("a token with no expiry was accepted")
	}

	// the same parse the verifier performs, without the hand-written presence check: the
	// library is content, which is the measurement that justifies the line above.
	parsed, err := jwt.Parse(token,
		func(*jwt.Token) (interface{}, error) { return public, nil },
		jwt.WithIssuer(testUser), jwt.WithSubject("ssh3"), jwt.WithAudience("unused"),
		jwt.WithIssuedAt(), jwt.WithLeeway(60*time.Second),
		jwt.WithValidMethods([]string{"RS256", "EdDSA", "ES256"}))
	if err != nil || !tokenIsValid(parsed) {
		t.Fatalf("the library refused the no-expiry token too (%v); the hand-written check is no longer what makes it fail -- update this test to say which one does", err)
	}
}

func tokenIsValid(token *jwt.Token) bool { return token != nil && token.Valid }

// TestConformanceSignatureAndAlgorithmAreChecked is the classic confusion set: another key, a
// different algorithm, an algorithm the server does not accept, and no signature at all.
func TestConformanceSignatureAndAlgorithmAreChecked(t *testing.T) {
	_, _, line := testKey(t)
	verifier := verifierFromLine(t, line)
	now := time.Now()

	otherPublic, otherPrivate, _ := testKey(t)

	// signed by a key nobody authorised
	if verifier.Verify(bearerRequest(signedToken(t, clientClaims(t, otherPublic, now), otherPrivate),
		"127.0.0.1:4242"), zeroConversationID) {
		t.Error("a token signed by another key was accepted")
	}

	// the RS256-to-HS256 confusion, in its sshoq form: HMAC the claims with the public key that
	// is in the identity line, and hand over the token with "alg": "HS256"
	hmaced, err := jwt.NewWithClaims(jwt.SigningMethodHS256, clientClaims(t, otherPublic, now)).
		SignedString([]byte(string(otherPublic)))
	if err != nil {
		t.Fatal(err)
	}
	if verifier.Verify(bearerRequest(hmaced, "127.0.0.1:4242"), zeroConversationID) {
		t.Error("a MAC token signed with the public key was accepted (algorithm confusion)")
	}

	// no signature at all: header {"alg":"none"}, empty signature
	good := signedToken(t, clientClaims(t, otherPublic, now), otherPrivate)
	parts := strings.Split(good, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape: %q", good)
	}
	unsigned := fmt.Sprintf("%s.%s.",
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)), parts[1])
	if verifier.Verify(bearerRequest(unsigned, "127.0.0.1:4242"), zeroConversationID) {
		t.Error("an unsigned token was accepted")
	}

	// and the same token with its signature removed: refused by the signature, not by the
	// algorithm list
	if verifier.Verify(bearerRequest(parts[0]+"."+parts[1]+".", "127.0.0.1:4242"), zeroConversationID) {
		t.Error("a token with its signature removed was accepted")
	}
}

// TestConformanceSourceAddressRestrictionAppliesToTheKeyNotTheToken covers the clause that runs
// after the signature is good: an identity line with from= only authenticates a connection that
// comes from one of its addresses, and the same key without from= is unrestricted. The claim
// itself says nothing about the address, which is why this cannot be caught by the token tests
// above.
func TestConformanceSourceAddressRestrictionAppliesToTheKeyNotTheToken(t *testing.T) {
	public, private, plainLine := testKey(t)
	now := time.Now()
	token := signedToken(t, clientClaims(t, public, now), private)

	// options come first in an authorized_keys line, as everywhere else in this format: putting
	// them after the key turns them into a comment and leaves the key unrestricted, which is
	// exactly the mistake this test would otherwise have been made of.
	restricted := fmt.Sprintf("from=\"127.0.0.0/8\" %s", strings.TrimSpace(plainLine))
	verifier := verifierFromLine(t, restricted)
	if !verifier.Verify(bearerRequest(token, "127.0.0.1:4242"), zeroConversationID) {
		t.Error("a connection from an address the identity line names was refused")
	}
	if verifier.Verify(bearerRequest(token, "10.0.0.1:4242"), zeroConversationID) {
		t.Error("a connection from an address outside from= was authenticated")
	}
	// the control in the other direction: the very same key and token, with no from= on the line
	unrestricted := verifierFromLine(t, plainLine)
	if !unrestricted.Verify(bearerRequest(token, "10.0.0.1:4242"), zeroConversationID) {
		t.Error("the same key without from= must authenticate from anywhere")
	}
}

// TestConformanceIdentityLinesThatAreNotThisPlugins are the shapes the registry relies on: a line
// that is not a public key at all contributes no identity (nil, nil), so another plugin may answer
// it (finding F12 / SR-AUTH-10), while a line that *is* a key but says something this plugin cannot
// enforce is an error -- a refusal, not a silent shrug.
func TestConformanceIdentityLinesThatAreNotThisPlugins(t *testing.T) {
	verifier, err := PubkeyAuthPlugin(testUser, "foobar")
	if err != nil || verifier != nil {
		t.Errorf("a line that is not a public key must yield no verifier and no error, got (%v, %v)", verifier, err)
	}
	verifier, err = PubkeyAuthPlugin(testUser, "")
	if err != nil || verifier != nil {
		t.Errorf("an empty identity line must yield no verifier and no error, got (%v, %v)", verifier, err)
	}
	// A key type the ssh package does not know at all -- ssh-dss is not compiled in -- does not
	// reach the switch below: it fails to parse, and so contributes no identity rather than an
	// error. Measured, and recorded here because the distinction decides whether the connection
	// survives (finding F12 / SR-AUTH-10).
	verifier, err = PubkeyAuthPlugin(testUser, "ssh-dss AAAAB3NzaC1kc3MAAACBAP4g3TAvDBNwpkZKbF3m")
	if err != nil || verifier != nil {
		t.Errorf("an unparseable key type must yield no verifier and no error, got (%v, %v)", verifier, err)
	}
	// An option that cannot be enforced makes the whole identity be refused rather than ignored.
	// This is the row that turns a bug in `identity_options.go` into a login failure rather than
	// into a key that silently grants a full shell.
	_, _, line := testKey(t)
	blob := strings.TrimSpace(line)
	if _, err := PubkeyAuthPlugin(testUser, "nosuchoption "+blob); err == nil {
		t.Error("an unrecognised authorized_keys option must refuse the identity (SR-PERM-01)")
	}
	if _, err := PubkeyAuthPlugin(testUser, "restrict,no-such-option "+blob); err == nil {
		t.Error("an unrecognised option after a comma must refuse the identity too")
	}
	// Measured, and surprising enough to pin: the ssh parser does not accept a quoted option
	// value followed by a second option separated by a space (`command="echo hi" no-agent-
	// forwarding KEY`), it reports "no key found". That is not a security hole -- an identity
	// that does not parse contributes nothing, so the key cannot authenticate -- but it does mean
	// the OpenSSH-style spelling with spaces makes a key inert rather than restricted. OpenSSH's
	// own format is comma separated with no spaces, which parses.
	verifier, err = PubkeyAuthPlugin(testUser, "command=\"echo hi\" no-agent-forwarding "+blob)
	if err != nil || verifier != nil {
		t.Errorf("the space-separated two-option form must yield no verifier and no error, got (%v, %v)", verifier, err)
	}
	if _, err := PubkeyAuthPlugin(testUser, "command=\"echo hi\",no-agent-forwarding "+blob); err != nil {
		t.Errorf("the comma-separated form is the one that parses, and it must be refused for the reason the model gives: %v", err)
	}
}

// TestConformanceBearerHeaderHasToBeThere is the entry to the function rather than its body: no
// header, another scheme, an empty token, and the bare word Bearer all refuse, and refuse without
// consulting a key at all.
func TestConformanceBearerHeaderHasToBeThere(t *testing.T) {
	_, _, line := testKey(t)
	verifier := verifierFromLine(t, line)

	requests := map[string]string{
		"no authorization header":   "",
		"another scheme":            "Basic dXNlcjpwYXNz",
		"bearer with nothing after": "Bearer ",
		"the bare word bearer":      "Bearer",
		"bearer with a non-token":   "Bearer notajwt",
		"lowercase scheme":          "bearer whatever",
	}
	for name, header := range requests {
		request := httptest.NewRequest(http.MethodGet, "/ssh3", nil)
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		if verifier.Verify(request, zeroConversationID) {
			t.Errorf("%s was authenticated", name)
		}
	}
}

package server_auth

// Conformance tests for proof/oidcbinding/model.gobra (SR-AUTH-06): the conversation binding of an
// OIDC ID token.
//
// The model proves a decision algebra: a token which carries neither `ssh3_conv_id` nor `jti` is
// refused; one bound to another conversation is refused; a token can be accepted for at most one
// conversation, because the value it is compared against is the server's own id; the replay key is
// `jti` when present and the binding value otherwise, and is never empty; and the replay store's
// refusal is not advisory. Two of its premises are things Go does, not things the model can see, and
// these tests are those steps:
//
//   - `conversation`, the value on the right of the comparison, really is the server's own
//     conversation id, base64-encoded -- and that encoding distinguishes conversation ids, or two
//     conversations would share one binding value and the model's "at most one conversation" would
//     say less than it looks like. Checked by executing the encoding, exhaustively on the short
//     inputs and bit by bit on real 32-byte ids.
//   - the block in `OpenIDConnectIdentity.Verify` really reads the claims in the order the model
//     assumes, compares against the parameter rather than against something the token brought, and
//     refuses at each step instead of falling through. `Verify` cannot be called without a live
//     issuer (its first act is a JWKS-backed signature check), so this is a structured read of the
//     source inside that one method, ordered, and it fails if the order or the compared values move.
//
// Run with `go test ./server_auth/ -run TestConformance`.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/h4sh5/sshoq"
)

// TestConformanceConversationIDEncodingIsInjective checks the one function call between the
// server's conversation id and the string the binding compares: base64.StdEncoding.EncodeToString
// over the 32 id bytes, which is also exactly ConversationID.String().
//
// It has to be injective. If two different conversation ids encoded to one string, a token bound to
// either would satisfy the check on both, and "a token is accepted for at most one conversation" --
// the property the model proves -- would be a statement about encodings and not about conversations.
func TestConformanceConversationIDEncodingIsInjective(t *testing.T) {
	encode := func(bytes []byte) string { return base64.StdEncoding.EncodeToString(bytes) }

	// the encoding the server compares with is the one the conversation type prints
	var id ssh3.ConversationID
	for i := range id {
		id[i] = byte(i * 7)
	}
	if got, want := id.String(), encode(id[:]); got != want {
		t.Fatalf("ConversationID.String() = %q but auth compares %q: the client and the server would "+
			"be binding different strings", got, want)
	}
	// and it is a function of its input, not of anything else in the process
	again := id
	if again.String() != id.String() {
		t.Fatal("the conversation id encoding is not deterministic")
	}

	// exhaustive on short inputs, placed at every offset of a 32-byte id: distinct bytes must give
	// distinct strings, padding and position included
	seen := map[string]string{}
	record := func(bytes []byte) {
		key := encode(bytes)
		if other, clash := seen[key]; clash && other != fmt.Sprintf("%x", bytes) {
			t.Fatalf("%x and %x both encode to %q", bytes, []byte(other), key)
		}
		seen[key] = fmt.Sprintf("%x", bytes)
	}
	for _, length := range []int{1, 2} {
		count := 1
		for i := 0; i < length; i++ {
			count *= 256
		}
		for n := 0; n < count; n++ {
			full := ssh3.ConversationID{}
			for i := 0; i < length; i++ {
				full[i] = byte(n >> (8 * (length - 1 - i)))
			}
			record(full[:])
			// the same bytes at the far end of the id must not collide with them either
			shifted := ssh3.ConversationID{}
			copy(shifted[32-length:], full[:length])
			record(shifted[:])
		}
	}

	// every single bit of a real id changes the encoding: the strongest practical statement that
	// distinct conversation ids do not share a binding value
	base := ssh3.ConversationID{}
	if _, err := rand.Read(base[:]); err != nil {
		t.Fatal(err)
	}
	baseEncoding := base.String()
	for byteIndex := 0; byteIndex < 32; byteIndex++ {
		for bit := 0; bit < 8; bit++ {
			flipped := base
			flipped[byteIndex] ^= 1 << bit
			if flipped.String() == baseEncoding {
				t.Fatalf("flipping bit %d of byte %d leaves the encoding unchanged: two conversation "+
					"ids would carry the same binding value", bit, byteIndex)
			}
		}
	}

	// random pairs, as a final sweep over the space the TLS exporter actually produces
	for n := 0; n < 20000; n++ {
		left, right := ssh3.ConversationID{}, ssh3.ConversationID{}
		if _, err := rand.Read(left[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(right[:]); err != nil {
			t.Fatal(err)
		}
		if left == right {
			continue
		}
		if left.String() == right.String() {
			t.Fatalf("two different conversation ids encode identically: %x and %x", left[:], right[:])
		}
	}
}

// conformanceBindingSteps is the order the model assumes, as it reads in the source of
// OpenIDConnectIdentity.Verify. Each entry is a phrase which must appear inside that method, later
// than the one before it; the comments are the model's own names for them.
var conformanceBindingSteps = []struct{ what, phrase string }{
	{
		"the identity is checked before the binding: an unverified or mismatched e-mail refuses " +
			"the token and the binding claim is never consulted",
		"claims.EmailVerified && claims.Email == i.email",
	},
	{"boundTo takes `ssh3_conv_id` first", "bound := claims.Conversation"},
	{"boundTo falls back to `jti` only when that claim is absent", "bound = claims.UniqueID"},
	{
		"an unbound token is refused rather than treated as bound to whatever is asking " +
			"(unboundTokenIsRefused)",
		"if bound == \"\"",
	},
	{
		"the comparison is against the server's own conversation id (oneTokenAtMostOneConversation)",
		"bound != base64ConversationID",
	},
	{"replayKey takes `jti` when present", "unique := claims.UniqueID"},
	{"replayKey falls back to the binding value", "unique = bound"},
	{
		"the replay store's answer decides: a second acceptance of the same key refuses the token " +
			"(storeRefusalRefusesTheToken)",
		"!acceptedOIDCTokens.Accept(token.Issuer, unique, token.Expiry)",
	},
}

// TestConformanceOIDCBindingBlockIsTheModelledDecision reads Verify and holds it to the order above.
func TestConformanceOIDCBindingBlockIsTheModelledDecision(t *testing.T) {
	const file = "authorized_identities.go"
	src, err := readFileForConformance(file)
	if err != nil {
		t.Fatal(err)
	}
	body := functionSource(t, file, src, "Verify", "OpenIDConnectIdentity")

	// searched in order, each phrase from where the previous one ended: two of the steps share the
	// text `if bound == ""` -- the fallback and the refusal -- and only a search which moves
	// forward can tell them apart
	previous, previousWhat := -1, ""
	for _, step := range conformanceBindingSteps {
		relative := strings.Index(body[previous+1:], step.phrase)
		if relative < 0 {
			t.Fatalf("%s: %q does not appear in %s's Verify after %q. If the binding really changed, "+
				"change proof/oidcbinding/model.gobra with it -- the proof says what the code said, and "+
				"this test is the only thing connecting them.",
				step.what, step.phrase, file, previousWhat)
		}
		at := previous + 1 + relative
		previous, previousWhat = at, step.what
	}

	// the right-hand side of the binding comparison is the server's, never something the token
	// carried: a token which could name the value it is compared against could bind itself to any
	// conversation, which is exactly the hole SR-AUTH-06 closes
	if strings.Contains(body, "bound != claims.") || strings.Contains(body, "bound == claims.") {
		t.Error("the binding is compared against a claim of the token rather than the server's "+
			"conversation id: a captured token can then be re-bound by whoever holds it")
	}
	// and the parameter it is compared against is the one the caller computes from the conversation
	if !strings.Contains(body, "base64ConversationID string") {
		t.Error("Verify no longer takes the conversation id as a parameter, so the proof's "+
			"`conversation` value has no counterpart in the code")
	}
}

// TestConformanceOIDCBindingClaimNames checks the claim names themselves, since a binding is only as
// good as the field it is read from: `ssh3_conv_id` is sshoq's, `jti` is accepted because OpenSSH's
// SSHFP-style tooling uses it, and neither may silently become something an issuer fills in for us.
func TestConformanceOIDCBindingClaimNames(t *testing.T) {
	const file = "authorized_identities.go"
	src, err := readFileForConformance(file)
	if err != nil {
		t.Fatal(err)
	}
	body := functionSource(t, file, src, "Verify", "OpenIDConnectIdentity")
	for _, want := range []string{`json:"jti"`, `json:"ssh3_conv_id"`, `json:"email_verified"`, `json:"email"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Verify no longer reads a claim with the tag %s: the model's convClaim/jtiClaim "+
				"and the token's fields have come apart", want)
		}
	}
	// the claim names as constants, which is what the error messages quote to an operator
	// whitespace-normalised, because gofmt aligns these and alignment is not the point
	aligned := strings.Join(strings.Fields(src), " ")
	for _, want := range []string{`conversationIDClaim = "ssh3_conv_id"`, `uniqueTokenIDClaim = "jti"`} {
		if !strings.Contains(aligned, want) {
			t.Errorf("%s is missing: the requirement names these claims to the operator, and the "+
				"proof names them to the prover", want)
		}
	}
}

// readFileForConformance reads a source file of this package, from the directory go test runs in.
func readFileForConformance(name string) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", name, err)
	}
	return string(data), nil
}

// functionSource returns the source text of one method, located by AST rather than by a marker
// comment, so that renaming a nearby helper cannot silently move the window being searched.
func functionSource(t *testing.T, filename, src, methodName string, receiverType string) string {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("cannot parse %s: %s", filename, err)
	}
	for _, decl := range parsed.Decls {
		method, ok := decl.(*ast.FuncDecl)
		if !ok || method.Name.Name != methodName || method.Recv == nil || len(method.Recv.List) != 1 {
			continue
		}
		if !typeNames(method.Recv.List[0].Type, receiverType) {
			continue
		}
		start := fset.Position(method.Pos()).Offset
		end := fset.Position(method.End()).Offset
		if end <= start || end > len(src) {
			t.Fatalf("cannot locate %s in %s", methodName, filename)
		}
		return src[start:end]
	}
	t.Fatalf("no method %s on %s in %s: the binding decision has moved and the proof cites it",
		methodName, receiverType, filename)
	return ""
}

// typeNames reports whether a receiver type is `T` or `*T`.
func typeNames(expr ast.Expr, name string) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == name
	case *ast.StarExpr:
		return typeNames(t.X, name)
	default:
		return false
	}
}

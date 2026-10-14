package oidc

import (
	"fmt"
	"testing"
	"time"
)

func TestValidateIssuerURL(t *testing.T) {
	valid := []string{
		"https://issuer.example.org",
		"https://issuer.example.org/",
		"https://issuer.example.org/realms/main",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
	}
	for _, issuerURL := range valid {
		if err := ValidateIssuerURL(issuerURL); err != nil {
			t.Errorf("%s should be accepted: %s", issuerURL, err)
		}
	}

	invalid := []string{
		"http://issuer.example.org",            // could be forged by anybody on the path
		"http://10.0.0.2:8080",                 // ditto, and this one is not even loopback
		"ftp://issuer.example.org",             // not a scheme sshoq can talk to
		"issuer.example.org",                   // no scheme at all
		"https://user:pass@issuer.example.org", // credentials hidden in the issuer URL
		"",
	}
	for _, issuerURL := range invalid {
		if err := ValidateIssuerURL(issuerURL); err == nil {
			t.Errorf("%q should be refused", issuerURL)
		}
	}
}

func TestAcceptedTokenStoreRefusesReplays(t *testing.T) {
	now := time.Now()
	store := NewAcceptedTokenStore(100)
	store.now = func() time.Time { return now }

	expiry := now.Add(time.Hour)
	if !store.Accept("https://issuer.example.org", "token-1", expiry) {
		t.Fatal("the token should be accepted the first time")
	}
	if store.Accept("https://issuer.example.org", "token-1", expiry) {
		t.Fatal("the very same token was accepted twice: it is a replay")
	}
	if store.Len() != 1 {
		t.Fatalf("expected 1 entry, got %d", store.Len())
	}

	// another issuer, another token: the identifier is only unique per issuer
	if !store.Accept("https://other.example.org", "token-1", expiry) {
		t.Fatal("a different issuer may issue a token with the same identifier")
	}

	// once the token expired, remembering it is useless: it cannot be verified, so it
	// cannot be replayed either
	now = now.Add(2 * time.Hour)
	if !store.Accept("https://issuer.example.org", "token-1", expiry) {
		t.Fatal("an expired token cannot be replayed, it must not be kept forever")
	}
}

func TestAcceptedTokenStoreRequiresAnIdentifier(t *testing.T) {
	store := NewAcceptedTokenStore(10)
	if store.Accept("https://issuer.example.org", "", time.Now().Add(time.Hour)) {
		t.Fatal("a token with no unique identifier cannot be deduplicated, it must be refused")
	}
}

func TestAcceptedTokenStoreIsBounded(t *testing.T) {
	now := time.Now()
	store := NewAcceptedTokenStore(10)
	store.now = func() time.Time { return now }

	// an unbounded map fed with identifiers received from the network would itself be a
	// memory exhaustion vector
	for i := 0; i < 10000; i++ {
		store.Accept("https://issuer.example.org", fmt.Sprintf("token-%d", i), now.Add(time.Hour))
	}
	if store.Len() > 10 {
		t.Fatalf("the store grew to %d entries although its bound is 10", store.Len())
	}
}

package oidc

// Conformance tests for the model in proof/replay/model.gobra (SR-AUTH-07, SR-RES-03).
//
// The Gobra unit proves, over every store state and every trace of tokens: that a token with
// no identifier is never accepted; that a token is refused exactly when it is remembered and
// still live, and that a refusal leaves the store untouched; that the store never exceeds its
// capacity; and that a full store gives up the token it accepted first. These tests run the
// same claims against the implementation, so that a change which breaks one of them fails a
// go test and not only a proof build.
//
// The model treats issuer and id as one opaque key, which is what the implementation composes
// internally; the tests below therefore pass an issuer and an id and never depend on the
// composition.

import (
	"fmt"
	"testing"
	"time"
)

func newStoreForConformance(t *testing.T, maxEntries int) *AcceptedTokenStore {
	t.Helper()
	return NewAcceptedTokenStore(maxEntries)
}

// The model: key == "" ==> !accepted, in every state, and the store is unchanged.
func TestConformanceNoIdentifierIsNeverAccepted(t *testing.T) {
	store := newStoreForConformance(t, 4)
	later := time.Now().Add(time.Hour)
	if store.Accept("issuer-without-an-id", "", later) {
		t.Fatal("a token with no identifier was accepted")
	}
	// and with the store non-empty and the entry live, the empty id is still refused
	if !store.Accept("issuer|known", "known", later) {
		t.Fatal("a first presentation of a live token should be accepted")
	}
	if store.Accept("issuer-without-an-id", "", later) {
		t.Fatal("a token with no identifier was accepted a second time")
	}
	if got := store.Len(); got != 1 {
		t.Fatalf("refusals must not change the store: Len() = %d, want 1", got)
	}
}

// The model: first use accepted, second use refused while the entry is live.
func TestConformanceFirstUseAcceptedReplayRefused(t *testing.T) {
	store := newStoreForConformance(t, 4)
	key, id := "https://idp/|token-1", "token-1"
	later := time.Now().Add(time.Hour)
	if !store.Accept(key, id, later) {
		t.Fatal("first presentation of a live token was refused")
	}
	if store.Accept(key, id, later) {
		t.Fatal("second presentation of the same live token was accepted: replay got through")
	}
	if got := store.Len(); got != 1 {
		t.Fatalf("the refused replay changed the store: Len() = %d, want 1", got)
	}
}

// The model: expiryIsZero ==> refused whenever the token is remembered, whatever the clock.
func TestConformanceRememberedTokenWithoutExpiryClaimIsRefusedOnSight(t *testing.T) {
	store := newStoreForConformance(t, 4)
	key, id := "https://idp/|no-exp", "no-exp"
	if !store.Accept(key, id, time.Now().Add(time.Hour)) {
		t.Fatal("first presentation was refused")
	}
	if store.Accept(key, id, time.Time{}) {
		t.Fatal("a remembered token presented with no expiry claim was accepted")
	}
}

// The model: len(res) <= capacity for every trace. Here: a trace far longer than the capacity,
// with replays interleaved so it also exercises the refusal path.
func TestConformanceBoundedUnderAnyTraffic(t *testing.T) {
	const capacity = 8
	store := newStoreForConformance(t, capacity)
	later := time.Now().Add(time.Hour)
	for round := 0; round < 4; round++ {
		for i := 0; i < 5*capacity; i++ {
			id := fmt.Sprintf("token-%d", i)
			store.Accept("issuer", id, later)
			if got := store.Len(); got > capacity {
				t.Fatalf("round %d token %d: Len() = %d exceeds the configured capacity %d",
					round, i, got, capacity)
			}
			// replay what is still remembered; this must never grow the store
			store.Accept("issuer", id, later)
			if got := store.Len(); got > capacity {
				t.Fatalf("round %d replay of token %d: Len() = %d exceeds capacity %d",
					round, i, got, capacity)
			}
		}
	}
}

// The model: a refusal is inert - nothing recorded, nothing evicted. A client which only
// replays cannot push the token it is replaying out of the store.
func TestConformanceReplayAttemptsCannotEvict(t *testing.T) {
	store := newStoreForConformance(t, 1)
	key, id := "https://idp/|only", "only"
	later := time.Now().Add(time.Hour)
	if !store.Accept(key, id, later) {
		t.Fatal("first presentation was refused")
	}
	for i := 0; i < 100; i++ {
		if store.Accept(key, id, later) {
			t.Fatalf("replay %d was accepted", i)
		}
	}
	if got := store.Len(); got != 1 {
		t.Fatalf("100 replays changed the store size: Len() = %d, want 1", got)
	}
	// the entry is still live, so the token is still a replay: the store still knows it
	if store.Accept(key, id, later) {
		t.Fatal("the store forgot the token it was replaying")
	}
}

// The model: newCapacity normalises below one to one, and one entry is enough to catch the
// replay of the token just accepted.
func TestConformanceOneEntryStoreStillCatchesReplay(t *testing.T) {
	store := newStoreForConformance(t, 0)
	key, id := "https://idp/|only", "only"
	later := time.Now().Add(time.Hour)
	if !store.Accept(key, id, later) {
		t.Fatal("first presentation was refused")
	}
	if store.Accept(key, id, later) {
		t.Fatal("a store configured with 0 entries accepted a replay")
	}
	if got := store.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
}

// The model: at capacity the token accepted first is the one given up. The consequence - the
// forgotten token can be presented again - is the price of the bound, and is worth stating in
// a test because it is the behaviour an operator debugging a login loop will see.
func TestConformanceAtCapacityTheOldestIsGivenUp(t *testing.T) {
	store := newStoreForConformance(t, 2)
	later := time.Now().Add(time.Hour)
	for _, id := range []string{"oldest", "newer"} {
		if !store.Accept("issuer", id, later) {
			t.Fatalf("first presentation of %s was refused", id)
		}
	}
	if !store.Accept("issuer", "incoming", later) {
		t.Fatal("a new token was refused although it is not a replay")
	}
	if got := store.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
	// the token which was forgotten can be presented again: that is the horizon the bound buys
	if !store.Accept("issuer", "oldest", later) {
		t.Fatal("the token accepted first was not given up, although the store is full")
	}
	// "incoming" is now the newest, so re-presenting it is a replay; "newer" was pushed out by
	// the eviction, and presenting it again is accepted
	if store.Accept("issuer", "incoming", later) {
		t.Fatal("a token which was just accepted was accepted again")
	}
	if got := store.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
}

// The implementation remembers a token whose expiry is already past for a minute rather than
// not at all, so a replay of it is still caught. Checking expiry is somebody else's job; this
// is here because the model abstracts the clock away, and this is one place where the abstract
// answer ("the entry is live or it is not") has a concrete edge worth pinning.
func TestConformanceExpiredTokenIsStillNotReplayableImmediately(t *testing.T) {
	store := newStoreForConformance(t, 4)
	key, id := "https://idp/|stale", "stale"
	before := time.Now().Add(-time.Hour)
	if !store.Accept(key, id, before) {
		t.Fatal("first presentation of the expired token was refused")
	}
	if store.Accept(key, id, before) {
		t.Fatal("an expired token was replayed straight through the store")
	}
}

package oidc

import (
	"sync"
	"time"
)

// AcceptedTokenStore records the OpenID Connect tokens which have been accepted, so a
// token cannot be presented twice.
//
// A raw ID token is a bearer credential: whoever holds a copy of it can authenticate,
// and nothing in the token itself prevents it from being handed over again after it was
// already used - by the same client which retries, or by anybody who got a copy of it.
// Remembering what was accepted, keyed on the issuer and on the unique identifier of the
// token, is what turns "verified once" into "verified once and only once".
//
// The store is deliberately bounded: an unbounded map fed with names received from the
// network would itself become a memory-exhaustion vector. Entries are forgotten once the
// token expired, which is when forgetting them stops being dangerous.
type AcceptedTokenStore struct {
	mutex      sync.Mutex
	accepted   map[string]time.Time
	orderUsed  []string
	maxEntries int
	// now is overridable for tests
	now func() time.Time
}

// NewAcceptedTokenStore creates a store remembering at most maxEntries tokens.
func NewAcceptedTokenStore(maxEntries int) *AcceptedTokenStore {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &AcceptedTokenStore{
		accepted:   make(map[string]time.Time),
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// Accept records the token identified by issuer and id, and tells whether it may be
// accepted: it returns false when that very token has already been accepted and has not
// expired yet, in which case the caller is looking at a replay.
func (s *AcceptedTokenStore) Accept(issuer string, id string, expiry time.Time) bool {
	if id == "" {
		// without an identifier there is nothing to deduplicate the token on
		return false
	}
	key := issuer + "|" + id

	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := s.now()
	if when, seen := s.accepted[key]; seen && (expiry.IsZero() || when.After(now)) {
		return false
	}
	s.evictExpired(now)
	// remember the token at least until it expires: past that date it can no longer be
	// verified anyway, so it can no longer be replayed either
	until := expiry
	if until.Before(now) {
		until = now.Add(time.Minute)
	}
	if _, exists := s.accepted[key]; !exists {
		s.orderUsed = append(s.orderUsed, key)
	}
	s.accepted[key] = until
	return true
}

// evictExpired drops the entries whose token expired, and, when the store is still too
// large, the oldest ones. Must be called with the lock held.
func (s *AcceptedTokenStore) evictExpired(now time.Time) {
	for key, until := range s.accepted {
		if until.Before(now) {
			delete(s.accepted, key)
		}
	}
	// the order slice may refer to keys which are gone: rebuild it when it grew too much
	if len(s.orderUsed) > s.maxEntries || len(s.orderUsed) > 2*len(s.accepted) {
		kept := s.orderUsed[:0]
		for _, key := range s.orderUsed {
			if _, ok := s.accepted[key]; ok {
				kept = append(kept, key)
			}
		}
		s.orderUsed = kept
	}
	for len(s.accepted) >= s.maxEntries && len(s.orderUsed) > 0 {
		oldest := s.orderUsed[0]
		s.orderUsed = s.orderUsed[1:]
		delete(s.accepted, oldest)
	}
}

// Len returns how many tokens are remembered.
func (s *AcceptedTokenStore) Len() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return len(s.accepted)
}

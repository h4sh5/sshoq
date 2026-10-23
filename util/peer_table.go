package util

import "sync"

// PeerTable remembers one value per remote address, and refuses to grow past a bound.
//
// It exists for the UDP forwardings, which open one channel per address the datagrams come
// from: without a bound, anything able to throw datagrams at the forwarded port - a
// broadcast or multicast address included - would get one channel, one goroutine and one
// table entry each, and keep them, since a peer which goes away without saying so is never
// noticed.
//
// The values are handled by whoever owns the table; the table only owns the keys, so the
// owner is responsible for releasing what it stores when it drops it, with Remove.
type PeerTable[V any] struct {
	mutex      sync.Mutex
	entries    map[string]V
	maxEntries int
}

// NewPeerTable creates a table holding at most maxEntries peers.
func NewPeerTable[V any](maxEntries int) *PeerTable[V] {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &PeerTable[V]{entries: make(map[string]V), maxEntries: maxEntries}
}

// Get returns the value remembered for a peer, if any.
func (t *PeerTable[V]) Get(peer string) (V, bool) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	value, ok := t.entries[peer]
	return value, ok
}

// Add remembers a value for a peer, and returns false - without storing anything - when the
// table already holds maxEntries peers.
func (t *PeerTable[V]) Add(peer string, value V) bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if _, exists := t.entries[peer]; !exists && len(t.entries) >= t.maxEntries {
		return false
	}
	t.entries[peer] = value
	return true
}

// Remove forgets a peer, making room for the next one.
func (t *PeerTable[V]) Remove(peer string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	delete(t.entries, peer)
}

// Len returns how many peers are remembered.
func (t *PeerTable[V]) Len() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return len(t.entries)
}

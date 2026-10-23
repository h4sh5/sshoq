package util

import "testing"

func TestPeerTableRemembersPeers(t *testing.T) {
	table := NewPeerTable[int](2)

	if _, ok := table.Get("10.0.0.1:1234"); ok {
		t.Fatal("an empty table must not know anybody")
	}
	if !table.Add("10.0.0.1:1234", 1) {
		t.Fatal("a table with room refused a peer")
	}
	if value, ok := table.Get("10.0.0.1:1234"); !ok || value != 1 {
		t.Fatalf("expected the value which was stored, got %d (found: %v)", value, ok)
	}
	if !table.Add("10.0.0.2:1234", 2) {
		t.Fatal("a table with room refused a peer")
	}
	// replacing the value of a known peer is not a new peer
	if !table.Add("10.0.0.1:1234", 3) {
		t.Fatal("replacing the value of a known peer was refused")
	}
	if table.Len() != 2 {
		t.Fatalf("replacing the value of a known peer added an entry: %d", table.Len())
	}

	if table.Add("10.0.0.3:1234", 4) {
		t.Fatal("a full table accepted one more peer")
	}
	if _, ok := table.Get("10.0.0.3:1234"); ok {
		t.Fatal("a refused peer still ended up in the table")
	}

	table.Remove("10.0.0.2:1234")
	if !table.Add("10.0.0.3:1234", 4) {
		t.Fatal("a peer which left did not make room for the next one")
	}
}

// A table created with a bound which makes no sense must still hold one peer, rather than
// refuse everybody and forward nothing at all.
func TestPeerTableMinimumBound(t *testing.T) {
	table := NewPeerTable[int](0)
	if !table.Add("peer", 1) {
		t.Fatal("a table created with a bound of 0 refuses every peer")
	}
	if table.Add("another peer", 2) {
		t.Fatal("a table created with a bound of 0 accepts more than one peer")
	}
}

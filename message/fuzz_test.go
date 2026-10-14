package message

import (
	"bytes"
	"testing"

	"github.com/h4sh5/sshoq/util"
)

// FuzzParseMessage feeds the message parser with whatever a peer sends.
//
// It exists because ParseMessage used to answer an unknown message type with
// panic("not implemented"), and it is called from goroutines which quic-go does not
// protect: one byte from a peer stopped the process, every session of every other user
// included. The parsers must now answer an error for anything malformed, however weird
// the input, and they must never allocate what the input merely announces - which is
// what the length ceilings of util.ParseSSHString are for.
//
// Run the seed corpus with "go test -run Fuzz ./message/", and the real thing with
// "go test -fuzz FuzzParseMessage -fuzztime 60s ./message/".
func FuzzParseMessage(f *testing.F) {
	seeds := [][]byte{
		{},                       // nothing at all
		{0x01},                   // a message type nobody knows
		{0x00},                   // channel open confirmation, truncated
		{0x00, 0x01, 0x02},       // ditto, slightly longer
		{0x02, 0x00},             // channel open failure, truncated
		{0x03, 0x00, 0x00},       // data, truncated
		{0x04, 0x00, 0x00, 0x00}, // extended data, truncated
		{0x05, 0x00, 0x00},       // channel request, truncated
		{0x05, 0x00, 0x07, 't', 'y', 'p', 'e', 0x00}, // request with a type and no payload
		// a request announcing a string of 2^62-1 bytes: the length must be refused
		// before anything is allocated for it
		{0x05, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		{0x05, 0x00, 0x04, 'p', 't', 'y', 0, 0x00, 0x00, 0x00},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// whatever comes out, it must come out as a message or as an error - never as a
		// panic, which would be the end of the process
		msg, err := ParseMessage(util.NewReader(bytes.NewReader(data)))
		if err != nil && msg != nil {
			t.Fatalf("ParseMessage returned both a message and an error: %v / %v", msg, err)
		}
		if msg != nil && msg.Length() < 0 {
			t.Fatalf("a message cannot have a negative length: %d", msg.Length())
		}
	})
}

// FuzzParseSSHString checks that the length-prefixed primitives refuse an announced
// length they would not be able to honour instead of trying to allocate it: a few
// bytes from the peer must never be an allocation request for the whole process.
func FuzzParseSSHString(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x00},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // 2^62-1
		{0x80, 0x80, 0x80, 0x80, 0x08},
		{0x05, 'h', 'e', 'l', 'l', 'o'},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		limited := util.NewLengthLimitedReader(util.NewReader(bytes.NewReader(data)), 1024)
		if s, err := util.ParseSSHString(limited); err == nil && len(s) > 1024 {
			t.Fatalf("a field of %d bytes accepted although the reader accepts 1024", len(s))
		}
		if b, err := util.ParseSSHBytes(limited); err == nil && len(b) > 1024 {
			t.Fatalf("a byte field of %d bytes accepted although the reader accepts 1024", len(b))
		}
	})
}

package sftp

// The sftp frames are the only part of sshoq that a logged-in peer gets to feed in as raw bytes:
// `DecodeRequest` and `DecodeResponse` take whatever came over the wire and turn it into a
// `Request`/`Response` struct, and both ends of a session are peer code. Two things had to be true and
// neither was tested anywhere: that the bounds checks in `frameCursor` really stop every short or
// lying frame (a panic here is a remote crash of the transfer, not an error message), and that the
// size arithmetic used to preallocate a frame agrees with the bytes the encoder writes -- because the
// reused-buffer path, `encodeRequestFrameInto`/`encodeResponseFrameInto`, is handed exactly that many
// bytes by its caller and would write past them otherwise (finding **F18** is what this file turned
// up on the encoding side: the string prefix is a `uint16` and nothing says so).
//
// The frames are also the boundary SR-PARSE-03 does not cover: that row is the QUIC varint and the
// field ceiling of the transport, which is proved in `util`. These are the SFTP packet fields, which
// are big-endian fixed-width integers and length-prefixed strings.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// requestSamples are frames of every shape the encoders have to handle, including the empty ones, the
// shapes the size arithmetic gets wrong most easily: no path, no data, a one-byte path, a path with
// embedded NUL and newline, and a path at the 65535-byte ceiling of the two-byte length prefix.
func requestSamples() []*Request {
	return []*Request{
		{ID: 0, Cmd: "pwd"},
		{ID: 1, Cmd: "cd", Path: "/tmp"},
		{ID: 2, Cmd: "ls", Path: "/"},
		{ID: 3, Cmd: "stat", Path: "x"},
		{ID: 4, Cmd: "get", Path: "/srv/in.bin", Offset: 4096, Limit: 32768},
		{ID: 5, Cmd: "put", Path: "/srv/out.bin", Data: []byte("hello")},
		{ID: 6, Cmd: "put", Path: "", Data: []byte{}},
		{ID: 7, Cmd: "rm", Path: "a\x00b\ncé\n"},
		{ID: 8, Cmd: "mkdir", Path: strings.Repeat("d/", 500) + "leaf"},
		{ID: 9, Cmd: "rmdir", Path: strings.Repeat("x", 65535)},
		{ID: ^uint64(0), Cmd: "get", Offset: -1, Limit: 0},
		{ID: 11, Cmd: "get", Offset: -9223372036854775808},
	}
}

func responseSamples() []*Response {
	info := &FileInfo{
		Name: "leaf", Size: 7, Mode: 0o644, LinkTarget: "/srv/leaf",
		ModTime: 1700000000, UID: 1000, GID: 1000, UserName: "alice", GroupName: "users",
	}
	return []*Response{
		{ID: 0, OK: true},
		{ID: 1, OK: false, Error: "no such file"},
		{ID: 2, OK: true, Path: "/tmp/x"},
		{ID: 3, OK: true, Data: []byte("payload")},
		{ID: 4, OK: true, Data: []byte{}},
		{ID: 5, OK: true, Entries: []FileInfo{*info}},
		{ID: 6, OK: true, Entries: []FileInfo{*info, {Name: "dir", IsDir: true}}},
		{ID: 7, OK: true, Info: info},
		{ID: 8, OK: true, Info: &FileInfo{Name: "", LinkTarget: "", UserName: "", GroupName: ""}},
		{ID: 9, OK: true, Error: strings.Repeat("e", 70000)},
	}
}

// mustDecodeRequest runs DecodeRequest and turns a panic into a test failure naming the frame, so that
// the robustness loops below report the byte offset that killed the parser instead of dying themselves.
func mustDecodeRequest(t *testing.T, payload []byte) (*Request, error) {
	t.Helper()
	var (
		req Request
		err error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DecodeRequest panicked on a %d-byte payload: %v", len(payload), r)
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		err = DecodeRequest(payload, &req)
	}()
	return &req, err
}

func mustDecodeResponse(t *testing.T, payload []byte) (*Response, error) {
	t.Helper()
	var (
		resp Response
		err  error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("DecodeResponse panicked on a %d-byte payload: %v", len(payload), r)
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		err = DecodeResponse(payload, &resp)
	}()
	return &resp, err
}

// TestConformanceRequestsRoundTripThroughTheirOwnBytes is the identity claim: what the encoder writes,
// the decoder reads back. A sample that only differs by an empty versus nil slice is included because
// that is the difference a decoder produces and a caller must tolerate.
func TestConformanceRequestsRoundTripThroughTheirOwnBytes(t *testing.T) {
	for _, want := range requestSamples() {
		frame := EncodeRequest(want)
		if prefix := binary.BigEndian.Uint32(frame[:4]); int(prefix) != len(frame)-4 {
			t.Fatalf("%#v: length prefix %d, payload %d bytes", want, prefix, len(frame)-4)
		}
		got, err := mustDecodeRequest(t, frame[4:])
		if err != nil {
			t.Fatalf("%#v: %v", want, err)
		}
		if got.ID != want.ID || got.Cmd != want.Cmd || got.Path != want.Path || got.Offset != want.Offset {
			t.Errorf("round trip: got %+v, want %+v", got, want)
		}
		if got.Limit != want.Limit {
			t.Errorf("%#v: limit round-tripped as %d", want, got.Limit)
		}
		if !bytes.Equal(got.Data, want.Data) {
			t.Errorf("%#v: data round-tripped as %q", want, got.Data)
		}
	}
}

// TestConformanceResponsesRoundTripThroughTheirOwnBytes is the same claim for the richer shape, with
// entries, with an info struct, with both, and with neither.
func TestConformanceResponsesRoundTripThroughTheirOwnBytes(t *testing.T) {
	for _, want := range responseSamples() {
		if len(want.Error) > 0xFFFF {
			continue // covered by TestConformanceStringFieldsOverSixtyFiveThousandBytesAreTruncated
		}
		frame := EncodeResponse(want)
		if prefix := binary.BigEndian.Uint32(frame[:4]); int(prefix) != len(frame)-4 {
			t.Fatalf("%#v: length prefix %d, payload %d bytes", want, prefix, len(frame)-4)
		}
		got, err := mustDecodeResponse(t, frame[4:])
		if err != nil {
			t.Fatalf("%#v: %v", want, err)
		}
		if got.ID != want.ID || got.OK != want.OK || got.Error != want.Error || got.Path != want.Path {
			t.Errorf("round trip: got %+v, want %+v", got, want)
		}
		if !bytes.Equal(got.Data, want.Data) {
			t.Errorf("%#v: data round-tripped as %q", want, got.Data)
		}
		if len(got.Entries) != len(want.Entries) {
			t.Fatalf("%#v: %d entries, want %d", want, len(got.Entries), len(want.Entries))
		}
		for i := range want.Entries {
			a, b := got.Entries[i], want.Entries[i]
			if a.Name != b.Name || a.Size != b.Size || a.Mode != b.Mode || a.IsDir != b.IsDir ||
				a.IsSymlink != b.IsSymlink || a.LinkTarget != b.LinkTarget || a.ModTime != b.ModTime ||
				a.UID != b.UID || a.GID != b.GID || a.UserName != b.UserName || a.GroupName != b.GroupName {
				t.Errorf("entry %d: got %+v, want %+v", i, a, b)
			}
		}
		if (want.Info == nil) != (got.Info == nil) {
			t.Fatalf("%#v: info presence lost", want)
		}
		if want.Info != nil && *got.Info != *want.Info {
			t.Errorf("info: got %+v, want %+v", *got.Info, *want.Info)
		}
	}
}

// TestConformanceSizeHelpersMatchTheBytesWritten pins the arithmetic the reused-buffer path depends on.
// `EncodeResponse` hands `encodeResponseFrameInto` exactly `responseFrameSize` bytes of capacity, and
// `encodeRequestFrameInto` is handed a caller's buffer; if the estimate were short, the encoder would
// realloc in the reused case (harmless) or, with a buffer sized by the same arithmetic, write out of
// range. `fileInfoFrameSize` is the term the estimate is built from, so it is pinned through a response
// that carries entries and an info struct.
func TestConformanceSizeHelpersMatchTheBytesWritten(t *testing.T) {
	for _, resp := range responseSamples() {
		if got, written := responseFrameSize(resp), len(EncodeResponse(resp)); got != written {
			t.Errorf("responseFrameSize = %d, EncodeResponse wrote %d bytes: %+v", got, written, resp)
		}
	}
	// the request size is written inline in EncodeRequest rather than named; pin it the same way
	for _, req := range requestSamples() {
		frame := EncodeRequest(req)
		want := 4 + 1 + 8 + 2 + len(req.Path) + 8 + 4 + 4 + len(req.Data)
		if len(req.Path) > 0xFFFF {
			continue // the two-byte prefix, see F18
		}
		if len(frame) != want {
			t.Errorf("%#v: the inline size is %d, the encoder wrote %d", req, want, len(frame))
		}
	}
}

// TestConformanceEveryTruncationOfAFrameIsAnError is the parser's whole safety claim in one loop: cut a
// valid frame anywhere and the decoder must say no. `frameCursor.take` is the single check behind it
// (`n < 0 || c.pos+n > len(c.b)`), and it is checked here against every prefix rather than against the
// three cases someone thought of.
func TestConformanceEveryTruncationOfAFrameIsAnError(t *testing.T) {
	for _, req := range requestSamples() {
		frame := EncodeRequest(req)[4:]
		for cut := 0; cut < len(frame); cut++ {
			if _, err := mustDecodeRequest(t, frame[:cut]); err == nil {
				t.Fatalf("a request frame truncated to %d of %d bytes decoded without an error", cut, len(frame))
			}
		}
	}
	for _, resp := range responseSamples() {
		frame := EncodeResponse(resp)[4:]
		if len(frame) > 2048 {
			frame = frame[:2048] // the 70 KB-error sample, whose prefixes are covered by the short ones
		}
		for cut := 0; cut < len(frame); cut++ {
			if _, err := mustDecodeResponse(t, frame[:cut]); err == nil {
				t.Fatalf("a response frame truncated to %d of %d bytes decoded without an error", cut, len(frame))
			}
		}
	}
}

// TestConformancePoisonedLengthFieldsCannotReadPastTheFrame is the same claim in the other direction:
// the frame is long enough to look structured but its length fields lie. Every four-byte window of a
// valid frame is set to 0xFFFFFFFF, 0x80000000 and 0x7FFFFFFF in turn -- which is where a `uint32`
// length read by a peer lands when it is meant to be a count or a negative number -- and the decoder
// must refuse or, if it happens to decode, must not have read past the payload it was given.
func TestConformancePoisonedLengthFieldsCannotReadPastTheFrame(t *testing.T) {
	poisons := []uint32{0xFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0x0000FFFF}
	for _, req := range requestSamples() {
		{
			frame := EncodeRequest(req)
			for i := 4; i+4 <= len(frame); i++ {
				for _, poison := range poisons {
					mutated := append([]byte{}, frame...)
					binary.BigEndian.PutUint32(mutated[i:], poison)
					// the answer may be "decoded" only where the poisoned window was a value
					// field rather than a length; the property under test is the absence of a
					// panic and of a read past the frame, both checked inside mustDecodeRequest
					_, _ = mustDecodeRequest(t, mutated[4:])
				}
			}
		}
	}
	for _, resp := range responseSamples() {
		{
			frame := EncodeResponse(resp)
			if len(frame) > 4096 {
				frame = frame[:4096]
			}
			for i := 4; i+4 <= len(frame); i++ {
				for _, poison := range poisons {
					mutated := append([]byte{}, frame...)
					binary.BigEndian.PutUint32(mutated[i:], poison)
					_, _ = mustDecodeResponse(t, mutated[4:])
				}
			}
		}
	}
}

// TestConformanceSingleByteMutationsNeverPanic is a deterministic fuzz: every byte of a valid frame
// replaced by every value a byte can take. No allocation here depends on the mutated byte in a way the
// parser could be talked into -- the entry count is the one field that does, and it is bounded by
// maxEntries, which the next test pins -- so the claim under test is that no byte of a peer's frame can
// make the parser crash or run off the end.
func TestConformanceSingleByteMutationsNeverPanic(t *testing.T) {
	frame := EncodeRequest(&Request{ID: 3, Cmd: "get", Path: "/a/b", Offset: 1, Limit: 2, Data: []byte("xy")})[4:]
	for i := range frame {
		for v := 0; v < 256; v++ {
			mutated := append([]byte{}, frame...)
			mutated[i] = byte(v)
			_, _ = mustDecodeRequest(t, mutated)
		}
	}
	response := EncodeResponse(&Response{ID: 3, OK: true, Path: "/a", Entries: []FileInfo{{Name: "n"}}})[4:]
	for i := range response {
		for v := 0; v < 256; v++ {
			mutated := append([]byte{}, response...)
			mutated[i] = byte(v)
			_, _ = mustDecodeResponse(t, mutated)
		}
	}
}

// TestConformanceEntryCountIsRefusedBeforeItIsAllocated is the one field whose value the decoder turns
// into an allocation: `make([]FileInfo, 0, count)`. The guard is `count > maxEntries`, and it is checked
// before the make; the test distinguishes *that* refusal from an incidental truncation error, because
// the guard moving after the allocation is exactly the change that would let a peer ask the server for
// four gigabytes with eight bytes on the wire.
func TestConformanceEntryCountIsRefusedBeforeItIsAllocated(t *testing.T) {
	// ID(8) OK(1) error-len(2) path-len(2) count(4): with no error and no path the count starts at
	// offset 13 of the payload, i.e. 17 of the frame.
	frame := EncodeResponse(&Response{ID: 1, OK: true})
	const countOffset = 4 + 8 + 1 + 2 + 2
	if got := binary.BigEndian.Uint32(frame[countOffset:]); got != 0 {
		t.Fatalf("the sample frame does not have its entry count where this test assumes, found %d", got)
	}
	for _, tc := range []struct {
		count     uint32
		wantError bool // whether the frame must be refused at all
		tooMany   bool // whether "too many entries" specifically must be the answer
	}{
		{0, false, false}, // the frame as it was encoded: zero entries, nothing to refuse
		{maxEntries + 1, true, true},
		{0xFFFFFFFF, true, true},
		{0x80000000, true, true},
		// accepted as a count and then refused because no entries follow: the guard is the thing
		// under test, so the test insists on which error says no
		{maxEntries, true, false},
		{1, true, false},
	} {
		mutated := append([]byte{}, frame...)
		binary.BigEndian.PutUint32(mutated[countOffset:], tc.count)
		_, err := mustDecodeResponse(t, mutated[4:])
		if (err != nil) != tc.wantError {
			t.Fatalf("count %d: err = %v, want an error: %v", tc.count, err, tc.wantError)
		}
		if err == nil {
			continue
		}
		if got := strings.Contains(err.Error(), "too many entries"); got != tc.tooMany {
			t.Errorf("count %d: %q, want the too-many-entries refusal: %v", tc.count, err, tc.tooMany)
		}
	}
}

// TestConformanceCommandCodesAreSymmetricAndUnknownIsInert covers the one byte of a request frame that
// decides *what happens*: nine commands, codes 1..9, with 0 reserved for "nobody". `cmdCode` returns 0
// for a string it does not know and `cmdName` returns "" for a code it does not know, so an unknown
// code travels as an empty command and the server's own switch answers "unknown command" (server.go).
// What would be dangerous is a collision -- a string that encodes to a valid other command -- so the
// codes are required to be distinct and the round trip required to be exact.
func TestConformanceCommandCodesAreSymmetricAndUnknownIsInert(t *testing.T) {
	commands := []string{"pwd", "cd", "ls", "stat", "get", "put", "mkdir", "rm", "rmdir"}
	seen := map[byte]string{}
	for _, cmd := range commands {
		code := cmdCode(cmd)
		if code == 0 {
			t.Errorf("%q has no command code", cmd)
		}
		if other, clash := seen[code]; clash {
			t.Errorf("%q and %q share code %d", cmd, other, code)
		}
		seen[code] = cmd
		if back := cmdName(code); back != cmd {
			t.Errorf("code %d decodes as %q, want %q", code, back, cmd)
		}
	}
	if len(seen) != len(commands) {
		t.Fatalf("%d codes for %d commands", len(seen), len(commands))
	}
	for code := 0; code < 256; code++ {
		if _, known := seen[byte(code)]; known {
			continue
		}
		if name := cmdName(byte(code)); name != "" {
			t.Errorf("unknown code %d decodes as %q", code, name)
		}
		if got := cmdCode(cmdName(byte(code))); got != 0 {
			t.Errorf("an unknown code re-encodes as %d", got)
		}
	}
	for _, unknown := range []string{"", "PWD", "Get", "rm -r", "cd ", "symlink"} {
		if code := cmdCode(unknown); code != 0 {
			t.Errorf("%q encodes as %d rather than the unknown code 0", unknown, code)
		}
	}
}

// TestConformanceStringFieldsOverSixtyFiveThousandBytesAreTruncated is finding F18, stated as the
// behaviour it has rather than the behaviour it wants. `appendStr` writes `uint16(len(s))`, and nothing
// checks the length first: a path, an error string, a file name or a user name longer than 65535 bytes
// goes on the wire with a prefix that is its length modulo 65536, and the peer reads a short string
// followed by what it will take for the rest of the frame. The decoder survives it (the bounds checks
// hold, and the tests above are about surviving), so this is a corrupted transfer rather than a memory
// error -- but it is silent, and the strings that reach 64 KiB are the ones a server builds out of
// other people's paths.
func TestConformanceStringFieldsOverSixtyFiveThousandBytesAreTruncated(t *testing.T) {
	long := strings.Repeat("x", 65536)

	frame := EncodeRequest(&Request{ID: 1, Cmd: "cd", Path: long})
	payload := frame[4:]
	// code(1) id(8) then the two-byte length prefix of the path
	if declared := binary.BigEndian.Uint16(payload[9:11]); declared != 0 {
		t.Errorf("a 65536-byte path is announced as %d bytes; this test records the wrap, so that a length check in appendStr is a decision", declared)
	}
	if _, err := mustDecodeRequest(t, payload); err == nil {
		t.Errorf("a frame whose path length wrapped decoded without an error; the peer would have read %q as the path", long[:0])
	}

	// the same one byte below the ceiling is fine, which is what makes the ceiling the interesting number
	short := strings.Repeat("x", 65535)
	frame = EncodeRequest(&Request{ID: 1, Cmd: "cd", Path: short})
	req, err := mustDecodeRequest(t, frame[4:])
	if err != nil || req.Path != short {
		t.Fatalf("a 65535-byte path: %q, %v", req.Path, err)
	}
}

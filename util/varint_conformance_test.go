package util

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// varint.go proves the arithmetic of wire lengths over every input. What these tests hold is the
// seam: that VarIntLen is the length AppendVarInt actually writes, that SSHStringLen and
// SSHBytesLen are the size WriteSSHString and WriteSSHBytes actually need, and that the ceiling the
// parser applies is the one fieldCeiling computes -- including the case the ceiling exists for, a
// peer that announces 2^62-1 in a message of a few bytes. Without these, the proofs would be about
// three functions that nothing calls.

// TestConformanceVarIntLenIsWhatAppendVarIntWrites walks every boundary of the format, and the
// values either side of each, and compares the proved length with the bytes the encoder produces.
// A disagreement here is a framing desynchronisation on a locally chosen value: the writer would
// emit a prefix that promises a different number of bytes than it wrote, and the peer would read
// the rest of the packet as part of the number.
func TestConformanceVarIntLenIsWhatAppendVarIntWrites(t *testing.T) {
	values := []uint64{
		0, 1, 62, 63, 64, 65,
		16382, 16383, 16384, 16385,
		1073741822, 1073741823, 1073741824, 1073741825,
		1 << 32, 1 << 40, 1 << 56,
		Max, Max - 1,
	}
	for _, prefix := range [][]byte{nil, {0xAA}, {0xAA, 0xBB, 0xCC}} {
		for _, i := range values {
			want := VarIntLen(i)
			out := AppendVarInt(append([]byte(nil), prefix...), i)
			if got := uint64(len(out) - len(prefix)); got != want {
				t.Fatalf("VarIntLen(%d) = %d, AppendVarInt wrote %d bytes", i, want, got)
			}
			// the prefix is untouched, and the number reads back as itself
			if !bytes.Equal(out[:len(prefix)], prefix) {
				t.Fatalf("AppendVarInt(%d) overwrote the %d bytes already in the buffer", i, len(prefix))
			}
			back, err := ReadVarInt(NewReader(bytes.NewReader(out[len(prefix):])))
			if err != nil {
				t.Fatalf("ReadVarInt of the encoding of %d: %v", i, err)
			}
			if back != i {
				t.Fatalf("%d encodes to %x and reads back as %d", i, out[len(prefix):], back)
			}
		}
	}
}

// TestConformanceVarIntLenThresholdsAreTheFormat checks the four proved ranges directly, at the
// endpoints and one step either side, rather than at sampled values: the boundaries are where an
// off-by-one in a threshold lives, and 63/64, 16383/16384 and 1073741823/1073741824 are the three
// places the format changes width.
func TestConformanceVarIntLenThresholdsAreTheFormat(t *testing.T) {
	cases := []struct {
		i    uint64
		want uint64
	}{
		{0, 1}, {63, 1},
		{64, 2}, {16383, 2},
		{16384, 4}, {1073741823, 4},
		{1073741824, 8}, {Max, 8},
	}
	for _, c := range cases {
		if got := VarIntLen(c.i); got != c.want {
			t.Errorf("VarIntLen(%d) = %d, want %d", c.i, got, c.want)
		}
		// the width is encoded in the top two bits of the first byte, so the encoder must agree
		// with the length function in the way the format says it does
		out := AppendVarInt(nil, c.i)
		if got := out[0] >> 6; uint64(1)<<got != c.want {
			t.Errorf("the first byte of the encoding of %d has length bits %d, which means %d bytes, but VarIntLen says %d",
				c.i, got, 1<<got, c.want)
		}
	}
	// and the value above the format's range is a panic, not a silent wide encoding: no peer can
	// announce it (ReadVarInt produces at most 62 bits), so this is a local-programming error
	func() {
		defer func() {
			if recover() == nil {
				t.Errorf("VarIntLen(%d) did not panic, although %d is above the 62-bit range", Max+1, Max+1)
			}
		}()
		_ = VarIntLen(Max + 1)
	}()
}

// TestConformanceVarIntEncodingIsCanonical checks what the round trip cannot: that the bytes written
// are the canonical short encoding, i.e. no value is written in more bytes than it needs. It is the
// reader that is lenient here -- ReadVarInt accepts a 1 in eight bytes -- so a writer that padded
// would break peers that compare encodings, and nothing would fail locally.
func TestConformanceVarIntEncodingIsCanonical(t *testing.T) {
	// the widths, in bytes, of the four ranges the format defines
	thresholds := []uint64{63, 16383, 1073741823, Max}
	for _, i := range []uint64{0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, Max} {
		out := AppendVarInt(nil, i)
		l := len(out)
		// the payload bits, reassembled the way the format says, must be the value
		var got uint64
		for _, b := range out[1:] {
			got = got<<8 | uint64(b)
		}
		got |= uint64(out[0]&0x3f) << uint(8*(l-1))
		if got != i {
			t.Fatalf("%d encoded as %x decodes to %d", i, out, got)
		}
		// canonical: written in the width the proved length function promises, and the width bits
		// in the first byte say the same thing
		if uint64(l) != VarIntLen(i) {
			t.Fatalf("%d written in %d bytes, VarIntLen promises %d", i, l, VarIntLen(i))
		}
		var rangeIdx int
		for rangeIdx = 0; rangeIdx < 4; rangeIdx++ {
			if i <= thresholds[rangeIdx] {
				break
			}
		}
		if wantWidth := []int{1, 2, 4, 8}[rangeIdx]; l != wantWidth {
			t.Fatalf("%d belongs in the %d byte range and was written in %d bytes", i, wantWidth, l)
		}
		if i > 63 && i <= 16383 && out[0]>>6 != 0b01 {
			t.Fatalf("%d: width bits %d do not say two bytes", i, out[0]>>6)
		}
		// and the proved lemma, so that it cannot rot into saying something else
		if !varIntLenNeverShrinks(0, i) || !varIntLenNeverShrinks(i, Max) {
			t.Fatalf("varIntLenNeverShrinks disagrees with itself at %d", i)
		}
	}
}

// TestConformanceSSHFieldLensAreTheBytesWritten pins SSHStringLen and SSHBytesLen against the
// writers: the exact size must be accepted, and one byte less must be refused. A length helper that
// over-promises costs a copy of wasted buffer; one that under-promises makes WriteSSHString write
// past what the caller allocated for it, which is the reason the callers trust it.
func TestConformanceSSHFieldLensAreTheBytesWritten(t *testing.T) {
	payloads := []string{"", "a", strings.Repeat("x", 62), strings.Repeat("x", 63),
		strings.Repeat("x", 64), strings.Repeat("x", 16383), strings.Repeat("x", 16384),
		strings.Repeat("x", 70000)}
	for _, s := range payloads {
		need := SSHStringLen(s)
		if want := VarIntLen(uint64(len(s))) + uint64(len(s)); int64(need) != int64(want) {
			t.Fatalf("SSHStringLen(%d bytes) = %d, the prefix plus the payload is %d", len(s), need, want)
		}
		out := make([]byte, need)
		n, err := WriteSSHString(out, s)
		if err != nil {
			t.Fatalf("WriteSSHString into exactly %d bytes: %v", need, err)
		}
		if n != need {
			t.Fatalf("WriteSSHString wrote %d bytes into a buffer sized %d by SSHStringLen", n, need)
		}
		// and it must round trip through the parser
		back, err := ParseSSHString(NewReader(bytes.NewReader(out[:n])))
		if err != nil || back != s {
			t.Fatalf("round trip of a %d byte string: %q, %v", len(s), back, err)
		}
		if need > 0 {
			if _, err := WriteSSHString(make([]byte, need-1), s); err == nil {
				t.Errorf("WriteSSHString accepted a buffer of %d bytes for a field of %d", need-1, need)
			}
		}
		b := []byte(s)
		if got := SSHBytesLen(b); got != need {
			t.Fatalf("SSHBytesLen and SSHStringLen disagree for %d bytes: %d vs %d", len(s), got, need)
		}
		nb, err := WriteSSHBytes(make([]byte, SSHBytesLen(b)), b)
		if err != nil || nb != need {
			t.Fatalf("WriteSSHBytes into the size SSHBytesLen promised: %d bytes, %v", nb, err)
		}
	}
}

// TestConformanceFieldCeilingIsTheComparison checks the ceiling function against the comparison
// checkFieldLength used to carry inline, over reader bounds from zero (refuse everything) to far
// above the absolute ceiling (which must not raise it).
func TestConformanceFieldCeilingIsTheComparison(t *testing.T) {
	readerMaxes := []uint64{0, 1, 7, 1 << 20, MaxFieldLength - 1, MaxFieldLength, MaxFieldLength + 1,
		1 << 30, Max}
	for _, readerMax := range readerMaxes {
		want := uint64(MaxFieldLength)
		if limited := readerMax; limited < want {
			want = limited
		}
		if got := fieldCeiling(readerMax); got != want {
			t.Errorf("fieldCeiling(%d) = %d, the inline comparison gives %d", readerMax, got, want)
		}
		if got := MinUint64(readerMax, MaxFieldLength); got != want {
			t.Errorf("MinUint64(%d, MaxFieldLength) = %d, the inline comparison gives %d", readerMax, got, want)
		}
		if got := fieldCeiling(readerMax); got > MaxFieldLength {
			t.Errorf("fieldCeiling(%d) = %d, above the absolute ceiling %d", readerMax, got, MaxFieldLength)
		}
	}
}

// TestConformanceFieldLengthIsCheckedBeforeAllocating drives the real parser -- ParseSSHString and
// ParseSSHBytes through the reader wrappers -- and checks that the accept/refuse boundary is exactly
// the proved predicate, for a plain reader (absolute ceiling) and a length-limited one.
//
// The last case is the one the ceiling exists for: a message of a handful of bytes announcing the
// largest length the varint format can carry. Before the guard existed, that announcement reached
// make() and either exhausted the address space or panicked the process outright.
func TestConformanceFieldLengthIsCheckedBeforeAllocating(t *testing.T) {
	// announce encodes a field header: a varint length, then that many bytes of payload.
	announce := func(length uint64, payloadBytes int) []byte {
		out := AppendVarInt(nil, length)
		return append(out, bytes.Repeat([]byte{'z'}, payloadBytes)...)
	}
	cases := []struct {
		readerMax uint64 // 0 means: a plain reader, which uses the absolute ceiling
		announced []uint64
	}{
		{0, []uint64{0, 1, 3, MaxFieldLength - 1, MaxFieldLength, MaxFieldLength + 1, Max}},
		{4, []uint64{0, 1, 4, 5, MaxFieldLength, Max}},
		{1, []uint64{0, 1, 2, MaxFieldLength}},
	}
	for _, c := range cases {
		for _, announced := range c.announced {
			ceiling := uint64(MaxFieldLength)
			if c.readerMax > 0 && c.readerMax < ceiling {
				ceiling = c.readerMax
			}
			// enough payload that an accepted field could be read in full
			body := announce(announced, int(minUint64(announced, ceiling)))
			for _, which := range []string{"string", "bytes"} {
				r := NewReader(bytes.NewReader(body))
				if c.readerMax > 0 {
					r = NewLengthLimitedReader(NewReader(bytes.NewReader(body)), c.readerMax)
				}
				var err error
				switch which {
				case "string":
					_, err = ParseSSHString(r)
				case "bytes":
					_, err = ParseSSHBytes(r)
				}
				accepted := announced <= ceiling
				if accepted == (err != nil) {
					t.Errorf("%s with a ceiling of %d and an announcement of %d: err=%v, the proved predicate says it is accepted=%v",
						which, ceiling, announced, err, accepted)
				}
				if err != nil && !strings.Contains(err.Error(), "maximum accepted length") && announced > ceiling {
					t.Errorf("%s refused an announcement of %d for the wrong reason: %v", which, announced, err)
				}
			}
		}
	}
	// the allocation bomb itself, spelled out: ten bytes on the wire, 2^62-1 announced
	bomb := announce(Max, 0)
	if len(bomb) > 12 {
		t.Fatalf("the bomb message should be a handful of bytes, it is %d", len(bomb))
	}
	if _, err := ParseSSHString(NewReader(bytes.NewReader(bomb))); err == nil {
		t.Fatalf("ParseSSHString accepted a %d bytes message announcing %d", len(bomb), Max)
	} else if !strings.Contains(err.Error(), "maximum accepted length") {
		t.Fatalf("the bomb was refused for the wrong reason: %v", err)
	}
	if _, err := ParseSSHBytes(NewReader(bytes.NewReader(bomb))); err == nil {
		t.Fatalf("ParseSSHBytes accepted a %d bytes message announcing %d", len(bomb), len(bomb))
	}
}

// minUint64 is the comparison the ceiling is made of, spelled out here so the test's expected values
// do not call the function they check.
func minUint64(a, b uint64) uint64 {
	if a <= b {
		return a
	}
	return b
}

// TestConformanceCheckFieldLengthAgreesWithThePredicate checks checkFieldLength itself -- the
// function the parsers call -- against the proved pair, through a reader that reports a bound and
// one that does not.
func TestConformanceCheckFieldLengthAgreesWithThePredicate(t *testing.T) {
	for _, readerMax := range []uint64{0, 1, 100, MaxFieldLength, MaxFieldLength * 2} {
		for _, length := range []uint64{0, 1, 99, 100, 101, MaxFieldLength - 1, MaxFieldLength, MaxFieldLength + 1} {
			var r Reader = NewReader(bytes.NewReader(nil))
			if readerMax > 0 {
				r = NewLengthLimitedReader(NewReader(bytes.NewReader(nil)), readerMax)
			}
			ceiling := minUint64(MaxFieldLength, readerMax)
			if readerMax == 0 {
				ceiling = MaxFieldLength
			}
			err := checkFieldLength(r, length)
			if accepted := length <= ceiling; accepted == (err != nil) {
				t.Errorf("checkFieldLength(ceiling %d, length %d): err=%v, accepted should be %v", ceiling, length, err, accepted)
			}
			if err != nil && !strings.Contains(fmt.Sprint(err), fmt.Sprintf("announced a %d bytes field", length)) {
				t.Errorf("checkFieldLength(%d) reported %q, which does not name the length the peer announced", length, err)
			}
		}
	}
}

// TestConformanceAppendVarIntWithLenKeepsThePromisedLength covers the third caller of VarIntLen:
// the padded encoding, which panics when the requested width cannot hold the value. The proof says
// how wide a value needs; this says the padded writer follows that, and pads to exactly the width
// the reader will consume.
func TestConformanceAppendVarIntWithLenKeepsThePromisedLength(t *testing.T) {
	for _, width := range []uint64{1, 2, 4, 8} {
		for _, i := range []uint64{0, 1, 63, 1000, 16384, 1073741824} {
			need := VarIntLen(i)
			if need > width {
				// too wide for the requested length: the writer must refuse, not truncate
				func() {
					defer func() {
						if recover() == nil {
							t.Errorf("AppendVarIntWithLen(%d, %d) did not panic, although the value needs %d bytes", i, width, need)
						}
					}()
					_ = AppendVarIntWithLen(nil, i, width)
				}()
				continue
			}
			out := AppendVarIntWithLen(nil, i, width)
			if uint64(len(out)) != width {
				t.Fatalf("AppendVarIntWithLen(%d, %d) wrote %d bytes", i, width, len(out))
			}
			// the width bits must promise exactly `width`, or the reader stops early and the rest
			// of the packet is read as a new message
			if got := []uint64{1, 2, 4, 8}[widthIndex(width)]; got != width {
				t.Fatalf("width %d is not one of the four the format allows", width)
			}
			if bits := []byte{0b00, 0b01, 0b10, 0b11}[widthIndex(width)]; out[0]>>6 != bits {
				t.Fatalf("padded encoding of %d in %d bytes has width bits %d, which promise %d bytes",
					i, width, out[0]>>6, []uint64{1, 2, 4, 8}[out[0]>>6])
			}
			back, err := ReadVarInt(NewReader(bytes.NewReader(out)))
			if err != nil || back != i {
				t.Fatalf("padded encoding of %d in %d bytes reads back as %d (%v)", i, width, back, err)
			}
		}
	}
}

// widthIndex maps an allowed width to its index in the format's table of four.
func widthIndex(width uint64) int {
	switch width {
	case 1:
		return 0
	case 2:
		return 1
	case 4:
		return 2
	}
	return 3
}

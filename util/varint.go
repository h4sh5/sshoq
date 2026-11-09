package util

// The arithmetic of lengths on the wire, verified where it runs.
//
// Everything a peer can make this process do is chosen by the peer, and almost all of it is
// chosen as a *number*: how long a field is, how many bytes a varint occupies, how big a buffer
// a write needs. Those three questions are pure arithmetic, so they are lifted out of `wire.go`
// -- which imports `fmt` for its error values, and `io`, which Gobra v26.09 has no stub for --
// and annotated here where `make proof` can check them. This file imports nothing.
//
// The property that matters, and the reason this is the first file of phase 4, is the one the
// length-limited reader exists for: a length announced by a peer must be bounded *before* it is
// used to allocate. `announcementIsBounded` below is that statement, proved over every announcement
// and every reader bound: whatever the parser accepts, it accepts something no larger than
// `MaxFieldLength`. The reading of bytes stays in `wire.go`, unverified, with
// `varint_conformance_test.go` holding it to these functions.

// taken from the QUIC draft
const (
	// Min is the minimum value allowed for a QUIC varint.
	Min = 0

	// Max is the maximum allowed value for a QUIC varint (2^62-1).
	Max = maxVarInt8

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

const (
	// MaxFieldLength is the absolute ceiling applied to any length-prefixed field
	// (an SSH string, an SSH byte string) read from a peer. Without such a ceiling,
	// a 10-byte message announcing a 2^62-1 length makes the process allocate up to
	// 4 EiB of address space, and any length above Go's maxAlloc makes `make`
	// panic ("makeslice: len out of range"), which kills the whole process.
	// Readers which know a tighter bound (a channel knows the maximum packet size it
	// negotiated with the peer) must use it, see NewLengthLimitedReader.
	MaxFieldLength uint64 = 1 << 24
)

// VarIntLen determines the number of bytes that will be needed to write the number i.
//
// The four clauses are the format itself, boundary included: 63 fits in one byte and 64 does not,
// 16383 fits in two and 16384 does not, and so on. That is worth proving because this function and
// `AppendVarInt` are the two halves of one promise -- if this one is wrong by a byte for some range,
// the writer emits a frame whose length prefix disagrees with its payload and the peer desynchronises
// on a value the local side chose, which is a corruption bug with no error anywhere.
// `TestConformanceVarIntLenIsWhatAppendVarIntWrites` is what says the promise holds of the encoder,
// which lives with the I/O code and cannot be checked here.
//
// The panic for a value above `Max` is reachable only from local code -- a peer cannot announce it,
// `ReadVarInt` produces at most `Max` -- so it is a precondition here rather than a clause.
//
// @ requires i <= Max
// @ ensures 1 <= n && n <= 8
// @ ensures i <= 63 ==> n == 1
// @ ensures 63 < i && i <= 16383 ==> n == 2
// @ ensures 16383 < i && i <= 1073741823 ==> n == 4
// @ ensures 1073741823 < i ==> n == 8
func VarIntLen(i uint64) (n uint64) {
	if i <= maxVarInt1 {
		return 1
	}
	if i <= maxVarInt2 {
		return 2
	}
	if i <= maxVarInt4 {
		return 4
	}
	if i <= maxVarInt8 {
		return 8
	}
	// Don't use a fmt.Sprintf here to format the error message.
	// The function would then exceed the inlining budget.
	panic(struct {
		message string
		num     uint64
	}{"value doesn't fit into 62 bits: ", i})
}

// varIntLenNeverShrinks is the monotonicity of the encoding length: a bigger number never needs
// fewer bytes. Stated as a function rather than as a clause of VarIntLen because a spec cannot call
// an impure function, and VarIntLen has to be impure -- four returns and a panic, where the `min`
// builtin that would collapse them ("got unknown identifier min" in this frontend) is unavailable.
//
// @ requires lower <= upper && upper <= Max
// @ ensures grows
func varIntLenNeverShrinks(lower uint64, upper uint64) (grows bool) {
	fewer := VarIntLen(lower)
	more := VarIntLen(upper)
	// @ assert 1 <= fewer && fewer <= 8 && 1 <= more && more <= 8
	return fewer <= more
}

// MinUint64 is the minimum of two lengths. It is not `min`: this Go frontend does not know the
// `min` and `max` builtins, so every ceiling in the verified code is spelled as an `if`, and the
// spelling deserves a name and a proof once rather than four times.
//
// @ ensures m == a || m == b
// @ ensures m <= a && m <= b
// @ ensures a <= b ==> m == a
// @ ensures b < a ==> m == b
func MinUint64(a uint64, b uint64) (m uint64) {
	if a <= b {
		return a
	}
	return b
}

// fieldCeiling is the ceiling a reader applies to a length-prefixed field: the tighter of the
// absolute ceiling and whatever the reader itself knows, which for a channel is the maximum packet
// size negotiated with the peer. `checkFieldLength` used to carry this comparison inline, in the
// same breath as the error message, which is why it could not be checked: the decision is here, and
// the error formatting that motivated `wire.go`'s imports stays there.
//
// @ ensures ceiling <= MaxFieldLength
// @ ensures ceiling == MaxFieldLength || ceiling == readerMax
// @ ensures readerMax < MaxFieldLength ==> ceiling == readerMax
// @ ensures readerMax >= MaxFieldLength ==> ceiling == MaxFieldLength
func fieldCeiling(readerMax uint64) (ceiling uint64) {
	if limit := MinUint64(readerMax, MaxFieldLength); limit < MaxFieldLength {
		return limit
	}
	return MaxFieldLength
}

// fieldLengthAcceptable is the answer the parser gives to a length announced by the peer: it may be
// allocated if and only if it fits under the ceiling. The bidirectional form is the point. Read as
// `length > ceiling ==> !ok` it is the refusal that protects the process; read as
// `length <= ceiling ==> ok` it is the statement that the guard does not refuse fields the process
// could have served, which is the failure mode a defensive check acquires later -- a ceiling
// tightened by a factor of two is a protocol bug that looks like a peer bug.
//
// @ ensures ok == (length <= ceiling)
// @ ensures length > ceiling ==> !ok
// @ ensures length <= ceiling ==> ok
// @ ensures ok ==> length <= ceiling
func fieldLengthAcceptable(length uint64, ceiling uint64) (ok bool) {
	return length <= ceiling
}

// announcementIsBounded is the reason both of the above exist, and the phase-4 statement of the
// property the length-limited reader was introduced for (see the finding behind SR-RES-03: a short
// message announcing a huge length is an allocation bomb, and past Go's maxAlloc it is a panic that
// takes the process rather than a refused message). Composed, the two rules above say: for every
// announcement and every reader bound, a field the parser accepts is at most MaxFieldLength bytes,
// and one it refuses is above the ceiling that reader applies.
//
// The premise that is not proved here, because it belongs to the code that reads: the length handed
// to `fieldLengthAcceptable` really is the one that was parsed, and nothing allocates between the
// parse and the check. `ParseSSHString` and `ParseSSHBytes` are the two places that ordering lives,
// and `TestConformanceFieldCeilingIsCheckedBeforeAllocating` is what holds them to it.
//
// @ ensures bounded
func announcementIsBounded(length uint64, readerMax uint64) (bounded bool) {
	ceiling := fieldCeiling(readerMax)
	// @ assert ceiling <= MaxFieldLength
	accepted := fieldLengthAcceptable(length, ceiling)
	// @ assert accepted == (length <= ceiling)
	return accepted == (length <= readerMax && length <= MaxFieldLength)
}

// SSHStringLen is the number of bytes WriteSSHString needs for s: the length prefix plus the
// payload. The bound on the prefix is what makes the caller's `len(out) < SSHStringLen(s)` test a
// decision about a buffer of known size rather than a guess, and the strict inequality is the
// statement that a string never fits in the space of its own payload alone.
//
// Requires, as everywhere in this file: the string is short enough to be announced, i.e. its length
// is at most Max. Go's own maximum string length is far below that (2^53-ish on 64-bit platforms in
// practice, and 2^31-1 for anything this package writes), so the premise is not load-bearing.
//
// @ requires len(s) <= Max
// @ ensures n == len(s) + 1 || n == len(s) + 2 || n == len(s) + 4 || n == len(s) + 8
// @ ensures n > len(s)
// @ ensures len(s) <= 63 ==> n == len(s) + 1
// @ ensures len(s) == 0 ==> n == 1
func SSHStringLen(s string) (n int) {
	return int(VarIntLen(uint64(len(s)))) + len(s)
}

// SSHBytesLen is SSHStringLen for a byte slice; the two are the same arithmetic, and they are kept
// separate because the caller's type decides which one it can write.
//
// @ requires len(s) <= Max
// @ ensures n == len(s) + 1 || n == len(s) + 2 || n == len(s) + 4 || n == len(s) + 8
// @ ensures n > len(s)
// @ ensures len(s) <= 63 ==> n == len(s) + 1
// @ ensures len(s) == 0 ==> n == 1
func SSHBytesLen(s []byte) (n int) {
	return int(VarIntLen(uint64(len(s)))) + len(s)
}

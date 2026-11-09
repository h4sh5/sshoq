package cmd

// `host_trust_rules.go` holds the client's trust decision, and `proof/knownhosts/model.gobra` has
// already proved a model of it (`accepts`, with the lemmas "a pin is never overruled by the user",
// "no terminal, no trust", "a changed key is a hard failure"). What this file adds is the seam between
// the two: the decision as the client actually runs it, over the facts the client actually has, held to
// a boolean formula written independently of the code, and to the model's formula where the two are
// supposed to say the same thing.
//
// The decision has eight boolean inputs and a pin that is either set or not, so the table is 512 rows
// and can be enumerated -- which is worth doing precisely because the interesting claims are the ones
// about rows nobody would think to test: that the branch order makes a known host impossible to prompt
// about, that a refusal reason exists for every way the facts can go wrong and exactly one of them
// applies, and that no verdict is dead code.

import "testing"

// trustFacts is one row of the table: everything setupQUICConnection knows when a connection fails
// because of a certificate, and nothing else.
type trustFacts struct {
	pinned          bool
	certSeen        bool
	pinMatches      bool
	alreadyRecorded bool
	cryptoFailure   bool
	knownEntry      bool
	selfSigned      bool
	hasTerminal     bool
	asked           bool
	yes             bool
}

func (f trustFacts) verdict() hostTrust {
	pin := ""
	if f.pinned {
		pin = "sha256-pinned"
	}
	return trustAfterFailedHandshake(pin, f.certSeen, f.pinMatches, f.alreadyRecorded, f.cryptoFailure,
		f.knownEntry, f.selfSigned, f.hasTerminal, f.asked, f.yes)
}

// everyTrustFacts enumerates all 1024 combinations of the inputs.
func everyTrustFacts(yield func(trustFacts) bool) {
	for mask := 0; mask < 1<<10; mask++ {
		f := trustFacts{
			pinned:          mask&1 != 0,
			certSeen:        mask&2 != 0,
			pinMatches:      mask&4 != 0,
			alreadyRecorded: mask&8 != 0,
			cryptoFailure:   mask&16 != 0,
			knownEntry:      mask&32 != 0,
			selfSigned:      mask&64 != 0,
			hasTerminal:     mask&128 != 0,
			asked:           mask&256 != 0,
			yes:             mask&512 != 0,
		}
		if !yield(f) {
			return
		}
	}
}

// expectedVerdict is the decision written a second time, as ten mutually exclusive boolean formulas
// rather than as a chain of ifs, so that agreeing with it means something. Each formula is the clause a
// reader would write down from the documented order of consequence in host_trust_rules.go, and
// TestConformanceTrustVerdictsAreTheTable requires that exactly one formula holds for every input and
// that it names the verdict the shipped code returned.
func expectedVerdict(f trustFacts) (hostTrust, bool) {
	type rule struct {
		verdict hostTrust
		holds   bool
	}
	rules := []rule{
		{hostTrustRecord, f.pinned && f.certSeen && f.pinMatches && !f.alreadyRecorded},
		{hostTrustRecord, !f.pinned && f.cryptoFailure && f.hasTerminal && !f.knownEntry && f.certSeen && f.selfSigned && f.asked && f.yes},
		{hostTrustAsk, !f.pinned && f.cryptoFailure && f.hasTerminal && !f.knownEntry && f.certSeen && f.selfSigned && !f.asked},
		{hostTrustDeclined, !f.pinned && f.cryptoFailure && f.hasTerminal && !f.knownEntry && f.certSeen && f.selfSigned && f.asked && !f.yes},
		{hostTrustRefusePinMismatch, f.pinned && f.certSeen && !f.pinMatches},
		{hostTrustRefuseAlreadyRecorded, f.pinned && f.certSeen && f.pinMatches && f.alreadyRecorded},
		{hostTrustRefuseNoCertificate, f.pinned && !f.certSeen},
		{hostTrustRefuseNoCertificate, !f.pinned && f.cryptoFailure && f.hasTerminal && !f.knownEntry && !f.certSeen},
		{hostTrustRefuseTransport, !f.pinned && !f.cryptoFailure},
		{hostTrustRefuseNoTerminal, !f.pinned && f.cryptoFailure && !f.hasTerminal},
		{hostTrustRefuseKnownHost, !f.pinned && f.cryptoFailure && f.hasTerminal && f.knownEntry},
		{hostTrustRefuseNotSelfSigned, !f.pinned && f.cryptoFailure && f.hasTerminal && !f.knownEntry && f.certSeen && !f.selfSigned},
	}
	var (
		which    hostTrust
		matches  int
		unsolved bool = true
	)
	for _, r := range rules {
		if !r.holds {
			continue
		}
		matches++
		if unsolved {
			which, unsolved = r.verdict, false
		} else if which != r.verdict {
			return which, false // two rules claim the same input and disagree
		}
	}
	if matches != 1 {
		return which, false
	}
	return which, true
}

func TestConformanceTrustVerdictsAreTheTable(t *testing.T) {
	rows := 0
	for f := range everyTrustFacts {
		rows++
		want, ok := expectedVerdict(f)
		if !ok {
			t.Fatalf("%+v: the formulas do not name exactly one verdict", f)
		}
		if got := f.verdict(); got != want {
			t.Errorf("%+v: verdict %d, want %d", f, got, want)
		}
	}
	if rows != 1024 {
		t.Fatalf("%d rows enumerated, want every combination of ten inputs", rows)
	}
}

func TestConformanceEveryVerdictTheDecisionCanGiveIsReachable(t *testing.T) {
	seen := map[hostTrust]bool{}
	for f := range everyTrustFacts {
		seen[f.verdict()] = true
	}
	// hostTrustConnect is the only value this function never returns: it belongs to the handshake that
	// succeeded, which is the path that does not consult the decision at all.
	for name, v := range map[string]hostTrust{
		"hostTrustRecord":                hostTrustRecord,
		"hostTrustAsk":                   hostTrustAsk,
		"hostTrustDeclined":              hostTrustDeclined,
		"hostTrustRefusePinMismatch":     hostTrustRefusePinMismatch,
		"hostTrustRefuseAlreadyRecorded": hostTrustRefuseAlreadyRecorded,
		"hostTrustRefuseNoCertificate":   hostTrustRefuseNoCertificate,
		"hostTrustRefuseTransport":       hostTrustRefuseTransport,
		"hostTrustRefuseNoTerminal":      hostTrustRefuseNoTerminal,
		"hostTrustRefuseKnownHost":       hostTrustRefuseKnownHost,
		"hostTrustRefuseNotSelfSigned":   hostTrustRefuseNotSelfSigned,
	} {
		if !seen[v] {
			t.Errorf("%s is unreachable: the decision has a branch nothing can lead to it", name)
		}
	}
	if seen[hostTrustConnect] {
		t.Error("hostTrustConnect came out of a failed-handshake decision, which should not be able to say that")
	}
}

// TestConformanceAPinIsNeverOverruledByYes is the lemma the model calls aPinIsNeverOverruledByTheUser,
// on the shipped code: whatever else is true, and whatever the person at the terminal answers, a
// certificate that does not match the pin does not get trusted, and does not get asked about.
func TestConformanceAPinIsNeverOverruledByYes(t *testing.T) {
	for f := range everyTrustFacts {
		if !f.pinned || !f.certSeen || f.pinMatches {
			continue
		}
		switch f.verdict() {
		case hostTrustRecord, hostTrustAsk, hostTrustDeclined:
			t.Errorf("a mismatching certificate was %d with %+v", f.verdict(), f)
		}
	}
}

// TestConformanceThePinIsSetnessOfTheString is the model's pinIsSetness: "no pin" and "an empty pin" are
// the same thing in this client, because hostHash comes from a flag or a config directive whose absence
// is the empty string. The two rows below are the same certificate, the same terminal and the same
// answer, differing only in whether a pin was asked for: with none the prompt decides, with one the pin
// decides and the answer is not consulted.
func TestConformanceThePinIsSetnessOfTheString(t *testing.T) {
	answered := trustFacts{
		certSeen: true, cryptoFailure: true, selfSigned: true, hasTerminal: true,
		asked: true, yes: true,
	}
	unpinned := answered
	if got := unpinned.verdict(); got != hostTrustRecord {
		t.Errorf("no pin, answered yes: %d, want the certificate recorded", got)
	}
	pinnedWrong := answered
	pinnedWrong.pinned = true
	pinnedWrong.pinMatches = false
	if got := pinnedWrong.verdict(); got != hostTrustRefusePinMismatch {
		t.Errorf("a pin that is set and wrong, answered yes: %d, want the pin mismatch refusal", got)
	}
	pinnedRight := answered
	pinnedRight.pinned = true
	pinnedRight.pinMatches = true
	if got := pinnedRight.verdict(); got != hostTrustRecord {
		t.Errorf("a pin that is set and right: %d, want the certificate recorded", got)
	}
	// and the empty string is no pin at all, at the handshake check too
	if !handshakePinAccepts("", true, false) {
		t.Error("an empty pin refused a certificate it has no opinion about")
	}
}

// TestConformanceAnAnswerNobodyAskedForMeansNothing is the reason `asked` comes before `userSaysYes` in
// the decision: a caller that has not put the question cannot bring an answer back with it and be
// trusted. With the order reversed -- which is how the branch reads if you are not careful -- an
// unasked "yes" records a certificate nobody approved.
func TestConformanceAnAnswerNobodyAskedForMeansNothing(t *testing.T) {
	for f := range everyTrustFacts {
		// the pinned path records a certificate without asking anybody, and rightly so: it is the pin
		// that decided, and the answer is not consulted there. This test is about the path where the
		// answer is the only authority.
		if f.pinned || f.asked || !f.yes {
			continue
		}
		if got := f.verdict(); got == hostTrustRecord {
			t.Errorf("a certificate was recorded on an answer nobody asked for: %+v", f)
		}
	}
	unasked := trustFacts{
		certSeen: true, cryptoFailure: true, selfSigned: true, hasTerminal: true,
		asked: false, yes: true,
	}
	if got := unasked.verdict(); got != hostTrustAsk {
		t.Errorf("an unasked yes: %d, want the question still to be asked", got)
	}
}

// TestConformanceNobodyIsAskedAboutAHostThatIsAlreadyKnown is the machine-in-the-middle guarantee: with
// an entry in known_hosts, the answer is a refusal, in every combination of everything else. A prompt
// here would be the bug -- it would train people to answer yes to the one question that means the
// network is lying to them.
func TestConformanceNobodyIsAskedAboutAHostThatIsAlreadyKnown(t *testing.T) {
	for f := range everyTrustFacts {
		if f.pinned || !f.knownEntry {
			continue
		}
		if got := f.verdict(); got == hostTrustAsk {
			t.Errorf("asked about a known host: %+v", f)
		}
	}
}

// TestConformanceNoTerminalMeansNoQuestionAndNoTrust is the non-interactive rule: a session without a
// /dev/tty neither asks nor trusts. This is what makes a pinned hash worth having in a script, and what
// keeps an unattended connection from silently accepting a certificate.
func TestConformanceNoTerminalMeansNoQuestionAndNoTrust(t *testing.T) {
	for f := range everyTrustFacts {
		if f.pinned || f.hasTerminal {
			continue
		}
		switch f.verdict() {
		case hostTrustAsk, hostTrustRecord, hostTrustDeclined:
			t.Errorf("a session with no terminal got %d with %+v", f.verdict(), f)
		}
	}
}

// TestConformanceOnlyASelfSignedCertificateIsEverOfferedUp pins the last guard before a person is asked:
// an unknown certificate that some authority issued, and that the authority did not vouch for here, is
// refused rather than explained to the user.
func TestConformanceOnlyASelfSignedCertificateIsEverOfferedUp(t *testing.T) {
	for f := range everyTrustFacts {
		if f.pinned || f.selfSigned {
			continue
		}
		if got := f.verdict(); got == hostTrustAsk || got == hostTrustRecord {
			t.Errorf("a certificate that does not sign itself was %d with %+v", got, f)
		}
	}
}

// TestConformanceDeclinedMeansSomebodyActuallySaidNo keeps the two ways an unknown certificate fails to
// be trusted apart: nobody was asked, and somebody was asked and refused. They write different things --
// a refusal writes to known_hosts, a decline writes nothing -- so the exit path must be able to tell them
// apart, and this is the claim that it can.
func TestConformanceDeclinedMeansSomebodyActuallySaidNo(t *testing.T) {
	for f := range everyTrustFacts {
		if f.verdict() != hostTrustDeclined {
			continue
		}
		if !f.asked || f.yes {
			t.Errorf("declined without an answer of no: asked=%v yes=%v (%+v)", f.asked, f.yes, f)
		}
	}
}

// TestConformanceHandshakePinIsTheComparisonItClaims covers the check crypto/tls performs on every
// handshake, before a byte of the session travels: a pin that is set, and a certificate to compare, and
// they disagree -- then the handshake does not happen. The one acceptance that is not a match is a
// handshake that presented no certificate, which is a resumed session; the test says so out loud,
// because it is the branch a reader is most likely to "tighten" into a bug.
func TestConformanceHandshakePinIsTheComparisonItClaims(t *testing.T) {
	type row struct {
		pin, certSeen, matches, want bool
		why                          string
	}
	rows := []row{
		{pin: false, certSeen: true, matches: true, want: true, why: "no pin, nothing to satisfy"},
		{pin: false, certSeen: true, matches: false, want: true, why: "no pin: an unpinned client trusts the way crypto/tls does"},
		{pin: false, certSeen: false, matches: false, want: true, why: "no pin and no certificate"},
		{pin: true, certSeen: true, matches: true, want: true, why: "the pin matches"},
		{pin: true, certSeen: true, matches: false, want: false, why: "the pin disagrees: this is the machine-in-the-middle refusal"},
		{pin: true, certSeen: false, matches: false, want: true, why: "a resumed session presents no certificate; its keys came from a handshake that was pinned"},
		{pin: true, certSeen: false, matches: true, want: true, why: "same as above: with no certificate the comparison is not looked at"},
	}
	for _, r := range rows {
		if got := handshakePinAccepts(pinOf(r.pin), r.certSeen, r.matches); got != r.want {
			t.Errorf("%s: handshakePinAccepts = %v, want %v", r.why, got, r.want)
		}
	}
	// and exhaustively: with a certificate in hand, acceptance is exactly "no pin or a match"
	for _, pin := range []bool{false, true} {
		for _, seen := range []bool{false, true} {
			for _, matches := range []bool{false, true} {
				got := handshakePinAccepts(pinOf(pin), seen, matches)
				want := !pin || !seen || matches
				if got != want {
					t.Errorf("pin=%v seen=%v matches=%v: %v, want %v", pin, seen, matches, got, want)
				}
			}
		}
	}
}

func pinOf(set bool) string {
	if set {
		return "SHA256:aaaa"
	}
	return ""
}

// TestConformanceTheShippedDecisionAgreesWithTheModel ties the code to `accepts` in
// proof/knownhosts/model.gobra, the formula the prover was given:
//
//	accepts(pinned, hashMatches, knownEntry, hasTerminal, userSaysYes) ==
//		(pinned && hashMatches) || (!pinned && !knownEntry && hasTerminal && userSaysYes)
//
// The model has five facts; the shipped decision has ten. The five it does not speak of are held fixed
// here at the values the model implicitly assumes -- the handshake did present a certificate, it was the
// TLS layer that refused, the certificate signs itself (the guard `SR-TR-02` puts on a prompt, which the
// shipped code has and the model does not), and the question has been put, which is what the model's
// `userSaysYes` is -- and known_hosts does not hold the pinned hash yet, since the model decides trust,
// not whether the file still has to be written. With those fixed, "this certificate is trusted" is the
// same set of rows in both, over all 32 combinations of the model's own variables.
func TestConformanceTheShippedDecisionAgreesWithTheModel(t *testing.T) {
	for mask := 0; mask < 1<<5; mask++ {
		pinned := mask&1 != 0
		hashMatches := mask&2 != 0
		knownEntry := mask&4 != 0
		hasTerminal := mask&8 != 0
		userSaysYes := mask&16 != 0

		f := trustFacts{
			pinned:          pinned,
			certSeen:        true,
			pinMatches:      hashMatches,
			alreadyRecorded: false,
			cryptoFailure:   true,
			knownEntry:      knownEntry,
			selfSigned:      true,
			hasTerminal:     hasTerminal,
			asked:           true,
			yes:             userSaysYes,
		}
		trusted := f.verdict() == hostTrustRecord
		modelAccepts := (pinned && hashMatches) ||
			(!pinned && !knownEntry && hasTerminal && userSaysYes)
		if trusted != modelAccepts {
			t.Errorf("pinned=%v hashMatches=%v knownEntry=%v hasTerminal=%v userSaysYes=%v: shipped %v, model %v",
				pinned, hashMatches, knownEntry, hasTerminal, userSaysYes, trusted, modelAccepts)
		}
	}
}

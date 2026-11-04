package cmd

// The two trust decisions of the client, in a file of their own so that they can be verified and tested
// where they run.
//
// `cmd/sshoq.go` decides, on every connection, whether the certificate the server handed over is the
// certificate the user agreed to trust. That decision is the client's whole defence against a
// machine-in-the-middle, and until these files it lived inside setupQUICConnection -- a function whose
// other job is sockets, TLS configuration, prompts on /dev/tty and retries, and which imports
// `crypto/tls`, `net` and quic-go, none of which Gobra v26.09 can read. Splitting the *decision* out is
// the move that made `server_auth/truncate.go` and `util/equalfold.go` verifiable: this file imports
// nothing, so `make proof` checks the code the client runs rather than a model of it, and
// `cmd/host_trust_conformance_test.go` holds it to its table -- including against
// `proof/knownhosts/model.gobra`, which had already written the decision down as `accepts` when it was
// still only prose inside main.
//
// The verdicts name their reason, rather than being a bare yes/no, for a practical reason: main has to
// *say something* when it refuses -- the machine-in-the-middle warning, the "not self-signed" message,
// the "non-terminal session" line -- and a refusal without a reason would send main back to
// re-deriving the reason from the facts, which is how the two copies of a decision drift apart. With
// reasons, main asks once, switches, and logs what the verdict says.
//
// The one deliberate looseness is where a handshake presented no certificate, which is what a *resumed*
// TLS session looks like: `handshakePinAccepts` accepts it. The alternative -- refusing -- would refuse
// the retry whose whole purpose is to reconnect after a certificate was added to known_hosts. What makes
// it safe is that a resumed session runs on the keys of a full handshake that did satisfy the pin; it is
// written as a named case rather than left to an `if certSeen` that reads like an oversight.

// hostTrust is what to do about a server certificate. The values are what setupQUICConnection can act
// on, and each refusal says why, because the person reading the failure has to be told something
// different for each of them.
type hostTrust int

const (
	// hostTrustConnect: the handshake is acceptable; use the connection.
	hostTrustConnect hostTrust = iota
	// hostTrustRecord: the certificate is trusted and known_hosts does not hold it yet; add it and
	// reconnect. This is what a matching pin does, and what a "yes" at the prompt does.
	hostTrustRecord
	// hostTrustAsk: an unknown, self-signed certificate for a host nobody has trusted yet, in front of a
	// terminal: the only case where a person is asked.
	hostTrustAsk
	// hostTrustDeclined: the person at the terminal said no. Nothing was trusted and nothing was written.
	hostTrustDeclined
	// hostTrustRefusePinMismatch: the pinned host hash and the certificate disagree.
	hostTrustRefusePinMismatch
	// hostTrustRefuseNoCertificate: the decision needed the certificate and there was none to look at.
	hostTrustRefuseNoCertificate
	// hostTrustRefuseAlreadyRecorded: the pin matches a certificate known_hosts already holds, so the pin
	// did not cause the failure and cannot cure it.
	hostTrustRefuseAlreadyRecorded
	// hostTrustRefuseNoTerminal: an untrusted certificate in a session with no terminal -- nobody to ask,
	// and the answer is no rather than a hang or a silent trust.
	hostTrustRefuseNoTerminal
	// hostTrustRefuseKnownHost: known_hosts already holds a certificate for this host and the peer did not
	// satisfy it. This is the machine-in-the-middle case, and it is never a prompt.
	hostTrustRefuseKnownHost
	// hostTrustRefuseNotSelfSigned: an unknown certificate that does not sign itself is a certificate some
	// authority issued and did not vouch for.
	hostTrustRefuseNotSelfSigned
	// hostTrustRefuseTransport: the connection failed for a reason that is not about trust at all.
	hostTrustRefuseTransport
)

// handshakePinAccepts reports whether the certificate a handshake presented satisfies the pinned host
// hash.
//
// pin is the hash the user asked for -- from -host-hash, or from the HostHash directive of
// ~/.ssh/config -- and the empty string means no pin was asked for, in which case every handshake
// satisfies it because there is nothing to satisfy. certSeen says whether the handshake presented a peer
// certificate at all, and pinMatches says whether that certificate's host hash (HostHash: SHA-256 of
// its DER, the string the server prints) is the pinned one; when certSeen is false, pinMatches means
// nothing and is not looked at.
func handshakePinAccepts(pin string, certSeen bool, pinMatches bool) bool {
	if pin == "" {
		return true
	}
	if !certSeen {
		// a resumed session, running on keys a pinned full handshake established
		return true
	}
	return pinMatches
}

// trustAfterFailedHandshake decides what to do when a connection failed and the certificate is the
// reason worth talking about.
//
// pin, certSeen and pinMatches are as in handshakePinAccepts. alreadyRecorded says known_hosts already
// holds a certificate with the pinned hash for this host. refusedByCrypto says the TLS layer refused the
// certificate, as opposed to the peer being unreachable. knownEntry says known_hosts holds some
// certificate for this host. selfSigned says the certificate the peer presented signs itself, the only
// shape sshoq will take a person's word for. hasTerminal says there is a /dev/tty to ask. asked says the
// question has already been put to a person, which is the difference between "ask" and "they said no";
// userSaysYes is their answer. Main makes the same call twice -- before the prompt with asked false,
// of the decision in one place.
//
// The order is the order of consequence, and it is what the proof and the table below pin:
//
//   - a pin decides everything and asks nobody, because a pin is the user having already answered this
//     question somewhere else; a match on a certificate the file already holds is still a refusal,
//     because the pin did not cause the failure;
//   - a failure that is not about the certificate is not a trust decision;
//   - nobody is asked without a terminal;
//   - a host already in known_hosts is a hard refusal and never a prompt: that is the
//     machine-in-the-middle case, and a prompt would train people to type yes to it;
//   - an unknown certificate must at least be self-signed;
//   - and then, and only then, the person is asked.
func trustAfterFailedHandshake(pin string, certSeen bool, pinMatches bool, alreadyRecorded bool, refusedByCrypto bool, knownEntry bool, selfSigned bool, hasTerminal bool, asked bool, userSaysYes bool) hostTrust {
	if pin != "" {
		if !certSeen {
			return hostTrustRefuseNoCertificate
		}
		if !pinMatches {
			return hostTrustRefusePinMismatch
		}
		if alreadyRecorded {
			return hostTrustRefuseAlreadyRecorded
		}
		return hostTrustRecord
	}
	if !refusedByCrypto {
		return hostTrustRefuseTransport
	}
	if !hasTerminal {
		return hostTrustRefuseNoTerminal
	}
	if knownEntry {
		return hostTrustRefuseKnownHost
	}
	if !certSeen {
		return hostTrustRefuseNoCertificate
	}
	if !selfSigned {
		return hostTrustRefuseNotSelfSigned
	}
	if !asked {
		return hostTrustAsk
	}
	// The answer counts because it was given: userSaysYes on its own means nothing, and a caller that
	// reaches this point without having put the question must not be able to arrive here with an answer
	// and be trusted for it. That is not a hypothetical -- the flag ordering in a future caller is
	// exactly the mistake this ordering forecloses.
	if userSaysYes {
		return hostTrustRecord
	}
	// the question was put, and the answer was no: nothing is trusted and nothing is written
	return hostTrustDeclined
}

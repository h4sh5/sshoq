package ssh3

// The protocol version gate, verified where it decides.
//
// `IsVersionSupported` in `version.go` is the answer a peer gets before it is allowed to
// authenticate: the version string arrives on the first bytes of the connection, and anything the
// gate does not recognise is refused without a password, a token or a certificate. The decision is
// a handful of comparisons, so it belongs here, where `make proof` can state what it does for every
// input rather than for the handful of versions a test happens to name. `version.go` keeps the
// struct, the parsers and the error values -- it imports `fmt`, which Gobra v26.09 cannot read -- and
// delegates to the function below.
//
// The identity constants live here because the spec below is written against them. They are the same
// constants with the same names and values as before; only the file they are declared in changed,
// and the package is unchanged, so nothing outside sees a difference.
//
// One thing the reading of this file should not "simplify": the legacy branch below compares the
// peer's implementation name against the literal "h4sh5/sshoq" and not against
// `SOFTWARE_IMPLEMENTATION_NAME`, and that is deliberate. The branch describes what *older releases
// of this project* announced on the wire, which is a fact about the past; `SOFTWARE_IMPLEMENTATION_NAME`
// is what this release announces, and if the project were ever renamed the two would disagree and
// the branch would have to keep the old name.

const PROTOCOL_MAJOR int = 3
const PROTOCOL_MINOR int = 0
const PROTOCOL_EXPERIMENTAL_SPEC_VERSION string = "alpha-00"

const SOFTWARE_IMPLEMENTATION_NAME string = "h4sh5/sshoq"
const SOFTWARE_MAJOR int = 0
const SOFTWARE_MINOR int = 2
const SOFTWARE_PATCH int = 1

// the software releases whose version numbers are legacy -- see versionSupported. 0.1.0, 0.1.1 and
// 0.1.2 announced an empty spec version but predate the wire behaviour this server expects, and 0.1.6
// onwards never existed with an empty spec version, so the two bounds are history rather than policy.
const legacySoftwareMajor int = 0
const legacySoftwareMinor int = 1
const legacyOldestSupportedPatch int = 3
const legacyNewestSupportedPatch int = 5

// versionSupported decides whether a peer that announced these version fields may proceed to
// authentication. It is `IsVersionSupported`'s decision, moved unchanged; the clauses are new.
//
// What they say, in the order a reader cares about:
//
//   - The protocol major and minor are checked strictly, and nothing else can override the result.
//     This is the clause that matters for security: every other allowance below is reachable only
//     inside the protocol version this server speaks, so no announcement about software versions or
//     legacy implementations can smuggle a peer onto a different protocol revision.
//   - A peer naming a spec version that is neither empty nor the one this server implements is
//     refused. There is no "newer is fine" rule and no prefix or substring matching, so a future
//     draft cannot be quietly accepted by a server that has not been updated for it.
//   - Naming this server's spec version, with the protocol version matching, is accepted.
//   - The empty spec version is the legacy case, and it is accepted for exactly one family -- this
//     project's own 0.1.3 through 0.1.5 -- with the answer inside that family being "patch at least
//     3". The boundaries are pinned because they are pure history and a reader cannot recover them
//     from first principles: 0.1.2 is refused and so is 0.1.6, which is a genuine asymmetry (a
//     hypothetical 0.1.6 that still announced an empty spec version would be refused, not accepted
//     as "newer"), and `TestConformanceLegacyVersionWindowIsExactlyThreeThroughFive` keeps it visible.
//
// @ ensures peerProtocolMajor != PROTOCOL_MAJOR || peerProtocolMinor != PROTOCOL_MINOR ==> !supported
// @ ensures peerProtocolMajor == PROTOCOL_MAJOR && peerProtocolMinor == PROTOCOL_MINOR && peerSpecVersion == PROTOCOL_EXPERIMENTAL_SPEC_VERSION ==> supported
// @ ensures peerProtocolMajor == PROTOCOL_MAJOR && peerProtocolMinor == PROTOCOL_MINOR && peerSpecVersion != "" && peerSpecVersion != PROTOCOL_EXPERIMENTAL_SPEC_VERSION ==> !supported
// @ ensures peerSpecVersion != "" && peerSpecVersion != PROTOCOL_EXPERIMENTAL_SPEC_VERSION ==> !supported
// @ ensures peerProtocolMajor == PROTOCOL_MAJOR && peerProtocolMinor == PROTOCOL_MINOR && legacyFamily(peerSpecVersion, peerImplementation, peerSoftwareMajor, peerSoftwareMinor, peerSoftwarePatch) ==> (supported == (peerSoftwarePatch >= legacyOldestSupportedPatch))
// @ ensures peerProtocolMajor == PROTOCOL_MAJOR && peerProtocolMinor == PROTOCOL_MINOR && peerSpecVersion == "" && peerImplementation == "h4sh5/sshoq" && peerSoftwareMajor == 0 && peerSoftwareMinor == 1 && peerSoftwarePatch == 2 ==> !supported
func versionSupported(peerProtocolMajor int, peerProtocolMinor int, peerSpecVersion string,
	peerImplementation string, peerSoftwareMajor int, peerSoftwareMinor int, peerSoftwarePatch int) (supported bool) {
	// strict protocol version checking
	if peerProtocolMajor != PROTOCOL_MAJOR || peerProtocolMinor != PROTOCOL_MINOR {
		return false
	}

	// special case: to our knowledge, experimental spec version older than alpha-00 are only
	// implemented by us (i.e. francoismichel/ssh3)
	if peerSpecVersion == "" && peerImplementation == "h4sh5/sshoq" &&
		peerSoftwareMajor == legacySoftwareMajor && peerSoftwareMinor == legacySoftwareMinor &&
		peerSoftwarePatch <= legacyNewestSupportedPatch {
		// then, only support software version >= 0.1.3
		return peerSoftwarePatch >= legacyOldestSupportedPatch
	}

	// Starting from here, we have proper experimental spec version signalling.
	// this version is version alpha-00, other versions are not supported.
	// If a server receives a request with an unsupported spec version, the client should
	// start a new request with a compatible version.
	return peerSpecVersion == PROTOCOL_EXPERIMENTAL_SPEC_VERSION
}

// ourOwnVersionIsSupported is the one claim about the constants themselves worth discharging: this
// release accepts the version string this release announces. Were it false, the server would refuse
// itself, and every client speaking to it, which is the kind of edit a version bump makes easy to do
// by accident -- bumping PROTOCOL_EXPERIMENTAL_SPEC_VERSION without noticing that the same constant
// appears in the comparison the gate ends with.
//
// @ ensures supported
func ourOwnVersionIsSupported() (supported bool) {
	return versionSupported(PROTOCOL_MAJOR, PROTOCOL_MINOR, PROTOCOL_EXPERIMENTAL_SPEC_VERSION,
		SOFTWARE_IMPLEMENTATION_NAME, SOFTWARE_MAJOR, SOFTWARE_MINOR, SOFTWARE_PATCH)
}

// legacyFamily is the antecedent of the legacy clause above, named so the spec above and the tests
// below talk about the same set of peers.
//
// @ pure
// @ decreases 0
// @ ensures isLegacy == (peerSpecVersion == "" && peerImplementation == "h4sh5/sshoq" && peerSoftwareMajor == legacySoftwareMajor && peerSoftwareMinor == legacySoftwareMinor && peerSoftwarePatch <= legacyNewestSupportedPatch)
func legacyFamily(peerSpecVersion string, peerImplementation string, peerSoftwareMajor int,
	peerSoftwareMinor int, peerSoftwarePatch int) (isLegacy bool) {
	return peerSpecVersion == "" && peerImplementation == "h4sh5/sshoq" &&
		peerSoftwareMajor == legacySoftwareMajor && peerSoftwareMinor == legacySoftwareMinor &&
		peerSoftwarePatch <= legacyNewestSupportedPatch
}

// One claim that is *not* here, and why: "away from the legacy family the verdict does not depend on
// the software version" is true, and the conformance test enumerates it over every field, but it did
// not verify as a universal statement. Its shape is two calls of the same imperative function under a
// hypothesis, and Silicon would not take the conclusion even with the legacy condition written out
// inline instead of calling `legacyFamily` -- so it is not the pure-function inlining that got in the
// way, and the next person does not have to rediscover that. The claim belongs in the test file.

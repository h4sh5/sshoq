package ssh3

import (
	"math/rand"
	"strings"
	"testing"
)

// These are the first tests the version gate has ever had. The requirement table used to say SR-TR-03
// was "covered by unit tests"; nothing in this repository, or in any test file, calls
// `IsVersionSupported`, `ParseVersionString` or reads `AVAILABLE_CLIENT_VERSIONS` (Finding F9). The gate
// decides whether a peer may authenticate at all, so it is worth having said something about its
// behaviour before claiming it.
//
// `preSplitIsVersionSupported` is the original body, copied: the shipped gate is now a field handoff to
// `versionSupported` in `version_rules.go`, so these tests pin the handoff, the verdicts, and the two
// claims the prover declined.

func preSplitIsVersionSupported(other Version) bool {
	otherProtocolMajor, otherProtocolMinor := other.protocolVersion.Major, other.protocolVersion.Minor
	otherSpecVersion := other.protocolVersion.ExperimentalSpecVersion
	otherImpl, otherSwMajor, otherSwMinor, otherSwPatch := other.softwareVersion.ImplementationName,
		other.softwareVersion.Major, other.softwareVersion.Minor, other.softwareVersion.Patch

	if otherProtocolMajor != PROTOCOL_MAJOR || otherProtocolMinor != PROTOCOL_MINOR {
		return false
	}
	if otherSpecVersion == "" && otherImpl == "h4sh5/sshoq" &&
		otherSwMajor == 0 && otherSwMinor == 1 && otherSwPatch <= 5 {
		return otherSwPatch >= 3
	}
	return otherSpecVersion == "alpha-00"
}

func mkVersion(pMajor, pMinor int, spec, impl string, swMajor, swMinor, swPatch int) Version {
	return NewVersion("SSH", NewProtocolVersion(pMajor, pMinor, spec),
		NewSoftwareVersion(swMajor, swMinor, swPatch, impl))
}

// TestConformanceHandoffAgreesWithThePreSplitGate runs both gates over the cross product of every field
// the decision reads, with the values a peer realistically sends plus the ones an attacker sends.
func TestConformanceHandoffAgreesWithThePreSplitGate(t *testing.T) {
	protocolMajors := []int{0, 2, 3, 4, -1, 1 << 40}
	protocolMinors := []int{0, 1, 99, -1}
	specs := []string{"", "alpha-00", "alpha-01", "alpha-0", "alpha-000", "ALPHA-00", "alpha-00 ",
		"draft-michel-ssh3-12", "0", "β"}
	implementations := []string{"h4sh5/sshoq", "francoismichel/ssh3", "H4SH5/sshoq", "", "h4sh5/sshoq "}
	swMajors := []int{0, 1, 2}
	swMinors := []int{0, 1, 2}
	swPatches := []int{-1, 0, 1, 2, 3, 4, 5, 6, 7, 100}

	checked := 0
	for _, pm := range protocolMajors {
		for _, pn := range protocolMinors {
			for _, spec := range specs {
				for _, impl := range implementations {
					for _, sm := range swMajors {
						for _, sn := range swMinors {
							for _, sp := range swPatches {
								v := mkVersion(pm, pn, spec, impl, sm, sn, sp)
								got := IsVersionSupported(v)
								want := preSplitIsVersionSupported(v)
								checked++
								if got != want {
									t.Fatalf("verdict for %d.%d spec %q impl %q sw %d.%d.%d: shipped %v, pre-split %v",
										pm, pn, spec, impl, sm, sn, sp, got, want)
								}
							}
						}
					}
				}
			}
		}
	}
	if checked != len(protocolMajors)*len(protocolMinors)*len(specs)*len(implementations)*len(swMajors)*len(swMinors)*len(swPatches) {
		t.Fatalf("grid did not run as described: %d comparisons", checked)
	}
	t.Logf("%d announcements compared", checked)
}

// TestConformanceVerdictTable pins what the verdicts *are*, so that a change to the gate has to be a
// decision rather than an accident. The interesting rows are the last five: inside protocol 3.0 with an
// empty spec version, our own 0.1.3, 0.1.4 and 0.1.5 are accepted, 0.1.2 is refused as too old, and
// 0.1.6 is refused too -- the legacy window is a window, not a "newer is fine" rule, because no 0.1.6
// ever announced an empty spec version. A peer that invented one would be refused.
func TestConformanceVerdictTable(t *testing.T) {
	cases := []struct {
		desc string
		v    Version
		want bool
	}{
		{"this release", ThisVersion(), true},
		{"protocol 3.0, spec alpha-00", mkVersion(3, 0, "alpha-00", "anything", 9, 9, 9), true},
		{"protocol 3.1", mkVersion(3, 1, "alpha-00", "anything", 0, 1, 5), false},
		{"protocol 4.0", mkVersion(4, 0, "alpha-00", "anything", 0, 1, 5), false},
		{"protocol 3.0, spec alpha-01", mkVersion(3, 0, "alpha-01", "anything", 0, 1, 5), false},
		{"protocol 3.0, spec draft-12", mkVersion(3, 0, "draft-michel-ssh3-12", "h4sh5/sshoq", 0, 1, 5), false},
		{"protocol 3.0, spec alpha-00, legacy sw 0.1.1", mkVersion(3, 0, "alpha-00", "h4sh5/sshoq", 0, 1, 1), true},
		{"protocol 3.0, empty spec, legacy 0.1.2", mkVersion(3, 0, "", "h4sh5/sshoq", 0, 1, 2), false},
		{"protocol 3.0, empty spec, legacy 0.1.3", mkVersion(3, 0, "", "h4sh5/sshoq", 0, 1, 3), true},
		{"protocol 3.0, empty spec, legacy 0.1.5", mkVersion(3, 0, "", "h4sh5/sshoq", 0, 1, 5), true},
		{"protocol 3.0, empty spec, legacy 0.1.6", mkVersion(3, 0, "", "h4sh5/sshoq", 0, 1, 6), false},
		{"protocol 3.0, empty spec, different implementation", mkVersion(3, 0, "", "francoismichel/ssh3", 0, 1, 4), false},
		{"protocol 3.0, empty spec, legacy name but sw 0.2.4", mkVersion(3, 0, "", "h4sh5/sshoq", 0, 2, 4), false},
		{"protocol 2.0, empty spec, legacy sw 0.1.4", mkVersion(2, 0, "", "h4sh5/sshoq", 0, 1, 4), false},
		{"protocol 2.0, spec alpha-00", mkVersion(2, 0, "alpha-00", "h4sh5/sshoq", 0, 1, 4), false},
		{"protocol 3.0, empty spec, no implementation named", mkVersion(3, 0, "", "", 0, 1, 4), false},
	}
	for _, c := range cases {
		if got := IsVersionSupported(c.v); got != c.want {
			t.Errorf("%s: want %v, got %v", c.desc, c.want, got)
		}
	}
}

// TestConformanceProtocolVersionIsStrictBothWays is the clause the security requirement turns on: no
// announcement about implementations or software versions can get a peer onto a protocol revision other
// than the two numbers this server speaks.
func TestConformanceProtocolVersionIsStrictBothWays(t *testing.T) {
	for _, pm := range []int{0, 1, 2, 4, 3 + 1} {
		for _, pn := range []int{0, 1, 2} {
			for _, spec := range []string{"", "alpha-00", "alpha-01", "zzz"} {
				for _, impl := range []string{"h4sh5/sshoq", "other"} {
					for _, sp := range []int{0, 3, 4, 5, 6} {
						if IsVersionSupported(mkVersion(pm, pn, spec, impl, 0, 1, sp)) {
							t.Fatalf("protocol %d.%d was accepted: spec %q impl %q sw 0.1.%d", pm, pn, spec, impl, sp)
						}
					}
				}
			}
		}
	}
}

// TestConformanceSoftwareVersionIsIrrelevantAwayFromTheLegacyFamily is the claim the prover declined:
// away from the legacy family, two announcements differing only in their software version get the same
// verdict. It is enumerated here rather than proved, for the reason written at the end of `version_rules.go`.
func TestConformanceSoftwareVersionIsIrrelevantAwayFromTheLegacyFamily(t *testing.T) {
	inLegacy := func(spec, impl string, maj, min, patch int) bool {
		return spec == "" && impl == "h4sh5/sshoq" && maj == 0 && min == 1 && patch <= 5
	}
	specs := []string{"", "alpha-00", "alpha-01"}
	implementations := []string{"h4sh5/sshoq", "other", ""}
	swValues := []struct{ maj, min, patch int }{{0, 1, 2}, {0, 1, 3}, {0, 1, 6}, {1, 0, 0}, {0, 0, 0}, {7, 7, 7}}
	pairs := 0
	for _, spec := range specs {
		for _, impl := range implementations {
			for _, a := range swValues {
				for _, b := range swValues {
					if inLegacy(spec, impl, a.maj, a.min, a.patch) || inLegacy(spec, impl, b.maj, b.min, b.patch) {
						continue
					}
					va := mkVersion(PROTOCOL_MAJOR, PROTOCOL_MINOR, spec, impl, a.maj, a.min, a.patch)
					vb := mkVersion(PROTOCOL_MAJOR, PROTOCOL_MINOR, spec, impl, b.maj, b.min, b.patch)
					pairs++
					if IsVersionSupported(va) != IsVersionSupported(vb) {
						t.Fatalf("software version changed the verdict away from the legacy family: %v vs %v for spec %q impl %q",
							IsVersionSupported(va), IsVersionSupported(vb), spec, impl)
					}
				}
			}
		}
	}
	if pairs < 50 {
		t.Fatalf("enumeration too small to mean anything: %d pairs", pairs)
	}
	t.Logf("%d software-version pairs agree", pairs)
}

// TestConformanceEveryVersionTheClientMayAnnounceIsSupportedByTheServer closes the loop between the two
// places the legacy window is written down: `AVAILABLE_CLIENT_VERSIONS` lists what this project's client
// is allowed to announce, and `IsVersionSupported` is what a server answers it with. They encode the
// same history in two different forms, and nothing but this test stops one of them being edited without
// the other.
func TestConformanceEveryVersionTheClientMayAnnounceIsSupportedByTheServer(t *testing.T) {
	if len(AVAILABLE_CLIENT_VERSIONS) == 0 {
		t.Fatal("no client versions at all")
	}
	for i, v := range AVAILABLE_CLIENT_VERSIONS {
		if !IsVersionSupported(v) {
			t.Errorf("AVAILABLE_CLIENT_VERSIONS[%d] = %s would be refused by our own server", i, v.GetVersionString())
		}
	}
}

// TestConformanceGateRefusesArbitraryAnnouncements feeds the gate strings no release produced, checking
// both that it never panics and that a spec version outside the two it knows is never accepted.
func TestConformanceGateRefusesArbitraryAnnouncements(t *testing.T) {
	rng := rand.New(rand.NewSource(14))
	alphabet := []byte("\x00 .-09AZaz_α")
	randString := func() string {
		var sb strings.Builder
		for i, n := 0, rng.Intn(12); i < n; i++ {
			sb.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		return sb.String()
	}
	for i := 0; i < 5000; i++ {
		spec, impl := randString(), randString()
		v := mkVersion(PROTOCOL_MAJOR, PROTOCOL_MINOR, spec, impl, rng.Intn(3), rng.Intn(3), rng.Intn(9))
		got := IsVersionSupported(v)
		if got != (spec == "alpha-00") {
			t.Fatalf("announcement spec %q impl %q got verdict %v; only \"alpha-00\" and the legacy window may be accepted",
				spec, impl, got)
		}
		if got != preSplitIsVersionSupported(v) {
			t.Fatalf("shipped and pre-split gates disagree on spec %q impl %q", spec, impl)
		}
	}
}

// TestConformanceVersionStringsRoundTripIntoTheGate is a thin guard on the parsers that feed the gate:
// the string this server announces parses, and what it parses to is supported; the legacy form -- four
// fields, no spec version -- parses and lands inside the legacy window; and a malformed announcement is
// an error rather than a panic. The parsing itself is outside the verified set (it logs, and the stubs
// say nothing about what strconv.Atoi or strings.Split return, so the numbers a parse produced are not
// facts the prover can use), which is exactly why this is a floor and not a proof.
func TestConformanceVersionStringsRoundTripIntoTheGate(t *testing.T) {
	roundTrip := []struct {
		s    string
		want bool
		why  string
	}{
		{GetCurrentVersionString(), true, "what this release announces"},
		{"SSH 3.0 h4sh5/sshoq 0.1.5", true, "legacy release, no spec version announced"},
		{"SSH 3.0 h4sh5/sshoq 0.1.2", false, "legacy release older than the window"},
		{"SSH 3.0 h4sh5/sshoq 0.1.5 experimental_spec_version=alpha-01", false, "a spec version we do not implement"},
	}
	for _, c := range roundTrip {
		v, err := ParseVersionString(c.s)
		if err != nil {
			t.Errorf("ParseVersionString(%q) = %v, want success (%s)", c.s, err, c.why)
			continue
		}
		if got := IsVersionSupported(v); got != c.want {
			t.Errorf("%s: %q parses to a version the gate answers %v, want %v", c.why, c.s, got, c.want)
		}
	}

	bad := []string{"", "SSH", "SSH 3.0", "SSH 3.0 h4sh5/sshoq", "SSH 3.0 h4sh5/sshoq 0.1",
		"SSH x.y h4sh5/sshoq 0.1.5", "SSH 3.0 h4sh5/sshoq a.b.c", "SSH 3.0 h4sh5/sshoq 99999999999999999999999.0.0",
		"   ", "\t\n"}
	for _, s := range bad {
		if v, err := ParseVersionString(s); err == nil {
			t.Errorf("ParseVersionString(%q) = %s, want an error", s, v.GetVersionString())
		}
	}
}

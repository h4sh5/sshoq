package ssh3

import (
	"strings"
	"testing"
)

// The gates in identity_checks.go are verified by Gobra on the shipped functions. What these tests
// hold is the two ends the prover cannot see: that the verdict the proof talks about is the verdict
// the exported method acts on, and that the verdict still says what the code did before the decision
// was separated from the message. The "before" is written out again here, from the pre-refactor
// source, because an agreement test between a function and itself proves nothing (finding F6).

// oldRequestRefused is CheckRequest as it was written when the decision and the message were one
// switch: which request types are refused, given the identity's flags.
func oldRequestRefused(requestType string, noPty, noEnv, noX11, noAgent bool) bool {
	switch requestType {
	case "pty-req":
		return noPty
	case "env":
		return noEnv
	case "x11-req":
		return noX11
	case "agent-forwarding":
		return noAgent
	}
	return false
}

// oldChannelOpenRefused is CheckChannelOpen as it was written, family extraction included.
func oldChannelOpenRefused(channelType string, noPortForwarding bool, forcedCommand string) bool {
	family := channelType
	if i := strings.IndexByte(family, ','); i >= 0 {
		family = family[:i]
	}
	switch family {
	case "direct-tcp", "direct-udp", "request-reverse-tcp", "request-reverse-udp", "open-request-reverse-tcp", "open-request-reverse-udp":
		return noPortForwarding || forcedCommand != ""
	case "sftp":
		return forcedCommand != ""
	}
	return false
}

func TestConformanceRequestVerdictIsTheGate(t *testing.T) {
	types := []string{
		"pty-req", "env", "x11-req", "agent-forwarding",
		// types with no gate, and spellings that must not be confused with one that has it
		"shell", "subsystem", "exec", "window-change", "signal", "exit-status",
		"PTY-REQ", "pty-req2", "pty-req ", "", "pty-reqx",
	}
	for _, requestType := range types {
		for mask := 0; mask < 16; mask++ {
			noPty := mask&1 != 0
			noEnv := mask&2 != 0
			noX11 := mask&4 != 0
			noAgent := mask&8 != 0
			want := oldRequestRefused(requestType, noPty, noEnv, noX11, noAgent)

			options := &IdentityOptions{
				NoPty: noPty, NoEnv: noEnv, NoX11Forwarding: noX11, NoAgentForwarding: noAgent,
			}
			err := options.CheckRequest(requestType)
			if got := err != nil; got != want {
				t.Fatalf("CheckRequest(%q) with flags (%v,%v,%v,%v) refused %v, the pre-refactor gate says %v",
					requestType, noPty, noEnv, noX11, noAgent, got, want)
			}

			verdict := requestVerdictFor(requestType, noPty, noEnv, noX11, noAgent)
			if got := verdict != requestPermitted; got != want {
				t.Fatalf("requestVerdictFor(%q, %v, %v, %v, %v) = %d, refused %v, the gate says %v",
					requestType, noPty, noEnv, noX11, noAgent, verdict, got, want)
			}

			// the method and the verified decision must not merely agree on yes/no: the reason
			// they refuse has to be the same reason, or the proof is about a different gate
			if want {
				if !strings.Contains(err.Error(), reasonOf(verdict)) {
					t.Fatalf("CheckRequest(%q) refused with %q, which does not carry the reason of verdict %d",
						requestType, err.Error(), verdict)
				}
			}
		}
	}

	// a nil identity has never carried restrictions, and the zero verdict keeps it that way
	if err := (*IdentityOptions)(nil).CheckRequest("pty-req"); err != nil {
		t.Fatalf("a nil identity refused %v", err)
	}
}

// reasonOf is the phrase each refusal has used since before the split, spelled here independently
// of the switch in CheckRequest so that a verdict mapped to the wrong message is caught.
func reasonOf(verdict requestVerdict) string {
	switch verdict {
	case requestRefusedPty:
		return "forbids it (no-pty)"
	case requestRefusedEnv:
		return "environment variables"
	case requestRefusedX11:
		return "X11 forwarding is forbidden"
	case requestRefusedAgent:
		return "agent forwarding is forbidden"
	}
	return ""
}

func TestConformanceChannelVerdictIsTheGate(t *testing.T) {
	families := []string{
		"direct-tcp", "direct-udp", "request-reverse-tcp", "request-reverse-udp",
		"open-request-reverse-tcp", "open-request-reverse-udp", "sftp",
		// the same families with the data that follows a comma on the wire
		"open-request-reverse-tcp,10.0.0.1:22", "direct-tcp,localhost:8080",
		// and types that no flag forbids
		"session", "direct-streamlocal@openssh.com", "", "direct-tcpx", "sftp2", "SFTP",
	}
	commands := []string{"", "ls", "echo a,b"}
	for _, channelType := range families {
		for _, noPortForwarding := range []bool{false, true} {
			for _, forcedCommand := range commands {
				want := oldChannelOpenRefused(channelType, noPortForwarding, forcedCommand)

				options := &IdentityOptions{NoPortForwarding: noPortForwarding, ForcedCommand: forcedCommand}
				err := options.CheckChannelOpen(channelType)
				if got := err != nil; got != want {
					t.Fatalf("CheckChannelOpen(%q) with no-port-forwarding=%v and command=%q refused %v, the pre-refactor gate says %v",
						channelType, noPortForwarding, forcedCommand, got, want)
				}

				verdict := channelVerdictFor(channelFamily(channelType, strings.IndexByte(channelType, ',')),
					noPortForwarding, forcedCommand)
				if got := verdict != channelPermitted; got != want {
					t.Fatalf("channelVerdictFor on %q = %d, refused %v, the gate says %v",
						channelType, verdict, got, want)
				}

				// the forwarding flag outranks the forced command, and that precedence is part of
				// what the catalogue says the gate does (SR-PERM-05)
				family := channelType
				if i := strings.IndexByte(family, ','); i >= 0 {
					family = family[:i]
				}
				if want && noPortForwarding && family != "sftp" && !strings.Contains(err.Error(), "port forwarding is forbidden") {
					t.Fatalf("CheckChannelOpen(%q) blamed something other than the forwarding flag: %q",
						channelType, err.Error())
				}
			}
		}
	}

	if err := (*IdentityOptions)(nil).CheckChannelOpen("sftp"); err != nil {
		t.Fatalf("a nil identity refused a channel open: %v", err)
	}
}

// TestConformanceForwardingFamilyIsTheEnumeration checks the set the verified postconditions talk
// about against the gate itself: every family the enumeration lists is refused by the forwarding
// flag, and no other family is.
func TestConformanceForwardingFamilyIsTheEnumeration(t *testing.T) {
	listed := []string{
		"direct-tcp", "direct-udp", "request-reverse-tcp", "request-reverse-udp",
		"open-request-reverse-tcp", "open-request-reverse-udp",
	}
	for _, family := range listed {
		if !isForwardingFamily(family) {
			t.Fatalf("%q is a forwarding family and the enumeration does not know it", family)
		}
		if verdict := channelVerdictFor(family, true, ""); verdict != channelRefusedPortForwarding {
			t.Fatalf("%q with no-port-forwarding set gave verdict %d", family, verdict)
		}
	}
	for _, family := range []string{"sftp", "session", "", "direct-tcp,1.2.3.4:22", "forward-udp", "Direct-Tcp"} {
		if isForwardingFamily(family) {
			t.Fatalf("%q is not a forwarding family and the enumeration claims it is", family)
		}
		if verdict := channelVerdictFor(family, true, ""); verdict != channelPermitted {
			t.Fatalf("%q is not a forwarding family but the forwarding flag gave verdict %d", family, verdict)
		}
	}
}

func TestConformanceChannelFamilyTrimsTheSuffix(t *testing.T) {
	for channelType, want := range map[string]string{
		"":                                     "",
		"sftp":                                 "sftp",
		"open-request-reverse-tcp,10.0.0.1:22": "open-request-reverse-tcp",
		",":                                    "",
		",x":                                   "",
		"direct-tcp,":                          "direct-tcp",
		"a,b,c":                                "a",
	} {
		if got := channelFamily(channelType, strings.IndexByte(channelType, ',')); got != want {
			t.Fatalf("channelFamily(%q) = %q, want %q", channelType, got, want)
		}
	}
}

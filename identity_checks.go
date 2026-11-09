package ssh3

// The decisions behind IdentityOptions.CheckRequest and CheckChannelOpen, separated from the
// messages they produce.
//
// The separation exists because of what the toolchain can read: Gobra v26.09 has stubs for
// strings and net but "does not support members defined in this package" for fmt, so a function
// that decides something and formats the refusal in the same statement cannot be verified where it
// lives. Putting the decision here -- an enum, no imports, no formatting -- means the gate that
// enforces no-pty, restrict, no-port-forwarding and a forced command is verified in shipped code
// rather than in a transcription of it, and the messages are then a switch over a value that has
// already been proved. proof/README.md, "Verification in place", has the details; glob.go is the
// other file in this category.
//
// The messages themselves are security-relevant only in that a refusal must be a refusal; which
// words each one uses is tested, not proved, in identity_options_source_conformance_test.go.

// A verdict on a channel request. The zero value permits, so that a verdict produced from an
// unrecognised request type or a nil identity allows, as it always has.
type requestVerdict int

const (
	requestPermitted requestVerdict = iota
	requestRefusedPty
	requestRefusedEnv
	requestRefusedX11
	requestRefusedAgent
)

// requestVerdictFor is the whole of the channel-request gate: requestType is the type as announced
// on the wire, plus the pseudo-type "agent-forwarding", and the four flags are what the identity's
// option line set.
//
// The postconditions below are the statement of SR-PERM-04 -- a request is refused exactly when the
// flag that governs it is set -- over the shipped decision, with nothing left in a model. Note what
// they do not say: that these are the only request types with a gate. That is the case by
// inspection of this function's body, and the `other` clause is what makes the enumeration
// exhaustive: any type not listed, however spelled, is permitted by every flag.
//
// @ decreases 0
// @ ensures (verdict == requestRefusedPty ==> requestType == "pty-req" && noPty) && (requestType == "pty-req" && noPty ==> verdict == requestRefusedPty)
// @ ensures (verdict == requestRefusedEnv ==> requestType == "env" && noEnv) && (requestType == "env" && noEnv ==> verdict == requestRefusedEnv)
// @ ensures (verdict == requestRefusedX11 ==> requestType == "x11-req" && noX11) && (requestType == "x11-req" && noX11 ==> verdict == requestRefusedX11)
// @ ensures (verdict == requestRefusedAgent ==> requestType == "agent-forwarding" && noAgent) && (requestType == "agent-forwarding" && noAgent ==> verdict == requestRefusedAgent)
// @ ensures (verdict == requestPermitted ==> !((requestType == "pty-req" && noPty) || (requestType == "env" && noEnv) || (requestType == "x11-req" && noX11) || (requestType == "agent-forwarding" && noAgent))) &&
// @     (!((requestType == "pty-req" && noPty) || (requestType == "env" && noEnv) || (requestType == "x11-req" && noX11) || (requestType == "agent-forwarding" && noAgent)) ==> verdict == requestPermitted)
func requestVerdictFor(requestType string, noPty bool, noEnv bool, noX11 bool, noAgent bool) (verdict requestVerdict) {
	switch requestType {
	case "pty-req":
		if noPty {
			return requestRefusedPty
		}
	case "env":
		if noEnv {
			return requestRefusedEnv
		}
	case "x11-req":
		if noX11 {
			return requestRefusedX11
		}
	case "agent-forwarding":
		if noAgent {
			return requestRefusedAgent
		}
	}
	return requestPermitted
}

// A verdict on opening a channel. As with a request, the zero value permits.
type channelVerdict int

const (
	channelPermitted channelVerdict = iota
	channelRefusedPortForwarding
	channelRefusedForwardingByCommand
	channelRefusedSftpByCommand
)

// channelVerdictFor is the channel-open gate. channelType arrives with data after a comma --
// "open-request-reverse-tcp,<address>" -- so the family is what precedes it; forwardingTypes is the
// set of families that count as port forwarding, spelled here because it is the security-relevant
// enumeration.
//
// The ensures clauses say the same thing twice, once in terms of the enumeration and once as the
// rule the catalogue states (SR-PERM-05): forwarding is refused when forwarding is forbidden or a
// forced command is set, and sftp is refused when a forced command is set. The second pair is what
// makes the rule visible without reading forwardingTypes; the first is what pins the set.
//
// @ decreases 0
// @ ensures (verdict == channelRefusedPortForwarding ==> isForwardingFamily(family) && noPortForwarding) && (isForwardingFamily(family) && noPortForwarding ==> verdict == channelRefusedPortForwarding)
// @ ensures (verdict == channelRefusedForwardingByCommand ==> isForwardingFamily(family) && !noPortForwarding && forcedCommand != "") && (isForwardingFamily(family) && !noPortForwarding && forcedCommand != "" ==> verdict == channelRefusedForwardingByCommand)
// @ ensures (verdict == channelRefusedSftpByCommand ==> family == "sftp" && forcedCommand != "") && (family == "sftp" && forcedCommand != "" ==> verdict == channelRefusedSftpByCommand)
// @ ensures (verdict == channelPermitted ==> !((isForwardingFamily(family) && (noPortForwarding || forcedCommand != "")) || (family == "sftp" && forcedCommand != ""))) &&
// @     (!((isForwardingFamily(family) && (noPortForwarding || forcedCommand != "")) || (family == "sftp" && forcedCommand != "")) ==> verdict == channelPermitted)
func channelVerdictFor(family string, noPortForwarding bool, forcedCommand string) (verdict channelVerdict) {
	switch family {
	case "direct-tcp", "direct-udp", "request-reverse-tcp", "request-reverse-udp", "open-request-reverse-tcp", "open-request-reverse-udp":
		if noPortForwarding {
			return channelRefusedPortForwarding
		}
		if forcedCommand != "" {
			return channelRefusedForwardingByCommand
		}
	case "sftp":
		if forcedCommand != "" {
			return channelRefusedSftpByCommand
		}
	}
	return channelPermitted
}

// isForwardingFamily is the set of channel families that port forwarding covers, stated apart from
// the switch that uses it so that the postconditions above can talk about it.
//
// @ pure
// @ decreases 0
// @ ensures res == (family == "direct-tcp" || family == "direct-udp" ||
// @     family == "request-reverse-tcp" || family == "request-reverse-udp" ||
// @     family == "open-request-reverse-tcp" || family == "open-request-reverse-udp")
//
//nolint:unused // the specification names this set; the switch in channelVerdictFor is what runs
func isForwardingFamily(family string) (res bool) {
	return family == "direct-tcp" || family == "direct-udp" ||
		family == "request-reverse-tcp" || family == "request-reverse-udp" ||
		family == "open-request-reverse-tcp" || family == "open-request-reverse-udp"
}

// channelFamily is the part of a channel type before a comma: "open-request-reverse-tcp,
// 10.0.0.1:22" belongs to the family "open-request-reverse-tcp". It carries no contract on
// purpose: the index arrives from strings.IndexByte, whose Gobra stub promises nothing about its
// range, so the slice's own precondition is not something the prover can take on from a stub. The
// behaviour is pinned by TestConformanceChannelFamilyTrimsTheSuffix instead.
//
// @ requires -1 <= comma && comma <= len(channelType)
// @ ensures comma < 0 ==> res == channelType
// @ ensures comma >= 0 ==> len(res) == comma
func channelFamily(channelType string, comma int) (res string) {
	if comma >= 0 {
		return channelType[:comma]
	}
	return channelType
}

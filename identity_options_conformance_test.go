package ssh3

import (
	"fmt"
	"strings"
	"testing"
)

// The Gobra unit proof/identityopts/model.gobra specifies the identity restrictions as an
// exact decision table: which option sets which flag, which request a flag refuses, which
// channel open a flag refuses, and what happens to a name this server does not enforce.
//
// That proof is only worth what its transcription is faithful, so this file enumerates the
// whole input space of those three decisions - every combination of the six decision fields
// against every request type and channel type, and every option name - and fails if the
// code the server runs disagrees with the table the proof checked. It is the same table in
// both places, and a change to one side has to be made in the other.

// modelCheckRequest is the ensures clause of checkRequest in the Gobra unit, written out in
// Go: a request is refused exactly when the flag which forbids it is set, and by nothing
// else.
func modelCheckRequest(o *IdentityOptions, requestType string) bool {
	return !(requestType == "pty-req" && o.NoPty) &&
		!(requestType == "env" && o.NoEnv) &&
		!(requestType == "x11-req" && o.NoX11Forwarding) &&
		!(requestType == "agent-forwarding" && o.NoAgentForwarding)
}

// modelForwardingType is the forwardingType predicate of the Gobra unit.
func modelForwardingType(channelType string) bool {
	switch channelType {
	case "direct-tcp", "direct-udp", "request-reverse-tcp", "request-reverse-udp",
		"open-request-reverse-tcp", "open-request-reverse-udp":
		return true
	}
	return false
}

// modelCheckChannelOpen is the ensures clause of checkChannelOpen in the Gobra unit.
func modelCheckChannelOpen(o *IdentityOptions, channelType string) bool {
	family := channelType
	if i := strings.IndexByte(family, ','); i >= 0 {
		family = family[:i]
	}
	return !((o.NoPortForwarding || o.ForcedCommand != "") && modelForwardingType(family)) &&
		!(o.ForcedCommand != "" && family == "sftp")
}

func TestConformanceIdentityOptionGatesMatchTheModel(t *testing.T) {
	requestTypes := []string{"pty-req", "env", "x11-req", "agent-forwarding", "shell", "subsystem",
		"window-change", ""}
	channelTypes := []string{"session", "direct-tcp", "direct-udp", "request-reverse-tcp",
		"request-reverse-udp", "open-request-reverse-tcp", "open-request-reverse-udp",
		"forward-tcp", "forward-udp", "sftp", "",
		// the family, not the parameter tail, decides
		"open-request-reverse-tcp,2001:db8::1:22", "direct-tcp,127.0.0.1:80"}
	// the six fields the gates read, in every combination
	for mask := 0; mask < 64; mask++ {
		options := &IdentityOptions{
			NoPty:             mask&1 != 0,
			NoPortForwarding:  mask&2 != 0,
			NoAgentForwarding: mask&4 != 0,
			NoX11Forwarding:   mask&8 != 0,
			NoEnv:             mask&16 != 0,
		}
		if mask&32 != 0 {
			options.ForcedCommand = "/bin/true"
		}
		for _, requestType := range requestTypes {
			if got, want := options.CheckRequest(requestType) == nil, modelCheckRequest(options, requestType); got != want {
				t.Fatalf("CheckRequest(%q) on %s: got allowed=%v, the proved table says %v",
					requestType, maskDescription(mask), got, want)
			}
		}
		for _, channelType := range channelTypes {
			if got, want := options.CheckChannelOpen(channelType) == nil, modelCheckChannelOpen(options, channelType); got != want {
				t.Fatalf("CheckChannelOpen(%q) on %s: got allowed=%v, the proved table says %v",
					channelType, maskDescription(mask), got, want)
			}
		}
	}
	// the nil option set - an identity which carried no options - allows everything, which
	// is the model's emptyOptions case
	var none *IdentityOptions
	for _, requestType := range requestTypes {
		if err := none.CheckRequest(requestType); err != nil {
			t.Fatalf("an identity without options must not refuse %q: %s", requestType, err)
		}
	}
	for _, channelType := range channelTypes {
		if err := none.CheckChannelOpen(channelType); err != nil {
			t.Fatalf("an identity without options must not refuse the channel %q: %s", channelType, err)
		}
	}
}

func maskDescription(mask int) string {
	names := []string{}
	for i, name := range []string{"NoPty", "NoPortForwarding", "NoAgentForwarding",
		"NoX11Forwarding", "NoEnv", "command="} {
		if mask&(1<<i) != 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "the empty restriction set"
	}
	return strings.Join(names, "+")
}

// enforcedOptionNames is supportedName in the Gobra unit: the names this server enforces.
// The two that need a value carry it, because an empty value is refused too - a stricter
// fail-closed, which cannot weaken what the proof says.
var enforcedOptionNames = []string{
	"command=/bin/true", "from=2001:db8::1", "restrict", "no-pty", "no-port-forwarding",
	"no-agent-forwarding", "no-x11-forwarding",
}

// unenforcedOptionNames are options OpenSSH knows (and which therefore appear in real
// files), plus typos: none of them may be accepted-and-ignored.
var unenforcedOptionNames = []string{
	"environment=FOO=bar", "permitopen=host:22", "tunnel=0", "no-touch-required",
	"verify-required", "no-env", "cert-authority", "exit-*,no-forward", "restrictions=",
	"no-ptyy", "No-PTY-Extra", "command", "from",
}

func TestConformanceParseIdentityOptionsIsFailClosed(t *testing.T) {
	// every enforced name, alone, parses and sets exactly what it says and nothing else
	for _, name := range enforcedOptionNames {
		options, err := ParseIdentityOptions([]string{name})
		if err != nil {
			t.Fatalf("the enforced option %q must parse: %s", name, err)
		}
		if options == nil {
			t.Fatalf("the enforced option %q must produce a restriction set", name)
		}
		key := name
		if i := strings.IndexByte(key, '='); i >= 0 {
			key = key[:i]
		}
		switch key {
		case "command":
			if options.ForcedCommand != "/bin/true" {
				t.Fatalf("%q must force the command it carries, got %q", name, options.ForcedCommand)
			}
		case "from":
			if len(options.From) != 1 || options.From[0] != "2001:db8::1" {
				t.Fatalf("%q must keep the address list, got %v", name, options.From)
			}
		}
		// no enforced option may clear a restriction, and none of them may set a restriction
		// belonging to another name (SR-PERM-03: adding an option never removes one)
		switch key {
		case "command", "from":
			if options.NoPty || options.NoPortForwarding || options.NoAgentForwarding ||
				options.NoX11Forwarding || options.NoEnv {
				t.Fatalf("%q must not restrict more than it says: %+v", name, *options)
			}
		case "no-pty", "no-port-forwarding", "no-agent-forwarding", "no-x11-forwarding":
			if options.NoEnv {
				t.Fatalf("%q must not forbid the environment; only restrict does: %+v", name, *options)
			}
		}
	}
	// one unenforced name anywhere in the list and the whole line is refused (SR-PERM-01)
	for _, bad := range unenforcedOptionNames {
		list := append([]string{"no-pty", "restrict"}, bad)
		options, err := ParseIdentityOptions(list)
		if err == nil {
			t.Fatalf("the option %q is not enforced, so the identity must be refused; got %+v", bad, options)
		}
		if options != nil {
			t.Fatalf("a refused identity must come with no restriction set at all, got %+v", options)
		}
	}
	// order-independence (SR-PERM-03): the restriction set depends on the names, not on the
	// order they were written in
	for _, a := range enforcedOptionNames {
		for _, b := range enforcedOptionNames {
			if a == b {
				continue // two identical command= entries are a duplicate, which is refused
			}
			first, err := ParseIdentityOptions([]string{a, b})
			if err != nil {
				t.Fatalf("%q and %q must parse together: %s", a, b, err)
			}
			second, err := ParseIdentityOptions([]string{b, a})
			if err != nil {
				t.Fatalf("%q and %q must parse in the other order too: %s", b, a, err)
			}
			if fmt.Sprint(*first) != fmt.Sprint(*second) {
				t.Fatalf("%q,%q and %q,%q give different restriction sets: %+v vs %+v", a, b, b, a, *first, *second)
			}
		}
	}
	// "restrict" is the conjunction of the five single restrictions it stands for
	// (SR-PERM-02)
	fromShortcut, err := ParseIdentityOptions([]string{"restrict"})
	if err != nil {
		t.Fatalf("restrict must parse: %s", err)
	}
	spelled, err := ParseIdentityOptions([]string{"no-pty", "no-port-forwarding",
		"no-agent-forwarding", "no-x11-forwarding"})
	if err != nil {
		t.Fatalf("the spelled-out restrictions must parse: %s", err)
	}
	if !fromShortcut.NoPty || !fromShortcut.NoPortForwarding || !fromShortcut.NoAgentForwarding ||
		!fromShortcut.NoX11Forwarding || !fromShortcut.NoEnv {
		t.Fatalf("restrict must set all five restrictions, got %+v", *fromShortcut)
	}
	if spelled.NoPty != fromShortcut.NoPty || spelled.NoPortForwarding != fromShortcut.NoPortForwarding ||
		spelled.NoAgentForwarding != fromShortcut.NoAgentForwarding ||
		spelled.NoX11Forwarding != fromShortcut.NoX11Forwarding {
		t.Fatalf("restrict and its spelled-out form must agree, got %+v vs %+v", *fromShortcut, *spelled)
	}
	// the environment is the one restriction OpenSSH's restrict adds which has no name of
	// its own; the Gobra unit states this, and it is what makes
	// restrictedIdentityRefusesEverythingItSaysItRefuses non-trivial
	if spelled.NoEnv {
		t.Fatalf("no-env is not an option name, so only restrict may forbid the environment")
	}
}

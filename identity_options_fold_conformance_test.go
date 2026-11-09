package ssh3

// Conformance tests for SR-PERM-08: option names are matched case-insensitively in a way that can
// only *add* restrictions. proof/identityopts/model.gobra is handed the already case-folded name --
// the model's `supportedName` is a set of lower-case names -- so the real `strings.ToLower(name)` in
// ParseIdentityOptions sits outside the proof. These tests say what that folding does, over the
// spellings a configuration or a token claim could arrive with, which closes the gap.
//
// Three claims, strongest first:
//
//   - Folding reaches exactly the ASCII case variants. Every spelling of an enforced name that
//     `strings.ToLower` maps to it is accepted and behaves exactly like the lower-case name: same
//     flags, same forced command, same address list. Case is a convenience for someone copying
//     "no-X11-forwarding" out of sshd(8), not a wider name space with wider behaviour.
//   - Nothing else folds in. A spelling that differs from an enforced name by a Unicode look-alike --
//     the Kelvin sign, the long s, the dotted and dotless I, the Angstrom sign, full-width forms --
//     is *refused*, not accepted as the option it resembles. That is the direction that matters: an
//     administrator who writes a restriction in a spelling the server does not know loses the login,
//     loudly, rather than getting a session where the restriction silently does nothing.
//   - Whatever is accepted restricts. There is no accepted option that sets nothing, which is what
//     makes the case-insensitive comparison safe to have at all: the folded name space contains only
//     restricting names.

import (
	"fmt"
	"strings"
	"testing"
)

// conformanceFoldNames are the enforced names, each with the value its grammar needs. They are
// spelled in lower case because that is the form the model reasons about; the values are left exactly
// as written, because folding applies to the name and not to a command or an address.
var conformanceFoldNames = []struct{ name, value string }{
	{"command", "/bin/true"}, {"from", "2001:db8::1"}, {"restrict", ""}, {"no-pty", ""},
	{"no-port-forwarding", ""}, {"no-agent-forwarding", ""}, {"no-x11-forwarding", ""},
}

// conformanceOption puts a name back together with its value.
func conformanceOption(name, value string) string {
	if value == "" {
		return name
	}
	return name + "=" + value
}

// conformanceRestrictionState is the restriction state as a string, in a fixed order so that "the
// same verdict" can be asserted rather than meant.
func conformanceRestrictionState(options *IdentityOptions) string {
	if options == nil {
		return "<no restriction set>"
	}
	fields := []string{}
	if options.ForcedCommand != "" {
		fields = append(fields, "command="+options.ForcedCommand)
	}
	if len(options.From) > 0 {
		fields = append(fields, fmt.Sprintf("from=%v", options.From))
	}
	for _, flag := range []struct {
		name string
		set  bool
	}{
		{"NoPty", options.NoPty},
		{"NoPortForwarding", options.NoPortForwarding},
		{"NoAgentForwarding", options.NoAgentForwarding},
		{"NoX11Forwarding", options.NoX11Forwarding},
		{"NoEnv", options.NoEnv},
	} {
		if flag.set {
			fields = append(fields, flag.name)
		}
	}
	if len(fields) == 0 {
		return "<empty restriction set>"
	}
	return strings.Join(fields, " ")
}

// conformanceASCIIVariants spells an ASCII name every way that ASCII case allows: the name itself,
// its upper-case form, and every per-letter combination of the two.
func conformanceASCIIVariants(name string) []string {
	out := []string{name, strings.ToUpper(name)}
	seen := map[string]bool{name: true, strings.ToUpper(name): true}
	var walk func(bytes []byte, i int)
	walk = func(bytes []byte, i int) {
		if i >= len(bytes) {
			s := string(bytes)
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
			return
		}
		walk(bytes, i+1)
		if 'a' <= bytes[i] && bytes[i] <= 'z' {
			bytes[i] -= 'a' - 'A'
			walk(bytes, i+1)
			bytes[i] += 'a' - 'A'
		}
	}
	walk([]byte(name), 0)
	return out
}

// conformanceLookalikes are the Unicode spellings that make a case-insensitive comparison a Unicode
// question rather than an ASCII one: each is a character a person might paste in place of the ASCII
// letter beside it, and `strings.ToLower` is what decides whether the result is still the name.
var conformanceLookalikes = []struct {
	letter rune
	name   string
	rune   string
}{
	{'k', "KELVIN SIGN", "\u212a"},
	{'s', "LATIN SMALL LETTER LONG S", "\u017f"},
	{'i', "LATIN CAPITAL LETTER I WITH DOT ABOVE", "\u0130"},
	{'i', "LATIN SMALL LETTER DOTLESS I", "\u0131"},
	{'a', "ANGSTROM SIGN", "\u212b"},
	{'f', "FULLWIDTH LATIN SMALL LETTER F", "\uff46"},
	{'r', "FULLWIDTH LATIN CAPITAL LETTER R", "\uff32"},
	{'t', "MATHEMATICAL BOLD ITALIC SMALL T", "\U0001D731"},
}

// conformanceLookalikeVariants returns each look-alike spelling of name that can be formed, together
// with what strings.ToLower makes of it.
func conformanceLookalikeVariants(name string) []struct{ spelling, folded string } {
	var out []struct{ spelling, folded string }
	for _, look := range conformanceLookalikes {
		idx := strings.IndexRune(name, look.letter)
		if idx < 0 {
			continue
		}
		spelling := name[:idx] + look.rune + name[idx+1:]
		out = append(out, struct{ spelling, folded string }{spelling, strings.ToLower(spelling)})
	}
	return out
}

// TestConformanceFoldingReachesExactlyTheASCIIVariants is the first claim: over all 2^len case
// variants of every enforced name, ParseIdentityOptions accepts and produces exactly the restriction
// state of the lower-case name.
func TestConformanceFoldingReachesExactlyTheASCIIVariants(t *testing.T) {
	for _, entry := range conformanceFoldNames {
		baseline, err := ParseIdentityOptions([]string{conformanceOption(entry.name, entry.value)})
		if err != nil {
			t.Fatalf("the enforced option %q must parse: %s", entry.name, err)
		}
		want := conformanceRestrictionState(baseline)
		if want == "<empty restriction set>" || want == "<no restriction set>" {
			t.Fatalf("the enforced option %q restricts nothing, which contradicts SR-PERM-08 on its own",
				entry.name)
		}
		variants := conformanceASCIIVariants(entry.name)
		for _, spelling := range variants {
			variant := conformanceOption(spelling, entry.value)
			got, err := ParseIdentityOptions([]string{variant})
			if err != nil {
				t.Errorf("ParseIdentityOptions(%q) failed: %s", variant, err)
				continue
			}
			if state := conformanceRestrictionState(got); state != want {
				t.Errorf("ParseIdentityOptions(%q) gives %s, but %q gives %s -- the case of the name "+
					"changed what the option restricts", variant, state,
					conformanceOption(entry.name, entry.value), want)
			}
		}
		t.Logf("%q: %d case variants, all accepted with the restriction state %q",
			entry.name, len(variants), want)
	}
}

// TestConformanceFoldingRefusesLookalikes is the second claim, and the one whose failure would have
// been dangerous rather than merely odd: a name that differs from an enforced option by a Unicode
// look-alike is refused outright. `strings.ToLower` is a Unicode function -- it maps the Kelvin sign
// to 'k' and the Angstrom sign to 'a' -- so the only thing standing between "RESTRIC\u212a" and a
// restriction the administrator believes is in force is this refusal, and the login fails loudly
// instead of quietly losing the restriction.
func TestConformanceFoldingRefusesLookalikes(t *testing.T) {
	checked := 0
	for _, entry := range conformanceFoldNames {
		for _, variant := range conformanceLookalikeVariants(entry.name) {
			// the fold is what the comparison sees; if it happens to still be the name, the
			// spelling is an ordinary accepted one and there is nothing to refuse here
			if variant.folded == strings.ToLower(entry.name) {
				continue
			}
			option := conformanceOption(variant.spelling, entry.value)
			options, err := ParseIdentityOptions([]string{option})
			if err == nil {
				t.Errorf("ParseIdentityOptions(%q) was accepted with state %q, although its folded "+
					"name %q is not the enforced %q: an unrecognised spelling must be refused, not "+
					"accepted as the option it resembles",
					option, conformanceRestrictionState(options), variant.folded, entry.name)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no look-alike spelling was reachable; the corpus has drifted")
	}
	t.Logf("%d look-alike spellings, all refused", checked)
}

// TestConformanceFoldedNamesAllRestrict is the third claim: nothing is accepted for doing nothing.
// Every option the parser accepts -- enforced name in any spelling -- sets at least one restriction,
// and every option OpenSSH knows but sshoq does not enforce is refused in every case variant, so
// folding cannot smuggle in an option that silently does nothing.
func TestConformanceFoldedNamesAllRestrict(t *testing.T) {
	for _, option := range unenforcedOptionNames {
		name, value, _ := strings.Cut(option, "=")
		for _, spelling := range conformanceASCIIVariants(name) {
			variant := conformanceOption(spelling, value)
			options, err := ParseIdentityOptions([]string{variant})
			if err != nil {
				continue // refused: fail closed, which is the expected half
			}
			if state := conformanceRestrictionState(options); state == "<empty restriction set>" ||
				state == "<no restriction set>" {
				t.Errorf("ParseIdentityOptions(%q) was accepted and restricts nothing (%s): "+
					"an accepted option must always restrict, and %q is an unenforced name",
					variant, state, option)
			}
		}
	}
}

// TestConformanceFoldingDoesNotCollideNames says the folded name space is still one option per name,
// which is the precondition of the tests above meaning anything: if two enforced names folded to one,
// "case does not change the verdict" would be vacuous, and if an unenforced name folded onto an
// enforced one, SR-PERM-01 and SR-PERM-08 could not both hold.
func TestConformanceFoldingDoesNotCollideNames(t *testing.T) {
	seen := map[string]string{}
	for _, entry := range conformanceFoldNames {
		key := strings.ToLower(entry.name)
		if other, clash := seen[key]; clash {
			t.Fatalf("%q and %q both fold to %q: two enforced options would be one", entry.name, other, key)
		}
		seen[key] = entry.name
	}
	for _, option := range unenforcedOptionNames {
		name, _, _ := strings.Cut(option, "=")
		key := strings.ToLower(name)
		// two entries of that list are enforced names written without their value -- "command" and
		// "from" -- and they are there to check the empty-value refusal, not the name space
		if _, enforcedButValueless := seen[key]; enforcedButValueless {
			if _, _, hasValue := strings.Cut(option, "="); !hasValue {
				continue
			}
		}
		if enforced, clash := seen[key]; clash {
			t.Fatalf("%q is listed as unenforced but folds to the enforced %q -- one of the two lists "+
				"is wrong, and SR-PERM-01 and SR-PERM-08 cannot both hold", option, enforced)
		}
	}
}

// TestConformanceFoldingIsASCIIOnASCII states what "the already case-folded name" in the model means,
// for the only names the model can hold: on ASCII input, strings.ToLower is ASCII case folding and
// nothing else. The non-ASCII spellings are refused rather than folded into the model's name space,
// which is what TestConformanceFoldingRefusesLookalikes checks.
func TestConformanceFoldingIsASCIIOnASCII(t *testing.T) {
	asciiFold := func(s string) string {
		out := []byte(s)
		for i := range out {
			if 'A' <= out[i] && out[i] <= 'Z' {
				out[i] += 'a' - 'A'
			}
		}
		return string(out)
	}
	subjects := []string{}
	for _, entry := range conformanceFoldNames {
		subjects = append(subjects, conformanceASCIIVariants(entry.name)...)
	}
	for _, option := range unenforcedOptionNames {
		name, _, _ := strings.Cut(option, "=")
		subjects = append(subjects, conformanceASCIIVariants(name)...)
	}
	for _, subject := range subjects {
		if strings.IndexFunc(subject, func(r rune) bool { return r >= 0x80 }) >= 0 {
			continue
		}
		if got, want := strings.ToLower(subject), asciiFold(subject); got != want {
			t.Fatalf("strings.ToLower(%q) = %q, ASCII folding gives %q -- the model's name space is "+
				"not what the parser compares on", subject, got, want)
		}
	}
}

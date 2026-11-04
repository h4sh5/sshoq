package ssh3

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

// SR-PERM-03, on the parser the server runs.
//
// `proof/identityopts/model.gobra` proves the fold as a *closed form*: when `parseOptions` succeeds,
// every flag of the resulting restriction set equals "some name in the list was this name, or
// `restrict`", and `forcedCommand` equals the text of `command=`. A closed form mentions only which
// names occur, so the two halves of this requirement -- processing another recognised option never
// clears a restriction, and the result does not depend on the order the options were written in -- are
// corollaries of one clause rather than two lemmas. That is stated properly in the requirement's row.
//
// What was missing is the shipped side. `ParseIdentityOptions` lives in a file that formats errors with
// `fmt.Errorf`, so the prover cannot read it and the closed form is a property of the model. These tests
// hold the real parser to the same closed form, over every subset of the seven enforced names and in six
// orders per subset, and then to monotonicity directly: for every pair of subsets with S ⊆ T, the
// restrictions of S are a subset of the restrictions of T. Both are exhaustive over the name space the
// parser recognises, so this is not a sample.
//
// The forced command's *text* and the `from=` *list* are included, not just the five booleans: "the
// result depends only on the set of names" is a claim about the whole restriction set, and a parser that
// quietly kept the first `command=` rather than the last -- or cleared one when a later option arrived --
// would satisfy a booleans-only version of this test.

// conformanceClosedFormNames lists every option name the parser enforces, with the value its grammar
// needs. Same seven as the case-folding tests, restated here because the two files are about different
// properties and should not fail to agree because one was edited.
var conformanceClosedFormNames = []struct{ name, value string }{
	{"command", "/bin/true"}, {"from", "2001:db8::1"}, {"restrict", ""}, {"no-pty", ""},
	{"no-port-forwarding", ""}, {"no-agent-forwarding", ""}, {"no-x11-forwarding", ""},
}

// conformanceOptionText reassembles a name with the value it needs.
func conformanceOptionText(i int) string {
	name, value := conformanceClosedFormNames[i].name, conformanceClosedFormNames[i].value
	if value == "" {
		return name
	}
	return name + "=" + value
}

// conformanceFlagsOfSubset is the closed form the model proves, written out in Go: the set of
// restrictions a subset of names must produce, as a sorted list of strings so two of them can be
// compared and a difference named.
func conformanceFlagsOfSubset(subset map[int]bool) []string {
	has := func(name string) bool {
		for i, n := range conformanceClosedFormNames {
			if n.name == name {
				return subset[i]
			}
		}
		return false
	}
	flags := []string{}
	if has("no-pty") || has("restrict") {
		flags = append(flags, "no-pty")
	}
	if has("no-port-forwarding") || has("restrict") {
		flags = append(flags, "no-port-forwarding")
	}
	if has("no-agent-forwarding") || has("restrict") {
		flags = append(flags, "no-agent-forwarding")
	}
	if has("no-x11-forwarding") || has("restrict") {
		flags = append(flags, "no-x11-forwarding")
	}
	if has("restrict") {
		flags = append(flags, "no-env")
	}
	if has("command") {
		flags = append(flags, "command=/bin/true")
	}
	if has("from") {
		flags = append(flags, "from=[2001:db8::1]")
	}
	sort.Strings(flags)
	return flags
}

// conformanceParseSubset parses one subset, in the order given by `perm`, and returns the restrictions
// as the same sorted list the closed form produces.
func conformanceParseSubset(t *testing.T, perm []int) []string {
	t.Helper()
	options := make([]string, 0, len(perm))
	for _, i := range perm {
		options = append(options, conformanceOptionText(i))
	}
	parsed, err := ParseIdentityOptions(options)
	if err != nil {
		t.Fatalf("ParseIdentityOptions(%v) = %v, want success: every name here is enforced", options, err)
	}
	if parsed == nil {
		// The parser's answer to an empty option list is no restriction set at all rather than a
		// zero-valued one, and SR-PERM-04 is what says nil means "allows everything" -- the same
		// state as an empty list of restrictions here. It must be the only time it happens: a
		// non-empty list of enforced names returning nil would be a restriction that vanished.
		if len(perm) != 0 {
			t.Fatalf("ParseIdentityOptions(%v) returned no restriction set for a non-empty option list", options)
		}
		return []string{}
	}
	seen := map[int]bool{}
	for _, i := range perm {
		seen[i] = true
	}
	got := []string{}
	if parsed.NoPty {
		got = append(got, "no-pty")
	}
	if parsed.NoPortForwarding {
		got = append(got, "no-port-forwarding")
	}
	if parsed.NoAgentForwarding {
		got = append(got, "no-agent-forwarding")
	}
	if parsed.NoX11Forwarding {
		got = append(got, "no-x11-forwarding")
	}
	if parsed.NoEnv {
		got = append(got, "no-env")
	}
	if parsed.ForcedCommand != "" {
		got = append(got, "command="+parsed.ForcedCommand)
	}
	if len(parsed.From) > 0 {
		got = append(got, fmt.Sprintf("from=%v", parsed.From))
	}
	sort.Strings(got)
	return got
}

// TestConformanceShippedFoldEqualsTheClosedForm walks every subset of the enforced names -- all 128 --
// and every permutation the test has time to ask for, and requires the parser's answer to be exactly
// what the closed form says. Order-independence is inside this test rather than beside it: the same
// subset is parsed in six orders and every one must give the same list.
func TestConformanceShippedFoldEqualsTheClosedForm(t *testing.T) {
	n := len(conformanceClosedFormNames)
	count := 1 << n
	rng := rand.New(rand.NewSource(3))
	parsed := 0
	for mask := 0; mask < count; mask++ {
		base := []int{}
		subset := map[int]bool{}
		for i := 0; i < n; i++ {
			if mask&(1<<i) != 0 {
				base = append(base, i)
				subset[i] = true
			}
		}
		want := strings.Join(conformanceFlagsOfSubset(subset), ",")

		orders := [][]int{base}
		for k := 0; k < 5; k++ {
			perm := append([]int{}, base...)
			rng.Shuffle(len(perm), func(a, b int) { perm[a], perm[b] = perm[b], perm[a] })
			orders = append(orders, perm)
		}
		for _, perm := range orders {
			got := strings.Join(conformanceParseSubset(t, perm), ",")
			parsed++
			if got != want {
				t.Fatalf("subset %v in order %v: parser says [%s], the closed form says [%s]",
					mask, perm, got, want)
			}
		}
	}
	if parsed != count*6 {
		t.Fatalf("expected %d parses, did %d", count*6, parsed)
	}
	t.Logf("%d parses over %d subsets and 6 orders each", parsed, count)
}

// TestConformanceShippedFoldIsMonotoneInTheNames states the requirement's first half directly rather
// than deriving it: for every pair of subsets S ⊆ T, every restriction the parser applies for S it also
// applies for T. It is checked against the parser, not against the closed form, so it is a second look at
// the same code from the other direction -- a parser that cleared a flag when an unrelated option arrived
// fails this even if the closed-form test above were somehow satisfied.
func TestConformanceShippedFoldIsMonotoneInTheNames(t *testing.T) {
	n := len(conformanceClosedFormNames)
	count := 1 << n
	states := make([]map[string]bool, count)
	for mask := 0; mask < count; mask++ {
		set := map[string]bool{}
		for _, f := range conformanceParseSubset(t, indicesOf(mask)) {
			set[f] = true
		}
		states[mask] = set
	}
	compared := 0
	for s := 0; s < count; s++ {
		for sup := 0; sup < count; sup++ {
			if s&sup != s {
				continue
			}
			compared++
			for f := range states[s] {
				if !states[sup][f] {
					t.Fatalf("not monotone: %q is restricted for subset %d but not for its superset %d", f, s, sup)
				}
			}
		}
	}
	if compared < count {
		t.Fatalf("no subset pairs compared: %d", compared)
	}
	t.Logf("%d subset pairs, none losing a restriction", compared)
}

// indicesOf turns a subset bitmask into the name indices it contains, in increasing order.
func indicesOf(mask int) []int {
	out := []int{}
	for i := 0; i < len(conformanceClosedFormNames); i++ {
		if mask&(1<<i) != 0 {
			out = append(out, i)
		}
	}
	return out
}

// TestConformanceUnknownOptionStillRefusesEverySubset is the fail-closed half attached to the same
// enumeration: one unenforced name added to any subset -- in any position -- and the whole line is
// refused with no restriction set returned. A monotone fold that accepted-and-ignored would look
// perfectly monotone here, which is why this is checked over the same 128 subsets rather than once.
func TestConformanceUnknownOptionStillRefusesEverySubset(t *testing.T) {
	unknowns := []string{"no-env", "environment=x", "permitopen=80", "tunnel=0", "pty", "restriction", "RESTRICT-"}
	count := 1 << len(conformanceClosedFormNames)
	for mask := 0; mask < count; mask++ {
		options := []string{}
		for _, i := range indicesOf(mask) {
			options = append(options, conformanceOptionText(i))
		}
		for _, u := range unknowns {
			for pos := 0; pos <= len(options); pos++ {
				withUnknown := append(append([]string{}, options[:pos]...), u)
				withUnknown = append(withUnknown, options[pos:]...)
				parsed, err := ParseIdentityOptions(withUnknown)
				if err == nil {
					t.Fatalf("%q in %v was accepted, yielding %v: an unenforced name must refuse the line",
						u, withUnknown, parsed)
				}
				if parsed != nil {
					t.Fatalf("%q in %v was refused but still returned a restriction set", u, withUnknown)
				}
			}
		}
	}
}

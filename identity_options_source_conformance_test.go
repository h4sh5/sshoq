package ssh3

// Conformance tests for the `from=` restriction: proof/sourcecheck/model.gobra versus
// identity_options.go (matchGlob, matchesSourcePattern, CheckSource, parsePeerIP).
//
// The model proves the *decision algebra* -- the two guards, the choice between the three
// strategies, and the negated list -- over the facts those strategies return, and says so in the
// header of the unit. These tests are the other half of the line: they say what the real functions
// return for those facts, and they are where the recursive glob itself is pinned down, because a
// recursive pure function in Gobra v26.09 is opaque once its measure is checked (see the unit's
// header and proof/README.md): its meaning cannot be derived inside the prover, so it is derived
// here, against an independent implementation.

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// conformanceGlob is matchGlob written a second time, independently: the classic two-pointer
// matcher, which does not recurse and runs in time linear in |pattern| + |text|. Agreement between
// the two over a large corpus is what gives the recursive version a meaning the prover could not
// give it: a pattern with stars stands for some split of the text, and both implementations find
// the same splits or miss them together.
func conformanceGlob(pattern, text string) bool {
	p, t := 0, 0
	star, mark := -1, 0
	for t < len(text) {
		switch {
		case p < len(pattern) && pattern[p] == '*': // before the literal case: finding F6
			star = p
			mark = t
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == text[t]):
			p++
			t++
		case star >= 0:
			p = star + 1
			mark++
			t = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// conformanceWords returns every string of length up to n over the given alphabet, shortest first.
func conformanceWords(alphabet []byte, n int) []string {
	out := []string{""}
	current := []string{""}
	for l := 1; l <= n; l++ {
		var next []string
		for _, w := range current {
			for _, c := range alphabet {
				next = append(next, w+string(c))
			}
		}
		out = append(out, next...)
		current = next
	}
	return out
}

// legacyMatchGlob is matchGlob as it was before the linear-time rewrite, verbatim: a recursion that
// tries the rest of the pattern after every possible prefix of the text. It is kept here because it
// is the definition the rewrite had to preserve, and because Gobra v26.09 cannot say that for itself
// -- a recursive pure function is opaque once its measure is checked (see proof/sourcecheck).
func legacyMatchGlob(pattern, text string) bool {
	var rec func(p, t string) bool
	rec = func(p, t string) bool {
		for len(p) > 0 {
			switch p[0] {
			case '*':
				for i := 0; ; i++ {
					if rec(p[1:], t[i:]) {
						return true
					}
					if i >= len(t) {
						return false
					}
				}
			case '?':
				if len(t) == 0 {
					return false
				}
				p, t = p[1:], t[1:]
			default:
				if len(t) == 0 || t[0] != p[0] {
					return false
				}
				p, t = p[1:], t[1:]
			}
		}
		return len(t) == 0
	}
	return rec(pattern, text)
}

// TestConformanceMatchGlobIsTheGlob says which function matchGlob is. Over every pattern of at most
// four characters from {a, b, *, ?, [, .} (1555 of them) and every text of at most four characters
// from {a, b, ., *} (341 of them), the shipped matcher, the recursion it replaced, and a second linear
// matcher written a different way all agree. Brackets and the dot are in the pattern alphabet because
// "[" makes matchesSourcePattern treat a pattern as a glob while the glob itself reads it as a
// literal, and because a textual address is always dotted. The star is in the *text* alphabet because
// of finding F6: without a star in the text, the corpus could not tell the two orders of the two
// cases apart, and both linear implementations were wrong in the same way.
func TestConformanceMatchGlobIsTheGlob(t *testing.T) {
	patterns := conformanceWords([]byte{'a', 'b', '*', '?', '[', '.'}, 4)
	texts := conformanceWords([]byte{'a', 'b', '.', '*'}, 4)
	triples := 0
	for _, p := range patterns {
		for _, text := range texts {
			want := conformanceGlob(p, text)
			if got := matchGlob(p, text); got != want {
				t.Fatalf("matchGlob(%q, %q) = %v, the independent linear matcher says %v", p, text, got, want)
			}
			if got := legacyMatchGlob(p, text); got != want {
				t.Fatalf("the recursion matchGlob replaced says %v for (%q, %q), which the linear one says is %v"+
					" -- the rewrite changed the meaning", got, p, text, want)
			}
			triples++
		}
	}
	if triples < 500000 {
		t.Fatalf("corpus is smaller than this test's claim: %d triples", triples)
	}
	t.Logf("%d pattern/text triples agree across three implementations", triples)
}

// TestConformanceMatchGlobStarInText is finding F6, and the reason the corpus above has stars in its
// texts: a "*" in the text is an ordinary character, but it is equal to a "*" in the pattern, so a
// matcher that tests literal equality before it tests for a star consumes the star as a literal,
// saves nothing, and has nothing to retry when the rest fails. matchGlob("a*", "a*b") returned false
// while OpenSSH's match_pattern() -- and the recursion this function replaced -- return true. Both
// linear implementations had the two cases in the same wrong order, which is why "three independent
// implementations" did not catch it and the Gobra annotations on glob.go did: the prover was asked
// what "*" means and got an answer.
func TestConformanceMatchGlobStarInText(t *testing.T) {
	cases := []struct {
		pattern, text string
		want          bool
	}{
		{"a*", "a*b", true},
		{"a*", "ab*", true},
		{"*", "**", true},
		{"*b", "*b", true},
		{"a*b", "a*b", true},
		{"a?c", "a?c", true},
		{"?", "*", true},
		{"?", "**", false},
		{"a*", "a", true},
		{"*a", "*a", true},
		{"ab*", "*ab", false}, // the first character of the pattern still has to match
		{"*ab", "*ab", true},
		{"a*a", "aa*", false},
	}
	for _, c := range cases {
		if got := matchGlob(c.pattern, c.text); got != c.want {
			t.Fatalf("matchGlob(%q, %q) = %v, want %v (finding F6)", c.pattern, c.text, got, c.want)
		}
		// the recursion this function replaced is the one that encodes OpenSSH's order, so it is the
		// reference for what the answer has to be
		if got := legacyMatchGlob(c.pattern, c.text); got != c.want {
			t.Fatalf("legacyMatchGlob(%q, %q) = %v, want %v: the reference implementation disagrees"+
				" with the table, so the table is what changed", c.pattern, c.text, got, c.want)
		}
		if got := conformanceGlob(c.pattern, c.text); got != c.want {
			t.Fatalf("the second linear matcher says %v for (%q, %q), want %v", got, c.pattern, c.text, c.want)
		}
	}
}

// TestConformanceLiteralGlobIsEquality is SR-PERM-07 -- "a pattern containing no wildcard matches
// exactly one text (equality)" -- checked exhaustively rather than asserted: over the same corpus
// with the wildcard characters removed, matchGlob accepts exactly the text equal to the pattern, and
// nothing else, of any length. This is the property that makes a wildcard-free `from=` value mean
// "this address" and not "an address of the same length".
func TestConformanceLiteralGlobIsEquality(t *testing.T) {
	literals := conformanceWords([]byte{'a', 'b'}, 4)
	texts := conformanceWords([]byte{'a', 'b'}, 4)
	for _, p := range literals {
		if strings.ContainsAny(p, "*?[") {
			t.Fatalf("corpus bug: %q holds a wildcard", p)
		}
		for _, text := range texts {
			want := p == text
			if got := matchGlob(p, text); got != want {
				t.Fatalf("matchGlob(%q, %q) = %v, equality says %v", p, text, got, want)
			}
		}
	}
}

// TestConformanceMatchGlobIsBounded is the resource bound, and the regression guard for finding F5:
// the patterns that make a backtracking matcher work hardest -- many stars, a text that keeps almost
// matching and then fails -- return in a time that does not depend on how many stars there are. The
// worst case below is sixty stars against an eighty-character text. The recursion this replaced needed
// 4.9s for ten stars and 2m56s for fourteen on that text, which is why the guard is a time bound and
// not a boolean: this is input that reaches the server before it has agreed anything with the peer,
// because `from=` arrives with the identity and matchesSourcePattern runs on every login attempt that
// carries one.
func TestConformanceMatchGlobIsBounded(t *testing.T) {
	long := strings.Repeat("ab", 40)
	cases := []struct {
		pattern string
		text    string
	}{
		{"*a*b*c*d*e*f*g*h*i*j", long},
		{strings.Repeat("a*", 8) + "z", long},
		{strings.Repeat("a*", 14) + "z", long},
		{strings.Repeat("?*", 20) + "z", long},
		{"**a**b**c**", long},
		{strings.Repeat("*", 60), long},
		{strings.Repeat("a*", 60) + "z", long},
		{strings.Repeat("10.*.", 20), "10.0.2.3"},
	}
	done := make(chan time.Duration)
	go func() {
		start := time.Now()
		for _, c := range cases {
			matchGlob(c.pattern, c.text)
		}
		done <- time.Since(start)
	}()
	select {
	case elapsed := <-done:
		if elapsed > time.Second {
			t.Fatalf("eight star-heavy patterns took %s in total; the matcher is meant to be linear in "+
				"len(pattern)+len(text) (finding F5)", elapsed)
		}
		t.Logf("eight star-heavy patterns, the worst 60 stars against 80 characters: %s", elapsed)
	case <-time.After(10 * time.Second):
		t.Fatal("matchGlob had not returned after 10s on patterns designed to make it backtrack")
	}
}

// TestConformanceMatchesSourcePatternStrategies says what the three strategies in
// matchesSourcePattern actually return, which is what the model's lemmas take as premises: the two
// guards, containment for a network, equality for a literal address (including the two textual
// forms of one IPv6 address, which the model treats as a single ipEquals), refusal for a host name,
// and the glob only ever for a pattern that holds a wildcard.
func TestConformanceMatchesSourcePatternStrategies(t *testing.T) {
	v4 := net.ParseIP("192.0.2.7")
	v6 := net.ParseIP("::1")
	if v4 == nil || v6 == nil {
		t.Fatal("test cannot parse its own addresses")
	}
	cases := []struct {
		pattern string
		ip      net.IP
		want    bool
		why     string
	}{
		{"", v4, false, "the empty pattern matches nothing, whatever the address"},
		{"10.0.0.0/8", net.ParseIP("10.9.9.9"), true, "a network holds the address"},
		{"10.0.0.0/8", net.ParseIP("11.9.9.9"), false, "a network that does not hold it refuses; nothing else is tried"},
		{"0.0.0.0/0", v4, true, "the whole v4 space"},
		{"192.0.2.7", v4, true, "a literal address is equality"},
		{"192.0.2.8", v4, false, "one octet off is a different address"},
		{"::1", v6, true, "the textual form the administrator wrote"},
		{"0:0:0:0:0:0:0:1", v6, true, "the same address spelled the long way: net.IP.Equal, not string equality"},
		{"::2", v6, false, "a different v6 address"},
		{"example.com", v4, false, "a host name matches nothing: no lookup is performed"},
		{"localhost", v6, false, "not even a name every host has"},
		{"192.0.2.*", v4, true, "the glob runs over the textual address"},
		{"192.?.2.7", v4, true, "a question mark inside a textual address"},
		{"10.*", v4, false, "a glob that does not describe this text"},
		{"[::1]", v6, false, "brackets make a pattern a glob rather than an address, and inside this glob they are literals -- so nothing matches: fail-closed, not a character class"},
		{"[::1]*", v6, false, "even with a star the brackets are read as themselves"},
		{"192.0.2.7", nil, false, "an undeterminable address matches nothing, whatever the pattern"},
		{"*", nil, false, "not even a pattern that would match any text"},
	}
	for _, c := range cases {
		if got := matchesSourcePattern(c.pattern, c.ip); got != c.want {
			t.Errorf("matchesSourcePattern(%q, %v) = %v, want %v (%s)", c.pattern, c.ip, got, c.want, c.why)
		}
	}
}

// TestConformanceCheckSourceTable is the model's fromListDecides against the real CheckSource: every
// row of the model's decision table, realised with real addresses, real `from=` lists and real
// errors. A nil error is the model's `true`.
func TestConformanceCheckSourceTable(t *testing.T) {
	cases := []struct {
		from   []string
		addr   string
		want   bool
		reason string
	}{
		// no restriction: nothing to enforce
		{nil, "192.0.2.7:443", true, "no from= at all restricts nothing"},
		{[]string{}, "nonsense", true, "an empty list is no restriction, even against an unparsable address"},

		// under a restriction, an undeterminable source is refused: fail closed
		{[]string{"10.0.0.0/8"}, "", false, "no source address at all"},
		{[]string{"10.0.0.0/8"}, "not-an-address", false, "a source address the server cannot name"},
		{[]string{"10.0.0.0/8"}, "10.1.2.3", true, "no port is not what RemoteAddr looks like, but SplitHostPort failing means the whole string is the host -- and that parses"},

		// a described source is accepted
		{[]string{"10.0.0.0/8"}, "10.1.2.3:443", true, "a network that holds it"},
		{[]string{"10.1.2.3"}, "10.1.2.3:443", true, "the literal address"},
		{[]string{"10.*"}, "10.1.2.3:443", true, "a glob over the text"},
		{[]string{"::1"}, "[::1]:443", true, "v6 RemoteAddr is bracketed; parsePeerIP trims it"},
		{[]string{"::1"}, "0:0:0:0:0:0:0:1:443", false, "a v6 address without brackets is ambiguous, and ambiguous is refused"},

		// an undescribed source is refused: there is no way in through an unmatched address
		{[]string{"10.0.0.0/8"}, "11.1.2.3:443", false, "not in the network"},
		{[]string{"10.0.0.0/8", "10.1.2.3"}, "192.0.2.7:443", false, "not in either pattern"},
		{[]string{"example.com"}, "10.1.2.3:443", false, "a host name describes nothing"},
		{[]string{"!10.1.2.3"}, "192.0.2.7:443", false, "a list of negations alone never accepts: accepted implies described"},

		// an exclusion cannot be outvoted, and the order of the list changes nothing
		{[]string{"10.0.0.0/8", "!10.9.9.9"}, "10.9.9.9:443", false, "the exclusion holds although the network describes it"},
		{[]string{"!10.9.9.9", "10.0.0.0/8"}, "10.9.9.9:443", false, "same verdict with the patterns swapped"},
		{[]string{"10.0.0.0/8", "!10.9.9.9"}, "10.1.1.1:443", true, "the exclusion is not a refusal of everything"},
		{[]string{"!10.9.9.9", "10.0.0.0/8"}, "10.1.1.1:443", true, "same verdict with the patterns swapped"},
		{[]string{"10.0.0.0/8", "!10.0.0.0/8"}, "10.1.1.1:443", false, "a pattern and its negation: the negation wins"},
	}
	for _, c := range cases {
		options := &IdentityOptions{From: c.from}
		err := options.CheckSource(c.addr)
		if got := err == nil; got != c.want {
			t.Errorf("CheckSource(%q) with from=%q = %v, want accepted=%v (%s)",
				c.addr, c.from, err, c.want, c.reason)
		}
	}
}

// TestConformanceCheckSourceIsOrderIndependent states the model's claim -- the verdict is a function
// of the two disjunctions the loop computes, so no permutation of the list changes it -- over every
// permutation of several real lists, including the ones where the code returns early on a negated
// match and so never sees what follows it.
func TestConformanceCheckSourceIsOrderIndependent(t *testing.T) {
	type result struct {
		accepted bool
	}
	run := func(from []string, addr string) result {
		return result{(&IdentityOptions{From: from}).CheckSource(addr) == nil}
	}
	lists := [][]string{
		{"10.0.0.0/8"},
		{"10.0.0.0/8", "!10.9.9.9"},
		{"192.0.2.7", "10.0.0.0/8", "!10.9.9.9"},
		{"!10.9.9.9", "10.1.2.3", "10.0.0.0/8"},
		{"*", "!10.9.9.9"},
		{"example.com", "10.0.0.0/8"},
	}
	addresses := []string{"10.1.2.3:443", "10.9.9.9:443", "192.0.2.7:443", "nonsense", ""}
	for _, list := range lists {
		for _, addr := range addresses {
			want := run(list, addr)
			perms := conformancePermutations(list)
			for _, perm := range perms {
				if got := run(perm, addr); got != want {
					t.Fatalf("CheckSource(%q): from=%v gives accepted=%v but from=%v gives %v "+
						"-- the verdict is supposed to depend only on which patterns match",
						addr, list, want.accepted, perm, got.accepted)
				}
			}
		}
	}
}

func conformancePermutations(items []string) [][]string {
	if len(items) <= 1 {
		return [][]string{append([]string(nil), items...)}
	}
	var out [][]string
	for i := range items {
		rest := append(append([]string{}, items[:i]...), items[i+1:]...)
		for _, tail := range conformancePermutations(rest) {
			out = append(out, append([]string{items[i]}, tail...))
		}
	}
	return out
}

// TestConformanceParsePeerIP is the guard the model calls addressKnown: what the server can and
// cannot name as a peer, since an address it cannot name is refused under `from=` rather than
// waved through. The forms are the ones an HTTP/3 server actually puts in RemoteAddr.
func TestConformanceParsePeerIP(t *testing.T) {
	cases := []struct {
		addr   string
		wantOK bool
		want   string
	}{
		{"10.1.2.3:443", true, "10.1.2.3"},
		{"[::1]:443", true, "::1"},
		{"::1", true, "::1"}, // no port, so SplitHostPort fails and the whole string is the host, which parses
		{"", false, ""},
		{"nonsense:443", false, ""},
		{"10.1.2.3", true, "10.1.2.3"},
		{"[fe80::1%eth0]:1234", false, ""}, // a scoped address is not one `from=` can name
	}
	for _, c := range cases {
		ip := parsePeerIP(c.addr)
		if gotOK := ip != nil; gotOK != c.wantOK {
			t.Errorf("parsePeerIP(%q) = %v (ok=%v), want ok=%v", c.addr, ip, gotOK, c.wantOK)
			continue
		}
		if ip != nil && ip.String() != c.want {
			t.Errorf("parsePeerIP(%q) = %q, want %q", c.addr, ip.String(), c.want)
		}
	}
}

// TestConformanceFromListFactsAreTheModelPremises names the two disjunctions the model decides on
// and checks that the real loop's verdict really is their function -- no third fact, such as which
// pattern matched first, is allowed to matter. This is the row-by-row form of the table above, and
// it is the statement the unit's fromListDecides corresponds to.
func TestConformanceFromListFactsAreTheModelPremises(t *testing.T) {
	addresses := []string{"10.1.2.3:443", "10.9.9.9:443", "192.0.2.7:443", "nonsense"}
	lists := [][]string{
		{"10.0.0.0/8"},
		{"10.0.0.0/8", "!10.9.9.9"},
		{"10.9.9.9"},
		{"!10.0.0.0/8"},
		{"*", "!10.9.9.9"},
		{},
	}
	for _, list := range lists {
		for _, addr := range addresses {
			ip := parsePeerIP(addr)
			positive, excluded := false, false
			for _, pattern := range list {
				negated := strings.HasPrefix(pattern, "!")
				if matchesSourcePattern(strings.TrimPrefix(pattern, "!"), ip) {
					if negated {
						excluded = true
					} else {
						positive = true
					}
				}
			}
			restricted := len(list) > 0
			want := !restricted || ip != nil && !excluded && positive
			got := (&IdentityOptions{From: list}).CheckSource(addr) == nil
			if got != want {
				t.Errorf("from=%v addr=%q: CheckSource accepted=%v but the model's two facts "+
					"(addressKnown=%v positive=%v excluded=%v) give %v",
					list, addr, got, ip != nil, positive, excluded, want)
			}
		}
	}
}

var _ = fmt.Sprintf

// TestConformanceNegationHelpers keeps isNegated -- the helper whose behaviour the proof of the
// source rule takes for granted -- equal to the strings method the loop used to call directly. It
// matters because the shipped loop now asks the named helper, so this line is what makes "which
// patterns are exclusions" in the proof mean "starts with an exclamation mark" in the wire format.
func TestConformanceNegationHelpers(t *testing.T) {
	patterns := []string{
		"", "!", "!!", "!10.0.0.0/8", "10.0.0.0/8", "10.*", "!10.*", "a!", " !x", "! ",
		"\t!", "example.com", "!example.com", "＊", "！x", "\x00!", "!*",
	}
	for _, pattern := range patterns {
		if got, want := isNegated(pattern), strings.HasPrefix(pattern, "!"); got != want {
			t.Errorf("isNegated(%q) = %v but strings.HasPrefix(%q, \"!\") = %v", pattern, got, pattern, want)
		}
	}
}

// TestConformanceSourceMatchesSplits is the single loop CheckSource used to run, taken apart: the
// per-pattern work moved to sourceMatches and the combination to sourceVerdictFor, and this says the
// two halves still compute exactly what the one loop computed -- the same exclusion flags, the same
// match results (against a body with the "!" trimmed), and the same accepted/excluded pair the loop
// would have reached. Exhaustive over the interesting pattern spellings, including a doubled "!",
// which is an exclusion whose body is a pattern that can match nothing.
func TestConformanceSourceMatchesSplits(t *testing.T) {
	patterns := []string{
		"10.0.0.0/8", "!10.9.9.9", "10.1.2.3", "!10.1.2.3", "10.*", "*", "!*",
		"::1", "!::1", "example.com", "!example.com", "", "!", "!!10.1.2.3",
	}
	addresses := []net.IP{
		net.ParseIP("10.1.2.3"), net.ParseIP("10.9.9.9"), net.ParseIP("192.0.2.7"),
		net.ParseIP("::1"), nil,
	}
	for _, ip := range addresses {
		negated, matched := sourceMatches(patterns, ip)
		if len(negated) != len(patterns) || len(matched) != len(patterns) {
			t.Fatalf("sourceMatches returned %d and %d flags for %d patterns", len(negated), len(matched), len(patterns))
		}
		positive, excluded := false, false
		for i, pattern := range patterns {
			wantNegated := strings.HasPrefix(pattern, "!")
			wantMatched := matchesSourcePattern(strings.TrimPrefix(pattern, "!"), ip)
			if negated[i] != wantNegated {
				t.Errorf("sourceMatches flag %d (%q): exclusion=%v, want %v", i, pattern, negated[i], wantNegated)
			}
			if matched[i] != wantMatched {
				t.Errorf("sourceMatches flag %d (%q): matched=%v, want %v", i, pattern, matched[i], wantMatched)
			}
			if wantMatched {
				if wantNegated {
					excluded = true
				} else {
					positive = true
				}
			}
		}
		// the loop returned early on an exclusion; the split scans everything and the verdict
		// below has to agree with what that early return decided
		got := sourceVerdictFor(true, ip != nil, negatedMatch(negated, matched, 0), inclusionMatch(negated, matched, 0))
		want := sourceRefusedNotListed
		switch {
		case ip == nil:
			want = sourceRefusedNoAddress
		case excluded:
			want = sourceRefusedExcluded
		case positive:
			want = sourcePermitted
		}
		if got != want {
			t.Errorf("split decision for address %v is %d, the original loop reaches %d", ip, got, want)
		}
	}
}

// TestConformanceSourceVerdictIsTheRule walks the whole input space of the proved decision function
// and checks each of the sixteen combinations against the rule as a reader of docs/server_config.md
// would state it. This is what the unit in source_check.go proves -- exhaustively here is the same
// set -- and it is the half of the correspondence that does not depend on any address parsing.
func TestConformanceSourceVerdictIsTheRule(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		for _, known := range []bool{false, true} {
			for _, excluded := range []bool{false, true} {
				for _, listed := range []bool{false, true} {
					want := sourcePermitted
					switch {
					case !restricted:
						want = sourcePermitted
					case !known:
						want = sourceRefusedNoAddress
					case excluded:
						want = sourceRefusedExcluded
					case listed:
						want = sourcePermitted
					default:
						want = sourceRefusedNotListed
					}
					if got := sourceVerdictFor(restricted, known, excluded, listed); got != want {
						t.Errorf("sourceVerdictFor(restricted=%v, known=%v, excluded=%v, listed=%v) = %d, want %d",
							restricted, known, excluded, listed, got, want)
					}
				}
			}
		}
	}
}

// TestConformanceVerdictsAreReachableAndWorded ties each verdict the proof reasons about to the one
// CheckSource message that reports it, with the wording the messages have always had. An operator
// tells "not in your network" from "your address is not known" from "you are excluded" by that text,
// so the mapping is part of the behaviour the split must not change.
func TestConformanceVerdictsAreReachableAndWorded(t *testing.T) {
	cases := []struct {
		from    []string
		addr    string
		verdict sourceVerdict
		message string // "" means no error, i.e. the permitted verdict
		through string
	}{
		{[]string{"10.0.0.0/8"}, "10.1.2.3:443", sourcePermitted, "", "a network that describes the address"},
		{[]string{"10.0.0.0/8"}, "nonsense", sourceRefusedNoAddress,
			"cannot determine the source address of the peer, which is required by the from=\"...\" restriction of this identity",
			"an address the server cannot name"},
		{[]string{"10.0.0.0/8", "!10.1.2.3"}, "10.1.2.3:443", sourceRefusedExcluded,
			"source address 10.1.2.3 is excluded by the from=\"...\" restriction of this identity",
			"an exclusion that the inclusion also describes"},
		{[]string{"10.0.0.0/8"}, "192.0.2.7:443", sourceRefusedNotListed,
			"source address 192.0.2.7 is not allowed by the from=\"...\" restriction of this identity",
			"an address no pattern describes"},
	}
	for _, c := range cases {
		err := (&IdentityOptions{From: c.from}).CheckSource(c.addr)
		if c.verdict == sourcePermitted {
			if err != nil {
				t.Errorf("CheckSource(%q) with from=%q: %v, want acceptance (%s)", c.addr, c.from, err, c.through)
			}
			continue
		}
		if err == nil {
			t.Errorf("CheckSource(%q) with from=%q accepted, want verdict %d (%s)", c.addr, c.from, c.verdict, c.through)
			continue
		}
		if err.Error() != c.message {
			t.Errorf("CheckSource(%q) with from=%q said %q, want %q (%s)", c.addr, c.from, err.Error(), c.message, c.through)
		}
	}
	// and the verdict CheckSource reaches is the one the split computes for the same input
	for _, c := range cases {
		ip := parsePeerIP(c.addr)
		negated, matched := sourceMatches(c.from, ip)
		got := sourceVerdictFor(len(c.from) > 0, ip != nil, negatedMatch(negated, matched, 0), inclusionMatch(negated, matched, 0))
		if got != c.verdict {
			t.Errorf("from=%q addr=%q: the decision is %d but CheckSource reported %d (%s)",
				c.from, c.addr, got, c.verdict, c.through)
		}
	}
}

// TestConformanceMatchPredicatesAreTheScan checks the two proved predicates against the scan they
// summarise, over every array of flags up to length four and from every starting index -- including
// the empty array, where both must say no, and the all-matched array, where an exclusion in the last
// position must still win.
func TestConformanceMatchPredicatesAreTheScan(t *testing.T) {
	for length := 0; length <= 4; length++ {
		for mask := 0; mask < 1<<(2*length); mask++ {
			negated := make([]bool, length)
			matched := make([]bool, length)
			for i := 0; i < length; i++ {
				negated[i] = mask&(1<<(2*i)) != 0
				matched[i] = mask&(1<<(2*i+1)) != 0
			}
			for start := 0; start <= length; start++ {
				wantExcluded, wantListed := false, false
				for i := start; i < length; i++ {
					if matched[i] {
						if negated[i] {
							wantExcluded = true
						} else {
							wantListed = true
						}
					}
				}
				if got := negatedMatch(negated, matched, start); got != wantExcluded {
					t.Errorf("negatedMatch(%v, %v, %d) = %v, want %v", negated, matched, start, got, wantExcluded)
				}
				if got := inclusionMatch(negated, matched, start); got != wantListed {
					t.Errorf("inclusionMatch(%v, %v, %d) = %v, want %v", negated, matched, start, got, wantListed)
				}
			}
		}
	}
}

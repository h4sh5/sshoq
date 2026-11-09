package server_auth

// The truncation of an untrusted `User-Agent`, verified where it runs.
//
// It lives in a file of its own for the same reason `glob.go` and `source_check.go` do: the code
// around it -- login_policy.go, auth.go -- imports `fmt`, and Gobra v26.09's stub for `fmt` says
// "We do not support members defined in this package", so nothing in those files can be verified
// where it sits. This file imports nothing, and `make proof` checks it.
//
// What the annotations below prove, and what they cannot:
//
//   * Memory safety is proved by the checker itself, not by a claim: the scan that walks back off
//     a multi-byte character indexes `s[cut]`, and Gobra only accepts that if the loop invariant
//     puts `cut` inside the string. That is the F10 bug class -- this function used to be `s[:100]`
//     in an error message, which panicked on every shorter header -- and it is now a proof
//     obligation rather than a review comment.
//   * The three clauses are the whole contract an unbounded header obeys: a non-positive bound
//     yields the empty string, a header that fits comes back *identically*, and a truncated line is
//     between three and max+3 bytes long, which is the statement that keeps one attacker-chosen
//     header from making a log line arbitrarily long.
//   * Which prefix survives is not provable here. The result is `s[:cut] + "..."`, and the prover
//     knows the length of a concatenation but has no rule for the characters of one --
//     `(a + b)[i] == a[i]` for `i < len(a)` is simply not in its theory -- so a claim like
//     `prefixEq(res, s, len(res)-3)` is refused. `TestConformanceTruncateMatchesTheModel` pins that
//     part instead, against the model in `proof/truncation`, on inputs whose boundary falls inside
//     two- and three-byte characters.

// truncate shortens s to at most max bytes, cutting on a rune boundary so that a header made of
// multi-byte characters cannot produce invalid UTF-8 in the log. The ellipsis is why the proved
// upper bound is max+3 rather than max: the alternative -- cutting the prefix to max-3 so the whole
// line fits max -- was never the behaviour, and changing it is a product decision, not a proof.
//
// @ ensures max <= 0 ==> res == ""
// @ ensures 0 < max && len(s) <= max ==> res == s
// @ ensures 0 < max && max < len(s) ==> 3 <= len(res) && len(res) <= max + 3
func truncate(s string, max int) (res string) {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := max
	// @ invariant 0 <= cut && cut <= max && max < len(s)
	// @ decreases cut
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "..."
}

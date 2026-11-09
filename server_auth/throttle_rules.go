package server_auth

import "time"

// The rules a login failure window applies, separated from the table, the lock and the
// clock that apply them, and verified here where they run.
//
// This file is a leaf: it imports `time` and nothing else, which is what makes it verifiable.
// The reason `login_policy.go` itself is not is `fmt` -- Gobra v26.09's stub for that package
// says "We do not support members defined in this package", so a file that formats an error (and
// `loginLocked.Error` does) cannot be checked where it lives. `time` by contrast is stubbed with
// real specs, `Duration` arithmetic included, so the rules below speak Durations exactly as the
// code around them does and nothing has to be converted at the boundary.
//
// The four functions are what loginThrottle.check asks the state, in the order it asks, plus the
// stale-window test that failure() and the capacity sweep share. Each of them used to be an
// inline expression, and a copy of the pre-split expressions is kept in the conformance test that
// covers them -- see finding F6 in proof/SECURITY_REQUIREMENTS.md for why that is stated instead
// of "behaviour unchanged".

// windowElapsed says whether a failure window that started `elapsed` ago is over. The
// comparison is strict, and that is a decision rather than an accident: at exactly the window
// length the failures still count, and the window closes one attempt later. The comparison is also
// what makes a clock that steps backwards harmless -- a negative elapsed time is "not yet over",
// never a fresh window -- and negative elapsed times are reachable, because the wall clock is not
// monotonic and `now` is whatever time.Now returns.
//
// @ ensures elapsed == window ==> !expired
// @ ensures elapsed > window ==> expired
// @ ensures elapsed < window ==> !expired
func windowElapsed(elapsed time.Duration, window time.Duration) (expired bool) {
	return elapsed > window
}

// attemptIsRefused says whether a key that already failed `failures` times in the current window
// may attempt again. The boundary is `failures >= maxFailures`: with a limit of ten, the tenth
// failure is the last one that is answered at all, and the eleventh attempt is refused -- one
// fewer guessing attempt than the sentence this function used to sit under, which said "more than
// maxFailures times". The docs describe the refusing count as the limit, and
// TestConformanceRefusalBoundaryIsTheLimit pins which of the two readings the server implements,
// so the sentence cannot drift from the code again.
//
// @ requires 0 <= maxFailures
// @ ensures refused == (failures >= maxFailures)
// @ ensures failures == maxFailures ==> refused
// @ ensures failures < maxFailures ==> !refused
func attemptIsRefused(failures int, maxFailures int) (refused bool) {
	return failures >= maxFailures
}

// failureDelay is how long an attempt waits given the failures already recorded for its key: one
// step per failure, capped at `limit`. The cap is the claim -- it is what keeps the delay an
// attacker provokes from ever exceeding the window the operator configured -- and it is proved
// here for every input, including a step of zero (no delay at all, which is how a deployment turns
// the delay off without turning the refusal off) and a limit of zero.
//
// What is a premise, and was one in the model too: `Duration` is a 64-bit count of nanoseconds, so
// a failure count times a step past 2^63 overflows instead of capping. Reaching it needs about nine
// billion failures inside one window. TestConformanceFailureDelayAtTheOverflowBoundary records what
// the shipped expression actually does there rather than assuming the proof covers it.
//
// @ requires 0 <= failures && 0 <= step && 0 <= limit
// @ ensures 0 <= delay && delay <= limit
// @ ensures failures == 0 ==> delay == 0
// @ ensures 0 < failures && time.Duration(failures) * step <= limit ==> delay == time.Duration(failures) * step
// @ ensures limit < time.Duration(failures) * step ==> delay == limit
func failureDelay(failures int, step time.Duration, limit time.Duration) (delay time.Duration) {
	delay = time.Duration(failures) * step
	if delay > limit {
		delay = limit
	}
	return delay
}

// retryAfter is how a refusal reports the time left of the lock-out: the time left of the window,
// floored at zero. The floor matters twice over. `loginLocked.RetryAfter` is printed to the client
// and to the log, and a negative one reads as a duration counted backwards; and the value is what a
// client uses to decide when to come back, for which "not before zero" is the only sane answer. The
// remaining time can legitimately be negative -- the window can have closed between the moment the
// entry was read and the moment this is computed, and a backwards clock does it too. The `if` below
// is the floor, spelled out rather than as `max(remaining, 0)`: this Gobra's Go frontend does not
// know the `min` and `max` builtins ("got unknown identifier min"), which is worth knowing before
// writing the next verified file.
//
// @ ensures 0 <= left
// @ ensures remaining >= 0 ==> left == remaining
// @ ensures remaining < 0 ==> left == 0
func retryAfter(remaining time.Duration) (left time.Duration) {
	if remaining < 0 {
		return 0
	}
	return remaining
}

// failureDelayGrowsWithFailures is the monotonicity of the delay: waiting never gets shorter as the
// failures pile up. It is not called by the server; it is how the property is stated where Gobra can
// check it, next to the function it is about -- and stated this way rather than as a clause of
// failureDelay itself, because "for every greater failure count" would have to call failureDelay
// from inside a spec, and this failureDelay is impure (a capped multiplication is two returns, and
// `min`, which would make it one, is unknown to the prover).
//
// @ requires 0 <= lower && lower <= upper && 0 <= step && 0 <= limit
// @ ensures grows
func failureDelayGrowsWithFailures(lower int, upper int, step time.Duration, limit time.Duration) (grows bool) {
	fewer := failureDelay(lower, step, limit)
	more := failureDelay(upper, step, limit)
	// both caps are the same limit, and the uncapped product only grows: whichever of the two
	// is capped, the other one is below it
	return fewer <= more
}

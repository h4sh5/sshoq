package server_auth

// The rules a login failure window applies, separated from the table, the lock and the
// clock that apply them, and verified here where they run.
//
// This file has no imports, which is not a style choice: Gobra v26.09 checks a verified
// file together with its own stubs of the standard library and nothing else -- not even
// its package-mates -- and it has no stub for the `time` package at all. So the throttle's
// arithmetic is spelled in integer nanoseconds, which is what a `time.Duration` *is*: the
// call sites in login_policy.go convert with `Nanoseconds()`, a getter for the same int64,
// and convert back with `time.Duration(...)`. What that leaves outside the proof is one
// thing, named here rather than in a review comment: a `Duration` holds at most about 292
// years, so a window longer than that wraps on conversion. The configured windows are
// minutes (see passwordFailureWindow), and TestConformanceThrottleConversionsAreLossless
// checks the round trip for every duration the server can be configured with.
//
// The four functions are exactly what loginThrottle.check asks the state, in the order it
// asks. Each of them used to be an inline expression, and a copy of the pre-split
// expressions is kept in the conformance test that covers them -- see finding F6 in
// proof/SECURITY_REQUIREMENTS.md for why that is stated instead of "behaviour unchanged".

// windowElapsed says whether a failure window that started `elapsed` nanoseconds ago is
// over. The comparison is strict, and that is a decision rather than an accident: at
// exactly the window length the failures still count, and the window closes one attempt
// later. The comparison is also what makes a clock that steps backwards harmless -- a
// negative elapsed time is "not yet over", never a fresh window -- and negative elapsed
// times are reachable, because the wall clock is not monotonic and `now` is whatever
// time.Now returns.
//
// @ ensures elapsed == window ==> !expired
// @ ensures elapsed > window ==> expired
// @ ensures elapsed < window ==> !expired
func windowElapsed(elapsed int, window int) (expired bool) {
	return elapsed > window
}

// attemptIsRefused says whether a key that already failed `failures` times in the current
// window may attempt again. The boundary is `failures >= maxFailures`: with a limit of ten,
// the tenth failure is the last one that is answered at all, and the eleventh attempt is
// refused -- one fewer guessing attempt than the sentence this function used to sit under,
// which said "more than maxFailures times". The docs and docs/server_config.md describe the
// refusing count as the limit, and TestConformanceRefusalBoundaryIsTheLimit pins which of
// the two readings the server implements, so the sentence cannot drift from the code again.
//
// @ requires 0 <= maxFailures
// @ ensures refused == (failures >= maxFailures)
// @ ensures failures == maxFailures ==> refused
// @ ensures failures < maxFailures ==> !refused
func attemptIsRefused(failures int, maxFailures int) (refused bool) {
	return failures >= maxFailures
}

// failureDelay is how long an attempt waits, in nanoseconds, given the failures already
// recorded for its key: one step per failure, capped at max. The cap is the claim -- it is
// what keeps a locked-out-looking delay from ever exceeding the window the operator
// configured, and it is proved here for every input, including a step of zero (no delay at
// all, which is how a deployment turns the delay off without turning the refusal off) and a
// cap of zero.
//
// What is a premise, and is a premise in the model too: Go's `int` is 64 bits, so a failure
// count times a step bigger than 2^63 overflows instead of capping. Reaching it needs about
// nine billion failures inside one five-minute window. TestConformanceFailureDelayAtTheOverflowBoundary
// records what the shipped expression actually does there, rather than assuming the proof
// covers it.
//
// @ requires 0 <= failures && 0 <= step && 0 <= limit
// @ ensures 0 <= delay && delay <= limit
// @ ensures failures == 0 ==> delay == 0
// @ ensures 0 < failures && failures * step <= limit ==> delay == failures * step
// @ ensures limit < failures * step ==> delay == limit
func failureDelay(failures int, step int, limit int) (delay int) {
	delay = failures * step
	if delay > limit {
		delay = limit
	}
	return delay
}

// retryAfter is how a refusal reports the time left of the lock-out: the nanoseconds left
// of the window, floored at zero. The floor matters twice over. `Duration.RetryAfter` is
// printed to the client and to the log, and a negative one reads as a duration counted
// backwards; and the value is what an operator or a client would use to decide when to come
// back, for which "not before zero" is the only sane answer. The remaining time can
// legitimately be negative -- the window can have closed between the moment the entry was
// read and the moment this is computed, and a backwards clock does it too. The body is the
// `if` below is the floor, spelled out rather than as `max(remaining, 0)`: this Gobra's Go
// frontend does not know the `min` and `max` builtins at all ("got unknown identifier min"),
// which is worth knowing before writing the next verified file.
//
// @ ensures 0 <= left
// @ ensures remaining >= 0 ==> left == remaining
// @ ensures remaining < 0 ==> left == 0
func retryAfter(remaining int) (left int) {
	if remaining < 0 {
		return 0
	}
	return remaining
}

// failureDelayGrowsWithFailures is the monotonicity of the delay: waiting never gets
// shorter as the failures pile up. It is not called by the server; it is how the property
// is stated where Gobra can check it, next to the function it is about. Saying it as a
// lemma rather than as a clause of failureDelay costs nothing and buys the statement -- the
// clause "for all greater failure counts" cannot live in an ensures of the function it
// quantifies over unless that function is pure, and a pure function has to be a single
// return of a pure expression, which the capped multiplication is not.
//
// @ requires 0 <= lower && lower <= upper && 0 <= step && 0 <= limit
// @ ensures grows
func failureDelayGrowsWithFailures(lower int, upper int, step int, limit int) (grows bool) {
	fewer := failureDelay(lower, step, limit)
	more := failureDelay(upper, step, limit)
	// both caps are the same limit, and the uncapped product only grows: whichever of the two
	// is capped, the other one is below it
	return fewer <= more
}

package server_auth

import (
	"fmt"
	"testing"
	"time"
)

// The rules in throttle_rules.go are verified there, over every input. What these tests hold is
// the seam around them: that each verified function computes what the inline expression it
// replaced computed, and that loginThrottle.check -- the code that applies the rules to a table
// and a clock -- still reaches the answer it reached before the rules were lifted out. The expected
// values below are the pre-split expressions, copied literally, for the reason given as finding F6
// in proof/SECURITY_REQUIREMENTS.md: comparing a refactor against a copy of what the old code said
// is the only way to catch a clause that was carried over wrongly.

// oldDelay is `delay := time.Duration(failures) * step; if delay > max { delay = max }`, the two
// lines check() used to run.
func oldDelay(failures int, step, max time.Duration) time.Duration {
	delay := time.Duration(failures) * step
	if delay > max {
		delay = max
	}
	return delay
}

// oldRetryAfter is `retryAfter := windowStart.Add(window).Sub(now); if retryAfter < 0 {
// retryAfter = 0 }`, the four lines check() used to run.
func oldRetryAfter(windowStart time.Time, window time.Duration, now time.Time) time.Duration {
	retryAfter := windowStart.Add(window).Sub(now)
	if retryAfter < 0 {
		retryAfter = 0
	}
	return retryAfter
}

// TestConformanceThrottleRulesAreTheExpressions checks the three rules that replaced inline
// arithmetic against that arithmetic, over windows, steps, caps, failure counts and clock positions.
func TestConformanceThrottleRulesAreTheExpressions(t *testing.T) {
	windows := []time.Duration{0, time.Nanosecond, time.Second, passwordFailureWindow, time.Hour, 292 * 365 * 24 * time.Hour}
	steps := []time.Duration{0, time.Nanosecond, 250 * time.Millisecond, passwordDelayStep, time.Second, passwordMaxDelay, time.Hour}
	maxes := []time.Duration{0, time.Nanosecond, passwordMaxDelay, time.Second, time.Minute, 24 * time.Hour}
	offsets := []time.Duration{-3 * time.Hour, -2 * time.Hour, -time.Hour, -time.Nanosecond, 0, time.Nanosecond, 90 * time.Minute}
	start := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	for _, window := range windows {
		for _, step := range steps {
			for _, max := range maxes {
				for _, offset := range offsets {
					windowStart := start.Add(offset)
					elapsed := start.Sub(windowStart)
					for failures := 0; failures <= 12; failures++ {
						// window expiry, as check(), failure() and the capacity sweep ask it
						if got, want := windowElapsed(elapsed, window), elapsed > window; got != want {
							t.Errorf("windowElapsed(elapsed=%v, window=%v) = %v, the comparison says %v", elapsed, window, got, want)
						}
						// the delay, as check() asks it
						if got, want := failureDelay(failures, step, max), oldDelay(failures, step, max); got != want {
							t.Errorf("failureDelay(%d, %v, %v) = %v, the two lines it replaced compute %v",
								failures, step, max, got, want)
						}
						// the refusal and its remaining time
						if got, want := attemptIsRefused(failures, 5), failures >= 5; got != want {
							t.Errorf("attemptIsRefused(%d, 5) = %v, the comparison says %v", failures, got, want)
						}
						if got, want := retryAfter(windowStart.Add(window).Sub(start)), oldRetryAfter(windowStart, window, start); got != want {
							t.Errorf("retryAfter for window %v starting %v seen at %v = %v, the four lines it replaced compute %v",
								window, windowStart, start, got, want)
						}
					}
				}
			}
		}
	}
}

// TestConformanceThrottleDelayProperties checks the shape the proof of failureDelay claims -- never
// negative, never above the cap, growing with the failures -- by walking the inputs, and includes
// the lemma function so that it cannot rot into saying something else.
func TestConformanceThrottleDelayProperties(t *testing.T) {
	steps := []time.Duration{0, time.Nanosecond, 999 * time.Nanosecond, time.Second, time.Minute}
	maxes := []time.Duration{0, time.Nanosecond, passwordMaxDelay, time.Second, time.Hour}
	for _, step := range steps {
		for _, max := range maxes {
			previous := time.Duration(-1)
			for failures := 0; failures <= 40; failures++ {
				delay := failureDelay(failures, step, max)
				if delay < 0 || delay > max {
					t.Errorf("failureDelay(%d, %v, %v) = %v, outside [0, %v]", failures, step, max, delay, max)
				}
				if delay < previous {
					t.Errorf("the delay shrank: %d failures wait %v, %d wait %v (step %v, cap %v)",
						failures-1, previous, failures, delay, step, max)
				}
				previous = delay
				if failures == 0 && delay != 0 {
					t.Errorf("a source with no failures waits %v", delay)
				}
				if failures > 0 && step > 0 && max > 0 && delay == 0 {
					t.Errorf("a source with %d failures waits nothing (step %v, cap %v)", failures, step, max)
				}
				if !failureDelayGrowsWithFailures(0, failures, step, max) {
					t.Errorf("failureDelayGrowsWithFailures(0, %d, %v, %v) says the delay shrank", failures, step, max)
				}
			}
		}
	}
}

// TestConformanceThrottleDelayIsInTheUnitsItLooksLike is a units test, and units are the one thing
// the split could silently change: the rules take Durations, so a step of one second must produce
// three seconds after three failures and not three nanoseconds. The configured values are the ones
// worth naming, because they are the numbers in docs/server_config.md.
func TestConformanceThrottleDelayIsInTheUnitsItLooksLike(t *testing.T) {
	cases := []struct {
		failures int
		step     time.Duration
		limit    time.Duration
		want     time.Duration
	}{
		{0, passwordDelayStep, passwordMaxDelay, 0},
		{1, passwordDelayStep, passwordMaxDelay, passwordDelayStep},
		{2, passwordDelayStep, passwordMaxDelay, 2 * passwordDelayStep},
		// the cap, in the units the operator wrote it in
		{10, passwordDelayStep, passwordMaxDelay, passwordMaxDelay},
		{10, time.Second, 5 * time.Second, 5 * time.Second},
		{4, time.Second, 5 * time.Second, 4 * time.Second},
		// and a delay switched off is off, not nearly off
		{9, 0, passwordMaxDelay, 0},
	}
	for _, c := range cases {
		if got := failureDelay(c.failures, c.step, c.limit); got != c.want {
			t.Errorf("failureDelay(%d, %v, %v) = %v, want %v", c.failures, c.step, c.limit, got, c.want)
		}
	}
	// the default configuration, end to end: the first attempts must not wait longer than the
	// documented maximum, and the last ones exactly that long
	for failures := 1; failures < passwordMaxFailuresPerSource; failures++ {
		if got := failureDelay(failures, passwordDelayStep, passwordMaxDelay); got > passwordMaxDelay {
			t.Errorf("%d failures schedule a %v wait, longer than the configured maximum %v", failures, got, passwordMaxDelay)
		}
	}
}

// TestConformanceFailureDelayAtTheOverflowBoundary records what the cap cannot do. The proof reasons
// about integers; Go multiplies 64-bit ones, so past about nine billion failures in a window the
// product wraps instead of saturating. That count is unreachable in a five-minute window -- and the
// consequence is not a refusal bypass anyway: a wrapped delay is either small or negative, and
// beforeAttempt only sleeps on a positive one, while the count towards the lock-out is unaffected.
// What the test asserts is that the shipped rule and the expression it replaced still agree at that
// point, so that the wrap is the same wrap and not a new bug.
func TestConformanceFailureDelayAtTheOverflowBoundary(t *testing.T) {
	step := time.Hour // 3.6e12 ns: nine billion of them overflow a Duration
	maxes := []time.Duration{0, time.Nanosecond, time.Second, time.Hour}
	for _, failures := range []int{1 << 31, 1 << 40, 3_000_000_000} {
		for _, max := range maxes {
			got := failureDelay(failures, step, max)
			want := oldDelay(failures, step, max)
			if got != want {
				t.Errorf("at %d failures with a %v step: the rule says %v, the expression it replaced says %v",
					failures, step, got, want)
			}
		}
	}
	// and the delay that comes out of a wrapped multiplication is never slept on if it is
	// negative, which is the only way the wrap could have mattered
	if delay := failureDelay(3_000_000_000, step, time.Second); delay > time.Second {
		t.Errorf("a wrapped delay of %v exceeds the configured cap of 1s, which the proof does not cover and a caller must not assume", delay)
	}
}

// TestConformanceCheckAppliesTheRules drives the real check() -- table, clock, window reset,
// refusal and delay -- and holds it to the pre-split computation over a grid of windows, steps,
// caps, failure counts and clock positions. This is the correspondence for the whole of SR-AUTH-08's
// arithmetic half: the rules are proved in throttle_rules.go, and this is what says check() asks
// them the questions it proved.
func TestConformanceCheckAppliesTheRules(t *testing.T) {
	windows := []time.Duration{0, time.Second, time.Hour, 2 * time.Hour}
	steps := []time.Duration{0, 250 * time.Millisecond, time.Second, time.Minute}
	maxes := []time.Duration{0, time.Second, 5 * time.Second, time.Hour}
	offsets := []time.Duration{-3 * time.Hour, -2 * time.Hour, -time.Hour, -time.Nanosecond, 0, time.Nanosecond, time.Second, 30 * time.Minute}
	limit := 3
	start := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	for _, window := range windows {
		for _, step := range steps {
			for _, max := range maxes {
				for _, offset := range offsets {
					clock := &fakeClock{now: start}
					throttle := newLoginThrottle(window, 8, step, max)
					throttle.now = clock.Now
					for failures := 0; failures <= limit+2; failures++ {
						key := fmt.Sprintf("203.0.113.%d|%v|%v|%v", failures, window, step, max)
						windowStart := start.Add(offset)
						throttle.entries[key] = &throttleEntry{failures: failures, windowStart: windowStart}

						delay, err := throttle.check(key, limit)

						// what the pre-split code computes for the same state
						var wantDelay time.Duration
						var wantErr error
						var wantRetry time.Duration
						switch {
						case clock.now.Sub(windowStart) > window:
							// a fresh window: the entry is reopened empty, so nothing is refused
							wantDelay = oldDelay(0, step, max)
						case failures >= limit:
							wantRetry = oldRetryAfter(windowStart, window, clock.now)
							wantErr = loginLocked{RetryAfter: wantRetry}
						default:
							wantDelay = oldDelay(failures, step, max)
						}

						if (err != nil) != (wantErr != nil) {
							t.Errorf("check(%q) with %d failures, window %v opened %v: err=%v, want %v",
								key, failures, window, offset, err, wantErr)
							continue
						}
						if wantErr != nil {
							locked, ok := err.(loginLocked)
							if !ok {
								t.Errorf("check(%q) refused with %T, want loginLocked", key, err)
								continue
							}
							if locked.RetryAfter != wantRetry {
								t.Errorf("check(%q) reports %v left of the window, the four lines it used to run report %v", key, locked.RetryAfter, wantRetry)
							}
							if delay != 0 {
								t.Errorf("check(%q) both refused and scheduled a %v delay", key, delay)
							}
							continue
						}
						if delay != wantDelay {
							t.Errorf("check(%q) with %d failures, step %v, cap %v: delay %v, want %v",
								key, failures, step, max, delay, wantDelay)
						}
					}
				}
			}
		}
	}
}

// TestConformanceWindowExpiryIsTheComparison states the two consequences of the strict comparison
// the three call sites share, in the terms an operator would notice: a window that is exactly as old
// as it is long has not closed, and a clock that steps backwards does not hand anybody a fresh
// window. Both are reachable -- time.Now is the wall clock, not a monotonic one -- and both were
// true of the inline comparison the predicate replaced.
func TestConformanceWindowExpiryIsTheComparison(t *testing.T) {
	for _, window := range []time.Duration{0, time.Nanosecond, time.Second, time.Hour} {
		for _, delta := range []time.Duration{-time.Hour, -time.Nanosecond, 0, time.Nanosecond, time.Hour} {
			elapsed := window + delta
			got := windowElapsed(elapsed, window)
			if delta > 0 && !got {
				t.Errorf("elapsed %v past a %v window is not expired", elapsed, window)
			}
			if delta <= 0 && got {
				t.Errorf("elapsed %v (delta %v) of a %v window counts as expired", elapsed, delta, window)
			}
		}
	}
}

// TestConformanceRefusalBoundaryIsTheLimit pins the off-by-one that the sentence above check() got
// wrong for as long as the code lived there -- finding F7: with a limit of N, it is the attempt made
// after N recorded failures that is refused, so N failures are enough to refuse and N-1 are not.
// Checked on the rule and through the real check(), because the sentence and the operator's
// expectation both concern what the server does.
func TestConformanceRefusalBoundaryIsTheLimit(t *testing.T) {
	for limit := 0; limit <= 6; limit++ {
		for failures := 0; failures <= limit+2; failures++ {
			want := failures >= limit
			if got := attemptIsRefused(failures, limit); got != want {
				t.Errorf("attemptIsRefused(failures=%d, limit=%d) = %v, want %v", failures, limit, got, want)
			}
			clock := &fakeClock{now: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)}
			throttle := newLoginThrottle(time.Hour, 8, time.Second, time.Minute)
			throttle.now = clock.Now
			key := fmt.Sprintf("203.0.113.%d|%d", failures, limit)
			throttle.entries[key] = &throttleEntry{failures: failures, windowStart: clock.now}
			_, err := throttle.check(key, limit)
			if got := err != nil; got != want {
				t.Errorf("check() with %d failures and a limit of %d refused=%v, want %v", failures, limit, got, want)
			}
		}
	}
}

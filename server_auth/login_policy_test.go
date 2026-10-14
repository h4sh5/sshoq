package server_auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestTruncateUserAgent(t *testing.T) {
	// the header is untrusted and read before any authentication: slicing it with [:100]
	// used to panic for every shorter User-Agent, which is what F10 is about
	short := "sshoq/1.0"
	if got := truncate(short, 100); got != short {
		t.Fatalf("a short header must be logged as is, got %q", got)
	}
	if got := truncate("", 100); got != "" {
		t.Fatalf("an empty header must stay empty, got %q", got)
	}
	long := strings.Repeat("a", 500)
	if got := truncate(long, 100); len(got) != 103 { // 100 + "..."
		t.Fatalf("expected a truncation at 100 bytes, got %d bytes", len(got))
	}
	// cutting in the middle of a multi-byte character would put invalid UTF-8 in the log
	multi := strings.Repeat("é", 200) // 2 bytes each
	if !utf8.ValidString(truncate(multi, 99)) {
		t.Fatal("truncation cut a multi-byte character")
	}
	if !utf8.ValidString(truncate(strings.Repeat("日", 200), 100)) {
		t.Fatal("truncation cut a 3-byte character")
	}
}

// fakeClock lets a test move the failure window without sleeping.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestThrottle(clock *fakeClock) *loginThrottle {
	throttle := newLoginThrottle(passwordFailureWindow, passwordThrottleEntries, passwordDelayStep, passwordMaxDelay)
	throttle.now = clock.Now
	return throttle
}

func TestLoginThrottleRefusesRepeatedFailures(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	throttle := newTestThrottle(clock)
	key := "203.0.113.7|root"

	// the first attempts are simply delayed, the delay grows with the failures
	for i := 0; i < passwordMaxFailuresPerSource; i++ {
		delay, err := throttle.check(key, passwordMaxFailuresPerSource)
		if err != nil {
			t.Fatalf("attempt %d refused too early: %s", i, err)
		}
		expected := time.Duration(i) * passwordDelayStep
		if expected > passwordMaxDelay {
			expected = passwordMaxDelay
		}
		if delay != expected {
			t.Fatalf("attempt %d: expected a delay of %s, got %s", i, expected, delay)
		}
		throttle.failure(key)
	}

	_, err := throttle.check(key, passwordMaxFailuresPerSource)
	if err == nil {
		t.Fatal("the source should be refused after too many failures")
	}
	locked, ok := err.(loginLocked)
	if !ok || locked.RetryAfter <= 0 || locked.RetryAfter > passwordFailureWindow {
		t.Fatalf("expected the remaining time of the window, got %v", err)
	}

	// another source is not penalised
	if _, err := throttle.check("198.51.100.7|root", passwordMaxFailuresPerSource); err != nil {
		t.Fatalf("an unrelated source should not be refused: %s", err)
	}

	// once the window is over, the source may try again
	clock.Advance(passwordFailureWindow + time.Second)
	if _, err := throttle.check(key, passwordMaxFailuresPerSource); err != nil {
		t.Fatalf("the source should be allowed again once the window is over: %s", err)
	}
}

func TestLoginThrottleDelayIsCapped(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	throttle := newTestThrottle(clock)
	key := "203.0.113.7|someuser"
	// the threshold is above the number of failures recorded below: what is checked here
	// is that the waiting time stays bounded even for a source which is not (yet) locked
	// out, so that holding a request for a whole minute cannot become the norm
	const threshold = 100
	for i := 0; i < 50; i++ {
		delay, err := throttle.check(key, threshold)
		if err != nil {
			t.Fatal(err)
		}
		if delay > passwordMaxDelay {
			t.Fatalf("the delay grew to %s, above the cap of %s", delay, passwordMaxDelay)
		}
		throttle.failure(key)
	}
}

func TestLoginThrottleSuccessForgetsWithinWindow(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	throttle := newTestThrottle(clock)
	key := "203.0.113.7|root"
	for i := 0; i < passwordMaxFailuresPerSource; i++ {
		throttle.failure(key)
	}
	throttle.success(key)
	if _, err := throttle.check(key, passwordMaxFailuresPerSource); err != nil {
		t.Fatalf("a user who finally got the password right must not stay locked out: %s", err)
	}
}

func TestLoginThrottleIsBounded(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	throttle := newTestThrottle(clock)
	for i := 0; i < passwordThrottleEntries*3; i++ {
		throttle.failure(fmt.Sprintf("2001:db8::%d|user%d", i, i))
	}
	throttle.mutex.Lock()
	size := len(throttle.entries)
	throttle.mutex.Unlock()
	if size > passwordThrottleEntries {
		t.Fatalf("the throttle grew to %d entries, above its bound of %d: an attacker must not be able to use it "+
			"as a memory sink", size, passwordThrottleEntries)
	}
}

func TestThrottleKey(t *testing.T) {
	perUser, perAddress := throttleKey("203.0.113.7:54321", "root")
	if perAddress != "203.0.113.7" {
		t.Fatalf("the port must not be part of the source key, got %q", perAddress)
	}
	if perUser != "203.0.113.7|root" {
		t.Fatalf("unexpected per-user key %q", perUser)
	}
	// an IPv6 address:port pair
	_, perAddress2 := throttleKey("[2001:db8::1]:54321", "root")
	if perAddress2 != "2001:db8::1" {
		t.Fatalf("unexpected IPv6 source key %q", perAddress2)
	}
}

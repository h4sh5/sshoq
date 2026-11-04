package server_auth

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// maxLoggedUserAgentLength is how much of an untrusted User-Agent is written to the
// log. It used to be sliced with [:100] in an error message, which panicked on every
// shorter header; the truncation is now explicit and safe, and the header is never
// echoed back to the peer.
const maxLoggedUserAgentLength = 100

// truncate shortens s to at most max bytes, cutting on a rune boundary so that a
// header made of multi-byte characters cannot produce invalid UTF-8 in the log.
func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "..."
}

// loginThrottle is a small fixed-window failure counter used to slow down and
// eventually refuse repeated failed logins.
//
// The password path had no rate limit and no delay: an attacker could try as many
// passwords as the machine is able to hash, as fast as it can, over a single long-lived
// connection. Counting failures per source (and per source and username pair) makes the
// cost of guessing grow instead of staying flat, and closes the source for a while once
// it guessed too often. The state is deliberately in memory and bounded: it only has to
// make one running attack expensive, not to keep history.
type loginThrottle struct {
	mutex   sync.Mutex
	entries map[string]*throttleEntry
	// order is a ring of the keys the table holds, used to forget the oldest ones when it
	// is full: the memory an attacker can make this server spend must not depend on how
	// many sources they pretend to come from.
	order   []string
	ringPos int
	window  time.Duration
	// capacity bounds the number of remembered sources. Forgetting is what makes it
	// bounded, so a very wide spray can push entries out of the table; the growing delay
	// still applies to everything it remembers, which is why this is a mitigation and not
	// a wall.
	capacity  int
	delayStep time.Duration
	maxDelay  time.Duration
	now       func() time.Time
}

type throttleEntry struct {
	failures    int
	windowStart time.Time
}

func newLoginThrottle(window time.Duration, capacity int, delayStep time.Duration, maxDelay time.Duration) *loginThrottle {
	if capacity < 1 {
		capacity = 1
	}
	return &loginThrottle{
		entries:   make(map[string]*throttleEntry, capacity),
		order:     make([]string, capacity),
		ringPos:   0,
		window:    window,
		capacity:  capacity,
		delayStep: delayStep,
		maxDelay:  maxDelay,
		now:       time.Now,
	}
}

// loginLocked is returned by beforeAttempt when a source has failed too many times and
// must not be tried again until the current window is over.
type loginLocked struct {
	RetryAfter time.Duration
}

func (e loginLocked) Error() string {
	return fmt.Sprintf("too many failed login attempts, refusing new ones for another %s", e.RetryAfter.Round(time.Second))
}

// beforeAttempt waits for a delay growing with the number of failures already recorded
// for key, and returns an error once that key has failed maxFailures times since the
// beginning of the current window -- the count that refuses is the limit itself, not one
// past it, which is what attemptIsRefused states and its test pins.
func (t *loginThrottle) beforeAttempt(key string, maxFailures int) error {
	delay, err := t.check(key, maxFailures)
	if err != nil {
		return err
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	return nil
}

// check is the part of beforeAttempt which does not sleep, so that it can be tested.
func (t *loginThrottle) check(key string, maxFailures int) (time.Duration, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	now := t.now()
	entry, ok := t.entries[key]
	if !ok || windowElapsed(int(now.Sub(entry.windowStart).Nanoseconds()), int(t.window.Nanoseconds())) {
		// a new window starts: what happened before does not count anymore
		entry = t.startWindowLocked(key, now)
	}
	if attemptIsRefused(entry.failures, maxFailures) {
		// both instants come from the same clock reading, so the difference is a plain
		// nanosecond count and the only judgement left is the floor at zero
		left := int(entry.windowStart.Add(t.window).Sub(now).Nanoseconds())
		return 0, loginLocked{RetryAfter: time.Duration(retryAfter(left))}
	}
	delayNs := failureDelay(entry.failures, int(t.delayStep.Nanoseconds()), int(t.maxDelay.Nanoseconds()))
	return time.Duration(delayNs), nil
}

// failure records a failed login attempt for key.
func (t *loginThrottle) failure(key string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	now := t.now()
	entry, ok := t.entries[key]
	if !ok || windowElapsed(int(now.Sub(entry.windowStart).Nanoseconds()), int(t.window.Nanoseconds())) {
		entry = t.startWindowLocked(key, now)
	}
	entry.failures++
}

// success forgets the failures of key: an interactive user who finally got their
// password right must not stay penalised for what they typed before.
func (t *loginThrottle) success(key string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	delete(t.entries, key)
}

// startWindowLocked creates the entry of a new failure window for key, making room for it
// when the table is full: first by forgetting the sources whose window is closed (which
// costs nothing), then by evicting the oldest remembered source. It must be called with
// the lock held.
func (t *loginThrottle) startWindowLocked(key string, now time.Time) *throttleEntry {
	if entry, remembered := t.entries[key]; remembered {
		// reopening the window of a source which is already remembered cannot grow the
		// table, so it does not have to evict anything
		entry.failures = 0
		entry.windowStart = now
		return entry
	}
	if len(t.entries) >= t.capacity {
		for staleKey, entry := range t.entries {
			if windowElapsed(int(now.Sub(entry.windowStart).Nanoseconds()), int(t.window.Nanoseconds())) {
				delete(t.entries, staleKey)
			}
		}
	}
	if len(t.entries) >= t.capacity {
		// the key the ring points at is the longest remembered one and the least interesting
		// to keep - but the ring is a hint and not a mirror: a source which was forgiven by
		// success() left its name here, so walk on until a name the table really holds turns
		// up. Evicting on the first slot regardless used to forget nothing at all, and the
		// table grew over its capacity without limit.
		for attempts := 0; attempts < len(t.order); attempts++ {
			victim := t.order[t.ringPos]
			t.ringPos = (t.ringPos + 1) % t.capacity
			if victim == "" || victim == key {
				continue
			}
			if _, live := t.entries[victim]; !live {
				continue
			}
			delete(t.entries, victim)
			break
		}
	}
	if len(t.entries) >= t.capacity {
		// every slot of the ring had been rewritten with names which are gone: fall back to
		// the entry whose window opened first, which is the same choice in essence and the
		// one which keeps the bound whatever the ring looks like
		oldestKey, oldestWindow := "", now
		for other, entry := range t.entries {
			if oldestKey == "" || entry.windowStart.Before(oldestWindow) {
				oldestKey, oldestWindow = other, entry.windowStart
			}
		}
		if oldestKey != "" {
			delete(t.entries, oldestKey)
		}
	}
	entry := &throttleEntry{windowStart: now}
	t.entries[key] = entry
	t.order[t.ringPos] = key
	t.ringPos = (t.ringPos + 1) % t.capacity
	return entry
}

const (
	// passwordFailureWindow is how long failures are remembered on the password path.
	passwordFailureWindow = 5 * time.Minute
	// passwordMaxFailuresPerSource is how many failures one source is allowed to make on
	// one username inside the window before it is refused.
	passwordMaxFailuresPerSource = 6
	// passwordMaxFailuresPerAddress is the same, counted over every username, so that
	// guessing across a list of accounts is closed too.
	passwordMaxFailuresPerAddress = 30
	// passwordDelayStep and passwordMaxDelay shape the growing wait a failed attempt
	// costs: cheap the first times, expensive once it is clear that guessing is going on.
	passwordDelayStep = 1 * time.Second
	passwordMaxDelay  = 3 * time.Second
	// passwordThrottleEntries bounds how many sources are remembered.
	passwordThrottleEntries = 4096
)

// passwordLogins is the process-wide throttle of the password login path.
var passwordLogins = newLoginThrottle(passwordFailureWindow, passwordThrottleEntries, passwordDelayStep, passwordMaxDelay)

// throttleKey builds the keys a failure is counted under: one for the source and
// username pair, one for the source alone. http.Request.RemoteAddr is "ip:port".
func throttleKey(remoteAddr string, username string) (perUser string, perAddress string) {
	address := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		address = host
	}
	return address + "|" + username, address
}

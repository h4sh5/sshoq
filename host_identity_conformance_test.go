package ssh3

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	client_config "github.com/h4sh5/sshoq/client/config"
)

// Which name a server is trusted *under*.
//
// `cmd/sshoq.go` asks one question of the known_hosts store on every connection -- is this certificate
// known for this name -- and the name is `Config.CanonicalHostFormat()`, spelled
// `hostname + ":" + decimal port + urlPath`. It is the trust anchor's identity: it is what is written by
// `AppendKnownHost`, what `Knows` and `KnowsHash` are queried with, and what a person reads when they open
// the file by hand. Nothing in this repository said so before these tests, and the two rows that exist for
// known_hosts (SR-TR-01, SR-TR-02) are about the store's answers and its line grammar, not about the key.
//
// Three things are worth holding in place, and one is worth reporting:
//
//   * the key is used consistently -- the string the client looks up is the string it writes, so a pin
//     cannot be recorded under one name and consulted under another (the classic way host-key checking
//     fails open, and here it fails shut);
//   * the key survives the file: it is written as one whitespace-separated field and read back as one, and
//     a key with whitespace in it is *dropped as an invalid line* rather than trusted under half its name;
//   * the `host:port` and `path` halves cannot run into each other, because `NewConfig` insists the path
//     starts with `/` -- the format function itself does not check, which is why this is a test and not an
//     invariant;
//   * and the key is the *literal* hostname, byte for byte as it was typed: **F13**, reported in
//     `proof/SECURITY_REQUIREMENTS.md`.

func conformanceConfig(host string, port int, path string) *client_config.Config {
	cfg, err := client_config.NewConfig("user", host, port, path, nil, nil)
	if err != nil {
		panic(err)
	}
	return cfg
}

// TestConformanceCanonicalHostFormatIsExactlyTheNameSplitsIntoThePartsThatBuiltIt pins the shape of the
// identity string: the hostname verbatim at the front, a colon, the port in decimal, and the path verbatim
// at the end with a leading slash that `NewConfig` supplies if the caller forgot it. The port is the part
// with arithmetic in it, so it is checked at the boundaries a human would mistype -- 0, 1, 22, 80, 443,
// 65535 -- and the two spellings of a path are shown to arrive at the same name, which is what makes
// `https://example.org` and `https://example.org/` one host rather than two.
func TestConformanceCanonicalHostFormatIsExactlyTheNameSplitsIntoThePartsThatBuiltIt(t *testing.T) {
	cases := []struct {
		host string
		port int
		path string
		want string
		why  string
	}{
		{"example.org", 443, "/", "example.org:443/", "the ordinary case"},
		{"example.org", 443, "", "example.org:443/", "an empty path becomes /, so it is never a bare host:port"},
		{"example.org", 443, "ssh", "example.org:443/ssh", "a path without its slash gets one"},
		{"example.org", 443, "/ssh/others", "example.org:443/ssh/others", "a path with slashes is one name"},
		{"127.0.0.1", 22, "/", "127.0.0.1:22/", "an IPv4 literal is not bracketed"},
		{"::1", 443, "/", "::1:443/", "an IPv6 literal is not bracketed either -- it is the key, see F13"},
		{"[::1]", 443, "/", "[::1]:443/", "brackets typed by hand are part of the name"},
		{"localhost", 0, "/", "localhost:0/", "port zero is spelled 0"},
		{"localhost", 65535, "/", "localhost:65535/", "the last port"},
		{"host.example", 8080, "/a?b=c#d", "host.example:8080/a?b=c#d", "a query and fragment are part of the name"},
	}
	for _, c := range cases {
		got := conformanceConfig(c.host, c.port, c.path).CanonicalHostFormat()
		if got != c.want {
			t.Errorf("CanonicalHostFormat for host=%q port=%d path=%q = %q, want %q -- %s", c.host, c.port, c.path, got, c.want, c.why)
		}
		cfg := conformanceConfig(c.host, c.port, c.path)
		if !strings.HasPrefix(got, c.host) {
			t.Errorf("%q does not begin with the hostname %q", got, c.host)
		}
		if !strings.HasSuffix(got, cfg.UrlPath()) {
			t.Errorf("%q does not end with the path %q", got, cfg.UrlPath())
		}
		if strings.Contains(cfg.UrlPath(), " ") || !strings.HasPrefix(cfg.UrlPath(), "/") {
			t.Errorf("NewConfig left the path %q without a leading slash", cfg.UrlPath())
		}
	}

	// the two spellings of the same URL are one identity, and a different port or path is another
	if conformanceConfig("example.org", 443, "").CanonicalHostFormat() != conformanceConfig("example.org", 443, "/").CanonicalHostFormat() {
		t.Error("an omitted path and an explicit / are different identities, so a pin under one is a first contact under the other")
	}
	if conformanceConfig("example.org", 443, "/").CanonicalHostFormat() == conformanceConfig("example.org", 8443, "/").CanonicalHostFormat() {
		t.Error("two ports are the same identity")
	}
}

// TestConformanceKeyWrittenIsKeyLookedUp is the consistency property, run through the real store: a
// certificate appended under the name the client computes is found under that name, by both answers, and
// by no other name. A store where the write key and the read key differed would report every connection as
// unknown -- which the client answers by trusting, on first contact -- so this is the difference between
// pinning and theatre.
func TestConformanceKeyWrittenIsKeyLookedUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	hosts := []string{"example.org", "127.0.0.1", "::1", "[::1]", "sub.example.org", "Example.org", "example.org."}
	cert := makeTestCertificate(t)
	keys := make([]string, 0, len(hosts))
	for i, h := range hosts {
		cfg := conformanceConfig(h, 443+i, "/")
		key := cfg.CanonicalHostFormat()
		keys = append(keys, key)
		if err := AppendKnownHost(path, key, cert); err != nil {
			t.Fatalf("appending %q: %v", key, err)
		}
	}

	store, invalid, err := ParseKnownHosts(path)
	if err != nil {
		t.Fatalf("parsing the file the client just wrote: %v", err)
	}
	if len(invalid) != 0 {
		t.Fatalf("the client wrote lines the parser refuses: %v", invalid)
	}
	for i, key := range keys {
		if !store.Knows(key) {
			t.Errorf("%q was appended and is not known", key)
		}
		if !store.KnowsHash(key, HostHash(cert)) {
			t.Errorf("%q: the certificate appended under it is not found by hash", key)
		}
		// and the config that produced it asks with the same string, which is the point
		if asked := conformanceConfig(hosts[i], 443+i, "/").CanonicalHostFormat(); asked != key {
			t.Errorf("the config asks with %q but the pin was written under %q", asked, key)
		}
	}
	// a name nobody wrote is not known, including the near misses
	for _, other := range []string{"example.org:443", "example.org:443/ssh", "example.org:8443/", "", "x"} {
		if store.Knows(other) {
			t.Errorf("%q is known without having been written", other)
		}
	}
}

// TestConformanceKeySurvivesTheFileOrIsDropped covers the one way the identity string could be truncated
// without an error: whitespace. The line format is three whitespace-separated fields, so a name
// containing a space, tab or newline is written as more fields than the grammar allows and the whole line
// is reported invalid and skipped. Nothing is trusted under a prefix of the name -- the failure is a lost
// pin, not a wrong pin -- and these are the names a URL cannot produce but a hand-edited file can.
func TestConformanceKeySurvivesTheFileOrIsDropped(t *testing.T) {
	cert := makeTestCertificate(t)
	encoded := base64.StdEncoding.EncodeToString(cert.Raw)

	oneWord := []string{"example.org:443/", "a:1/", "::1:443/", "x.y:65535/a b/c"}
	withSpace := []string{"exa mple.org:443/", "a\tb:1/", "a b:443/"}

	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	var lines []string
	for _, k := range append(append([]string{}, oneWord...), withSpace...) {
		if k == "x.y:65535/a b/c" {
			continue // checked below as the path side of the same rule
		}
		lines = append(lines, fmt.Sprintf("%s x509-certificate %s", k, encoded))
	}
	for _, k := range withSpace {
		if !strings.Contains(k, " ") && !strings.Contains(k, "\t") {
			t.Fatalf("the test data is wrong: %q has no whitespace", k)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	store, invalid, err := ParseKnownHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range oneWord {
		if strings.ContainsAny(k, " \t\n") {
			continue
		}
		if !store.Knows(k) {
			t.Errorf("the single-field name %q did not survive the file", k)
		}
	}
	// the whitespace names: three of the lines written above had four or more fields, so each must appear
	// in `invalid` and none of them may be known under any prefix of its name
	if len(invalid) != len(withSpace) {
		t.Errorf("%d lines were refused, want %d (the names containing whitespace)", len(invalid), len(withSpace))
	}
	for _, k := range withSpace {
		if store.Knows(k) || store.Knows(strings.Fields(k)[0]) {
			t.Errorf("%q is known, so a name with whitespace was trusted under part of itself", k)
		}
	}

	// a path with a space has the same effect, and it is reachable from a URL-encoded path only if someone
	// decodes it before building the config -- which is why the rule is asserted, not assumed
	spaced := fmt.Sprintf("%s x509-certificate %s", "x.y:65535/a b/c", encoded)
	if err := os.WriteFile(path, []byte(spaced+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, invalid, err = ParseKnownHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(invalid) != 1 || store.Knows("x.y:65535/a b/c") || store.Knows("x.y:65535/a") {
		t.Errorf("a name with a space in its path was not simply dropped: invalid=%v", invalid)
	}
}

// TestConformanceHostAndPortCannotRunIntoThePath is the boundary claim, and the reason it is a test: the
// format is `host ":" port path` with nothing separating the port from the path, so `("h", 44, "30/")` and
// `("h", 443, "0/")` would be the same name -- two servers, one pin. They are not, because `NewConfig`
// prefixes the path with a slash, and that is the only thing keeping the two halves apart. The enumeration
// below crosses every host in a mixed alphabet with every pair of ports and paths that could run together,
// and requires distinct names for distinct (host, port, path) triples.
func TestConformanceHostAndPortCannotRunIntoThePath(t *testing.T) {
	hosts := []string{"h", "h.example", "127.0.0.1", "::1", "[::1]", "H"}
	ports := []int{1, 4, 44, 443, 4430, 65535}
	paths := []string{"/", "/0", "/30", "0/", "30/", "", "/a?b=c"}

	seen := map[string]string{}
	triples := map[string]bool{}
	for _, h := range hosts {
		for _, p := range ports {
			for _, pa := range paths {
				cfg := conformanceConfig(h, p, pa)
				key := cfg.CanonicalHostFormat()
				// the triple, as the client means it, with the path as NewConfig normalised it
				triple := fmt.Sprintf("%x|%d|%x", h, p, cfg.UrlPath())
				if other, ok := seen[key]; ok && other != triple {
					t.Errorf("%s and %s are both %q: two servers would share one pin", other, triple, key)
				}
				seen[key] = triple
				triples[triple] = true
			}
		}
	}
	// the honest count: the empty path and "/" are one triple because NewConfig normalises, so the number of
	// distinct identities must be the number of distinct triples -- no two meanings sharing a name
	if len(seen) != len(triples) {
		t.Errorf("%d configs with %d distinct meanings produced %d names", len(hosts)*len(ports)*len(paths), len(triples), len(seen))
	}
	t.Logf("%d distinct meanings, %d names, no collision", len(triples), len(seen))
}

// TestConformanceSpellingChangesThePin is **F13**, stated as measured behaviour rather than as a claim about
// what ought to be. DNS names are case-insensitive (RFC 4343), an IPv6 address has more than one valid
// spelling, and a trailing dot is the same host as none -- but the identity here is the literal bytes, so
// each spelling is a separate pin, and connecting under a spelling that was never written is a *first
// contact*, which the client answers by trusting and recording. A person who pins `example.org` and is
// later handed a link to `Example.org` therefore gets a second, independent trust-on-first-use. The test
// asserts the mechanism, so that if the key is ever normalised -- the decision this finding asks for -- the
// test is where the change is written down.
func TestConformanceSpellingChangesThePin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	cert := makeTestCertificate(t)

	pinned := conformanceConfig("example.org", 443, "/").CanonicalHostFormat()
	if err := AppendKnownHost(path, pinned, cert); err != nil {
		t.Fatal(err)
	}
	store, _, err := ParseKnownHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	if !store.KnowsHash(pinned, HostHash(cert)) {
		t.Fatal("the pinned spelling does not know its certificate")
	}

	// the same host, spelled otherwise: unknown, and therefore trusted again on first contact
	for _, other := range []string{"Example.org", "EXAMPLE.ORG", "example.org.", "example.org:443/"} {
		cfg := conformanceConfig(other, 443, "/")
		key := cfg.CanonicalHostFormat()
		if other == "example.org:443/" {
			continue // not a spelling of a hostname, it is what a hand-written bracket-less line looks like
		}
		if store.Knows(key) {
			t.Errorf("%q is known under the pin for %q, so the key normalises spellings and this test needs rewriting", other, pinned)
		}
	}

	// and the dial string is a third spelling: URLHostnamePort brackets IPv6 because a URL needs it, while
	// the identity does not bracket it because nothing asked. Both are used, so the name in the known_hosts
	// file for an IPv6 server is not the name in the URL that reached it.
	v6 := conformanceConfig("::1", 443, "/")
	if v6.URLHostnamePort() != "[::1]:443" {
		t.Errorf("the dial string for ::1 is %q, want the bracketed form a URL requires", v6.URLHostnamePort())
	}
	if v6.CanonicalHostFormat() != "::1:443/" {
		t.Errorf("the identity for ::1 is %q", v6.CanonicalHostFormat())
	}
	if v6.CanonicalHostFormat() == v6.URLHostnamePort() {
		t.Error("the identity and the dial string are the same string, so one of them has changed shape")
	}
	// a person writing the file by hand in URL form does not match what the client writes
	handwritten := fmt.Sprintf("[::1]:443/ x509-certificate %s\n", base64.StdEncoding.EncodeToString(cert.Raw))
	if err := os.WriteFile(path, []byte(handwritten), 0o600); err != nil {
		t.Fatal(err)
	}
	byHand, invalid, err := ParseKnownHosts(path)
	if err != nil || len(invalid) != 0 {
		t.Fatalf("parsing the hand-written line: %v %v", err, invalid)
	}
	if byHand.KnowsHash(v6.CanonicalHostFormat(), HostHash(cert)) {
		t.Error("the bracketed hand-written identity matched the bracket-less one")
	}
	if !byHand.Knows("[::1]:443/") {
		t.Error("the hand-written identity was not stored under itself")
	}
}

// TestConformanceCanonicalHostFormatDoesNotDependOnUnusedConfig fields, so that the identity of a server is
// not quietly a function of the username, the options or the environment a user happens to carry: two
// clients logging in as different users to the same server ask about the same name, and one of them cannot
// inherit the other's pin by accident.
func TestConformanceCanonicalHostFormatDoesNotDependOnUnusedConfigFields(t *testing.T) {
	basics := conformanceConfig("example.org", 443, "/")
	for _, user := range []string{"", "root", "a user"} {
		cfg, err := client_config.NewConfig(user, "example.org", 443, "/", nil, nil, []string{"A=1", "B=2"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.CanonicalHostFormat() != basics.CanonicalHostFormat() {
			t.Errorf("username %q changed the identity to %q", user, cfg.CanonicalHostFormat())
		}
		if cfg.Username() != user {
			t.Errorf("username %q came back as %q", user, cfg.Username())
		}
	}
}

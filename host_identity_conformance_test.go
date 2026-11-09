package ssh3

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// splitCanonicalKey recovers the three parts of an identity string. The rule is "the last colon before the
// first slash separates host from port": a path always begins with a slash, so it is the boundary, and the
// port in between is digits. Whether the recovery is *unique* is the question
// TestConformanceCanonicalHostFormatIsInjectiveOnRealisticHosts asks; this is the function that states it.
func splitCanonicalKey(t *testing.T, key string) (host string, port int, path string) {
	t.Helper()
	slash := strings.IndexByte(key, '/')
	if slash < 0 {
		t.Fatalf("identity %q has no path: the empty path is supposed to become /", key)
	}
	colon := strings.LastIndexByte(key[:slash], ':')
	if colon < 0 {
		t.Fatalf("identity %q has no port separator before its path", key)
	}
	n, err := strconv.Atoi(key[colon+1 : slash])
	if err != nil {
		t.Fatalf("identity %q: %q is not a port: %v", key, key[colon+1:slash], err)
	}
	return key[:colon], n, key[slash:]
}

// TestConformanceCanonicalHostFormatIsInjectiveOnRealisticHosts is the claim that a trust anchor belongs to
// one server: among names, IPv4 and IPv6 literals -- with and without the brackets a person might type --
// over the ports with arithmetic in them and paths with and without their leading slash, queries, fragments
// and a colon, no two configurations share an identity string unless they agree on host and port and on the
// path after normalisation. In other words: pinning one of these cannot pin another, and a certificate
// recorded for one cannot be found when asking about another.
//
// The pathological case is the *next* test, not this one: what makes this domain safe is that the host
// contains neither a colon nor a slash, so the separator between host and port is the only colon before the
// path. That is a property of hostnames, not of the formatting function, and it is why the row stays
// `conformant` rather than `proved:shipped` -- see the note on library postconditions in proof/README.md.
func TestConformanceCanonicalHostFormatIsInjectiveOnRealisticHosts(t *testing.T) {
	hosts := []string{
		"example.org", "sub.example.org", "localhost", "127.0.0.1", "10.0.0.1",
		"::1", "[::1]", "2001:db8::1", "[2001:db8::1]", "0", "a.example",
	}
	ports := []int{0, 1, 22, 80, 443, 8443, 65535}
	paths := []string{"", "/", "ssh", "/ssh", ":1", "/:1", "/ssh/others", "/a?b=c#d", "8443/", "/8443/"}

	byKey := map[string]string{}
	for _, host := range hosts {
		for _, port := range ports {
			for _, path := range paths {
				cfg := conformanceConfig(host, port, path)
				key := cfg.CanonicalHostFormat()
				// the parts must survive a round trip through the identity string
				gotHost, gotPort, gotPath := splitCanonicalKey(t, key)
				if gotHost != host || gotPort != port {
					t.Errorf("%q: splits into host=%q port=%d, want host=%q port=%d", key, gotHost, gotPort, host, port)
				}
				if want := normalisedPath(path); gotPath != want {
					t.Errorf("%q: path part %q, want the normalised path %q", key, gotPath, want)
				}
				where := fmt.Sprintf("host=%q port=%d path=%q", host, port, normalisedPath(path))
				if other, seen := byKey[key]; seen && other != where {
					t.Errorf("identity %q is claimed by %s and by %s", key, other, where)
				}
				byKey[key] = where
			}
		}
	}
	// every host, port and *normalised* path is its own identity, and nothing else is: the paths in the
	// list above spell six distinct ones, so that is how many keys the sweep must produce.
	normalised := map[string]bool{}
	for _, path := range paths {
		normalised[normalisedPath(path)] = true
	}
	if want := len(hosts) * len(ports) * len(normalised); len(byKey) != want {
		t.Errorf("%d distinct identities from %d hosts, %d ports and %d paths, want %d",
			len(byKey), len(hosts), len(ports), len(normalised), want)
	}
}

// TestConformanceCanonicalHostFormatIsNotInjectiveOnHostsThatAreNotHosts characterises the other half: when
// the "hostname" carries a slash or a colon of its own -- what a mistyped URL leaves behind -- the separator
// the identity string relies on stops being unique, and two different servers can be trusted under one name.
// This is not a bug report so much as a fence: it is the reason the guard belongs where the hostname is
// taken in, and if someone puts that guard in, this test will fail and send them to the paragraph it
// describes.
func TestConformanceCanonicalHostFormatIsNotInjectiveOnHostsThatAreNotHosts(t *testing.T) {
	a := conformanceConfig("example.org:443/", 1, "/")
	b := conformanceConfig("example.org", 80, "/:443/1")
	if a.CanonicalHostFormat() != "example.org:443/:1/" {
		t.Fatalf("identity of the mistyped host is %q", a.CanonicalHostFormat())
	}
	if b.CanonicalHostFormat() != "example.org:80/:443/1" {
		t.Fatalf("identity of the path-with-colon host is %q", b.CanonicalHostFormat())
	}
	collision := [][3]interface{}{
		{"example.org:443/", 1, "/"},
		{"example.org", 443, "/:1/"},
	}
	keys := map[string]bool{}
	for _, c := range collision {
		key := conformanceConfig(c[0].(string), c[1].(int), c[2].(string)).CanonicalHostFormat()
		if keys[key] {
			continue
		}
		keys[key] = true
	}
	if len(keys) != 1 {
		t.Fatalf("expected the two configurations to share the identity %v, got %v", keys, collision)
	}
}

// normalisedPath is what `NewConfig` makes of the path argument: the empty path becomes "/", and a path
// written without its leading slash gets one. The identity string is built from the result, so this is the
// function the tests above compare against -- and the reason "" and "/" and "ssh" and "/ssh" are two
// spellings of at most two identities rather than four.
func normalisedPath(path string) string {
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}

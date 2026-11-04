package ssh3

// Conformance tests for proof/knownhosts/model.gobra (SR-TR-01): the known_hosts store and the
// trust decision built on it.
//
// The model describes the store by the two answers the client reads about one (host,
// certificate) pair -- does this host have a line, does one of its lines carry this hash -- and
// proves that an empty store answers no to both, that appending only ever adds, that a line the
// grammar refuses changes nothing, and that the trust decision accepts exactly when a pin
// matched or a human said yes at a terminal about a host with no entry.
//
// What the model cannot check is that the real store really behaves like those two answers.
// These tests are that check: they parse real files with real self-signed certificates through
// the real ParseKnownHosts, Knows, KnowsHash and AppendKnownHost. The trust decision itself
// lives inside the TLS callbacks in cmd/sshoq.go and is exercised there by
// cmd/sshoq_pinning_e2e_test.go; what is checked here is the store it queries. Run with
// `go test . -run TestConformance`.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The empty store, which is what a client with no known_hosts file gets: neither answer may be
// yes, or the first certificate seen would be trusted. Conforms to the model's
// emptyStoreTrustsNobody, including the nil map the model represents by "no lines".
func TestConformanceEmptyKnownHostsTrustsNobody(t *testing.T) {
	var nilStore KnownHosts
	empty := KnownHosts{}
	for name, store := range map[string]KnownHosts{"nil": nilStore, "empty": empty} {
		if store.Knows("host.example") {
			t.Errorf("%s store: Knows = true", name)
		}
		if store.KnowsHash("host.example", "anything") {
			t.Errorf("%s store: KnowsHash = true", name)
		}
	}
}

// Conforms to the model's knownHashMeansKnownHost and entryMeansKnown: the two answers may only
// be yes when the file really has lines, and a host with an entry is known.
func TestConformanceKnowsMatchesTheStore(t *testing.T) {
	cert := makeTestCertificate(t)
	hash := HostHash(cert)
	host := "host.example"
	store := KnownHosts{host: {cert}}
	if !store.Knows(host) {
		t.Fatalf("Knows(%q) = false with an entry on file", host)
	}
	if !store.KnowsHash(host, hash) {
		t.Fatalf("KnowsHash(%q, %q) = false with that certificate on file", host, hash)
	}
	// the entry for one host says nothing about another: data independence, the reason the
	// model's facts are per (host, certificate) pair
	other := KnownHosts{"elsewhere": {cert}}
	if other.Knows(host) || other.KnowsHash(host, hash) {
		t.Error("an entry for another host was reported for this one")
	}
	// a hash that is on file for another host is not a hash for this one
	if !other.KnowsHash("elsewhere", HostHash(cert)) {
		t.Error("KnowsHash missed a pair that is on file")
	}
	if other.KnowsHash("elsewhere", "SHA256 not-it") {
		t.Error("KnowsHash matched the wrong hash")
	}
}

// Conforms to the model's lineAccepted grammar and rejectedLineChangesNothing: a line is
// recorded exactly when it has three whitespace-separated fields, the second one the type tag,
// and a third field that is base64 for a certificate that parses. Everything else is reported by
// line number and contributes no entry -- so a known_hosts file full of rubbish can neither add
// trust nor make the client forget the lines that did parse.
func TestConformanceParseKnownHostsGrammar(t *testing.T) {
	cert := makeTestCertificate(t)
	encoded := base64.StdEncoding.EncodeToString(cert.Raw)
	other := makeTestCertificate(t)
	otherEncoded := base64.StdEncoding.EncodeToString(other.Raw)

	lines := []struct {
		text    string
		records bool
	}{
		{"good.example x509-certificate " + encoded, true},
		{"shortline x509-certificate", false},                           // two fields
		{"extra.example x509-certificate " + encoded + " extra", false}, // four fields
		{"wrongtag.example ssh-rsa " + encoded, false},                  // second field is not the tag
		{"notb64.example x509-certificate !!!not base64!!!", false},
		{"notcert.example x509-certificate " + base64.StdEncoding.EncodeToString([]byte("hello")), false},
		{"", false},
		{"   ", false},
		{"second.example x509-certificate " + otherEncoded, true},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	var sb strings.Builder
	invalidWant := []int{}
	for i, l := range lines {
		sb.WriteString(l.text)
		sb.WriteString("\n")
		if !l.records {
			invalidWant = append(invalidWant, i)
		}
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0600); err != nil {
		t.Fatal(err)
	}

	store, invalid, err := ParseKnownHosts(path)
	if err != nil {
		t.Fatalf("ParseKnownHosts: %v", err)
	}
	if len(invalid) != len(invalidWant) {
		t.Fatalf("invalid lines = %v, want %v", invalid, invalidWant)
	}
	for i, got := range invalid {
		if got != invalidWant[i] {
			t.Fatalf("invalid lines = %v, want %v", invalid, invalidWant)
		}
	}
	// the two good lines are known, with their own certificates
	if !store.Knows("good.example") || !store.KnowsHash("good.example", HostHash(cert)) {
		t.Errorf("the first good line is not on file")
	}
	if !store.Knows("second.example") || !store.KnowsHash("second.example", HostHash(other)) {
		t.Errorf("the second good line is not on file")
	}
	// and no refused line left an entry behind: not for its host name, and not by borrowing a
	// certificate from a line that did parse
	for _, host := range []string{"shortline", "extra.example", "wrongtag.example", "notb64.example", "notcert.example"} {
		if store.Knows(host) {
			t.Errorf("refused line left an entry for %q", host)
		}
	}
	if len(store) != 2 {
		t.Errorf("store holds %d hosts, want 2 (the two lines the grammar accepted)", len(store))
	}
}

// A missing file is not an error and not a trust decision: the client gets an empty store, which
// is emptyStoreTrustsNobody in the model.
func TestConformanceMissingKnownHostsFileIsEmpty(t *testing.T) {
	store, invalid, err := ParseKnownHosts(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("ParseKnownHosts on a missing file: %v", err)
	}
	if len(invalid) != 0 {
		t.Errorf("invalid lines = %v, want none", invalid)
	}
	if len(store) != 0 || store.Knows("anything") || store.KnowsHash("anything", "SHA256 x") {
		t.Errorf("a missing file produced a non-empty store: %v", store)
	}
}

// Conforms to the model's recordingMakesThePairKnown and recordingIsMonotone, through the real
// AppendKnownHost + ParseKnownHosts round trip: after a certificate is written the pair is known,
// and everything known before is still known. This is the append-only property in the code -- a
// host that changes certificate ends up with both lines on file, so the verifier still has the
// old one to fail against instead of silently following the newest entry.
func TestConformanceAppendKeepsWhatWasKnown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	old := makeTestCertificate(t)
	fresh := makeTestCertificate(t)
	host := "rotating.example"

	if err := AppendKnownHost(path, host, old); err != nil {
		t.Fatal(err)
	}
	store, _, err := ParseKnownHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	if !store.KnowsHash(host, HostHash(old)) {
		t.Fatal("the appended certificate is not on file")
	}
	if store.KnowsHash(host, HostHash(fresh)) {
		t.Fatal("a certificate never written is known")
	}

	// the server changes certificate; the client records the new one
	if err := AppendKnownHost(path, host, fresh); err != nil {
		t.Fatal(err)
	}
	after, invalid, err := ParseKnownHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(invalid) != 0 {
		t.Fatalf("appended lines did not parse: %v", invalid)
	}
	if len(after[host]) != 2 {
		t.Fatalf("host holds %d certificates, want 2 (append must not replace)", len(after[host]))
	}
	if !after.KnowsHash(host, HostHash(old)) {
		t.Error("the old certificate was forgotten: the store replaced instead of appending")
	}
	if !after.KnowsHash(host, HostHash(fresh)) {
		t.Error("the new certificate is not known")
	}
	// the file itself is the record: two lines, both for this host
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Split(strings.TrimRight(string(data), "\n"), "\n")); got != 2 {
		t.Errorf("known_hosts has %d lines, want 2", got)
	}
}

package ssh3

import (
	"crypto/rand"
	"crypto/x509"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/h4sh5/sshoq/util"
)

// makeTestCertificate builds a self-signed certificate the way the server does,
// so that a host hash computed from it is one a client and a server agree on.
func makeTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	pub, priv, err := util.GenerateKey()
	if err != nil {
		t.Fatalf("could not generate a key: %s", err)
	}
	template, err := util.GenerateCert(priv)
	if err != nil {
		t.Fatalf("could not make a certificate: %s", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("could not create the certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse the certificate: %s", err)
	}
	return cert
}

// The host hash is what the server announces and what the client checks: it is
// the fingerprint of the certificate itself, base64-encoded, so both sides of
// the copy and paste get the same string.
func TestHostHashIsTheCertificateFingerprint(t *testing.T) {
	cert := makeTestCertificate(t)
	hash := HostHash(cert)
	if hash != util.Sha256Fingerprint(cert.Raw) {
		t.Fatalf("expected the SHA-256 fingerprint of the certificate, got %q", hash)
	}
	if len(hash) != 44 {
		t.Fatalf("a base64 SHA-256 is 44 characters, got %q", hash)
	}
	// another certificate is another host: no two certificates may share a hash
	if other := HostHash(makeTestCertificate(t)); other == hash {
		t.Fatalf("two different certificates gave the same host hash: %q", hash)
	}
}

// KnowsHash tells which certificate a host is known by, not merely whether the
// host has an entry: a pinned hash already on file must not be written twice,
// while a stale entry must not keep the pinned certificate out of the file.
func TestKnownHostsKnowsHash(t *testing.T) {
	cert := makeTestCertificate(t)
	other := makeTestCertificate(t)
	dir := t.TempDir()
	filename := path.Join(dir, "known_hosts")
	if err := AppendKnownHost(filename, "server.example.org:443", cert); err != nil {
		t.Fatalf("could not write known_hosts: %s", err)
	}
	knownHosts, invalidLines, err := ParseKnownHosts(filename)
	if err != nil || len(invalidLines) != 0 {
		t.Fatalf("could not read back known_hosts: %v (invalid lines %v)", err, invalidLines)
	}
	if !knownHosts.KnowsHash("server.example.org:443", HostHash(cert)) {
		t.Fatal("the certificate which was written should be known by its hash")
	}
	if knownHosts.KnowsHash("server.example.org:443", HostHash(other)) {
		t.Fatal("another certificate is not known for that host")
	}
	if knownHosts.KnowsHash("elsewhere.example.org:443", HostHash(cert)) {
		t.Fatal("a certificate is not known for a host it was not written for")
	}
	if (KnownHosts{}).KnowsHash("server.example.org:443", HostHash(cert)) {
		t.Fatal("an empty known_hosts knows nobody")
	}
	if len(knownHosts["server.example.org:443"]) != 1 {
		t.Fatalf("expected a single entry, got %d", len(knownHosts["server.example.org:443"]))
	}
	// the file must stay what ParseKnownHosts reads: one host, one type, one base64
	// certificate, on one line
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("could not read known_hosts: %s", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "server.example.org:443 x509-certificate ") {
		t.Fatalf("unexpected known_hosts content: %q", string(content))
	}
	// and it stays readable by its owner only, a known host being a secret on a shared box
	if info, err := os.Stat(filename); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("known_hosts should be 0600, got %v (%v)", info.Mode(), err)
	}
}

package ssh3

import (
	"bufio"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/h4sh5/sshoq/util"
)

type KnownHosts map[string][]*x509.Certificate

func (kh KnownHosts) Knows(hostname string) bool {
	if len(kh) == 0 {
		return false
	}
	_, ok := kh[hostname]
	return ok
}

// KnowsHash reports whether known_hosts holds, for a host, a certificate with the
// given host hash. It differs from Knows in that it asks *which* certificate is
// known, not merely whether the host has an entry: a pinned host hash which is
// already on file must not be appended again, while a host whose entry holds
// another certificate still has to get the pinned one written next to it.
func (kh KnownHosts) KnowsHash(hostname string, hash string) bool {
	for _, cert := range kh[hostname] {
		if HostHash(cert) == hash {
			return true
		}
	}
	return false
}

type InvalidKnownHost struct {
	line string
}

func (e InvalidKnownHost) Error() string {
	return fmt.Sprintf("invalid known host line: %s", e.line)
}

// HostHash returns the "host hash" of a server certificate: the base64-encoded
// SHA-256 of the certificate itself. It identifies the certificate the way an
// OpenSSH host key fingerprint identifies a host key, is short enough to read on
// a screen and to copy by eye, and is the string the client shows when it asks
// about an unknown certificate, the one it pins with -host-hash / HostHash, and
// the one the server prints when it starts.
func HostHash(cert *x509.Certificate) string {
	return util.Sha256Fingerprint(cert.Raw)
}

func ParseKnownHosts(filename string) (knownHosts KnownHosts, invalidLines []int, err error) {
	knownHosts = make(map[string][]*x509.Certificate)
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		// the known hosts file simply does not exist yet, so there is no known host
		return knownHosts, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	scanner := bufio.NewScanner(file)

	for i := 0; scanner.Scan(); i++ {
		knownHost := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(knownHost)
		if len(fields) != 3 || fields[1] != "x509-certificate" {
			invalidLines = append(invalidLines, i)
			continue
		}
		certBytes, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			invalidLines = append(invalidLines, i)
			continue
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			invalidLines = append(invalidLines, i)
			continue
		}
		certs := knownHosts[fields[0]]
		certs = append(certs, cert)
		knownHosts[fields[0]] = certs
	}
	return knownHosts, invalidLines, nil
}

func AppendKnownHost(filename string, host string, cert *x509.Certificate) error {
	encodedCert := base64.StdEncoding.EncodeToString(cert.Raw)
	// a file created here is 0600, and one which already exists and was readable by others
	// gets tightened: the mode given to OpenFile only applies when it is created, so a
	// known_hosts written by an older version - or by hand - stayed world-readable
	knownHosts, err := util.OpenSecretAppendFile(filename)
	if err != nil {
		return err
	}
	_, err = knownHosts.WriteString(fmt.Sprintf("%s x509-certificate %s\n", host, encodedCert))
	if err != nil {
		return err
	}

	return nil
}

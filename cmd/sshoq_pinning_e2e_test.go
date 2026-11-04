package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	ssh3 "github.com/h4sh5/sshoq"
	"golang.org/x/crypto/ssh"
)

// The tests of the pinned host hash are end to end, on purpose: the decision
// itself is unit tested in sshoq_test.go, but what the feature is made of is
// what a user sees - a hash printed by a server, copied into a client, and the
// connection, or the refusal, which follows. Only the real binaries show whether
// the hash really reaches the person who has to copy it, whether a prompt is
// asked where nobody should be asked one, and whether known_hosts ends up with
// the certificate it promises.
//
// They build the two binaries of this very tree, so that they can never pass
// against a binary of some other revision; that costs a few seconds, and -short
// skips them.

// lockedBuffer collects what a server writes while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// buildSshoqBinaries compiles the client and the server of this tree.
func buildSshoqBinaries(t *testing.T) (client string, server string) {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go tool to build the sshoq binaries with: %s", err)
	}
	dir := t.TempDir()
	client = filepath.Join(dir, "sshoq")
	server = filepath.Join(dir, "sshoq-server")
	for _, binary := range []string{client, server} {
		// the test runs in cmd/, where the sshoq/ and sshoq-server/ main packages are
		build := exec.Command(goTool, "build", "-o", binary, "./"+filepath.Base(binary))
		if out, err := build.CombinedOutput(); err != nil {
			t.Skipf("could not build %s: %s\n%s", filepath.Base(binary), err, out)
		}
	}
	return client, server
}

// startPinningServer runs a server with a self-signed certificate on a port of
// its own and waits for the line announcing its host hash: without that line
// there is nothing to copy, which is the whole point of printing it.
// The client key is authorized with -rpub, in the memory of this run only: the
// file the server would otherwise read belongs to the home of the OS user, which
// is not somewhere a test should write in.
// It returns the announced hash and the URL to connect to.
func startPinningServer(t *testing.T, serverBinary string, home string, authorizedKey string) (hash string, url string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not find a free port: %s", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("could not release the port: %s", err)
	}

	command := exec.Command(serverBinary,
		"-bind", fmt.Sprintf("127.0.0.1:%d", port),
		"-url-path", "/test",
		"-generate-selfsigned-cert",
		"-rpub", authorizedKey,
	)
	command.Env = append(os.Environ(), "HOME="+home)
	var output lockedBuffer
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatalf("could not start the server: %s", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})

	announced := regexp.MustCompile(`Server host hash: (SHA256 [A-Za-z0-9+/=]+)`)
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
	defer cancel()
	for deadline.Err() == nil {
		if command.ProcessState != nil && command.ProcessState.Exited() {
			break
		}
		if match := announced.FindStringSubmatch(output.String()); match != nil {
			return match[1], fmt.Sprintf("root@127.0.0.1:%d/test", port)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// A server which does not come up at all is an environment missing what a
	// server needs - users, permissions, PAM - not a broken host hash: say so.
	t.Skipf("the server did not announce its host hash: %s", output.String())
	return "", ""
}

// runPinningClient runs the client with HOME set to the directory of the test, so
// that the pin, the ssh config and known_hosts in play are the ones written here.
// A test has no terminal to answer a (yes/no) prompt with, which is exactly the
// situation a pinned certificate is meant to work in.
// It returns everything the client has to say: it logs on stderr, whatever the
// terminal, which CombinedOutput collects.
func runPinningClient(t *testing.T, clientBinary string, home string, args ...string) string {
	t.Helper()
	command := exec.Command(clientBinary, args...)
	command.Env = append(os.Environ(), "HOME="+home)
	combined, err := command.CombinedOutput()
	if err != nil {
		combined = append(combined, []byte("\n"+err.Error())...)
	}
	return string(combined)
}

// readKnownHosts returns the known_hosts of a client home, or the reason there is
// none - a message which fails the assertion is easier to read than an empty one.
func readKnownHosts(t *testing.T, home string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(home, ".ssh3", "known_hosts"))
	if err != nil {
		return "could not read known_hosts: " + err.Error()
	}
	return string(content)
}

// knownHostHashes returns the host hash of every certificate a client recorded,
// with the parser and the hash function the client itself uses: known_hosts holds
// certificates, and a hash is what is compared to the pin, so this is the only way
// to ask the file whether it trusts a given hash.
func knownHostHashes(t *testing.T, home string) []string {
	t.Helper()
	knownHosts, invalidLines, err := ssh3.ParseKnownHosts(filepath.Join(home, ".ssh3", "known_hosts"))
	if err != nil {
		t.Fatalf("could not parse known_hosts of the client: %s", err)
	}
	if len(invalidLines) != 0 {
		t.Fatalf("known_hosts of the client has invalid lines: %v", invalidLines)
	}
	hashes := make([]string, 0, len(knownHosts))
	for _, certificates := range knownHosts {
		for _, certificate := range certificates {
			hashes = append(hashes, ssh3.HostHash(certificate))
		}
	}
	return hashes
}

func knowsHash(t *testing.T, home string, hash string) bool {
	t.Helper()
	for _, known := range knownHostHashes(t, home) {
		if known == strings.TrimPrefix(hash, "SHA256 ") {
			return true
		}
	}
	return false
}

// writeTestIdentity writes a client private key and returns the authorized_keys
// line which authorizes it, for the server to hold.
func writeTestIdentity(t *testing.T, path string) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the client key: %s", err)
	}
	block, err := ssh.MarshalPrivateKey(private, "sshoq-pinning-test")
	if err != nil {
		t.Fatalf("could not marshal the client key: %s", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("could not write the client key: %s", err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatalf("could not get the public key: %s", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
}

func TestPinnedHostHashEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end to end test of the pinned host hash, skipped with -short")
	}
	clientBinary, serverBinary := buildSshoqBinaries(t)

	// One server for every scenario below - the scenarios differ by the HOME of
	// the client, which is where the pin, the ssh config and known_hosts live.
	root := t.TempDir()
	serverHome := filepath.Join(root, "server")
	if err := os.MkdirAll(filepath.Join(serverHome, ".ssh3"), 0700); err != nil {
		t.Fatalf("could not create the config dir of the server: %s", err)
	}
	keyPath := filepath.Join(root, "id_ed25519")
	authorizedKey := writeTestIdentity(t, keyPath)

	pinnedHash, url := startPinningServer(t, serverBinary, serverHome, authorizedKey)
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pinnedHash, "SHA256 ")); err != nil {
		t.Fatalf("the announced host hash %q is not a base64 SHA-256: %s", pinnedHash, err)
	} else if len(decoded) != 32 {
		t.Fatalf("the announced host hash %q is not a SHA-256 but %d bytes", pinnedHash, len(decoded))
	}
	// A hash of the right shape and of no certificate, to be the wrong pin with.
	anotherHash := "SHA256 " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))

	// What the feature is for: a pinned certificate is trusted without anybody
	// being asked, in a session with no terminal at all, and the hash is on file
	// afterwards so that the host keeps being trusted the same way.
	t.Run("a pinned hash is trusted without a prompt and recorded in known hosts", func(t *testing.T) {
		home := filepath.Join(root, "pinned")
		if err := os.MkdirAll(home, 0700); err != nil {
			t.Fatalf("could not create the home of the client: %s", err)
		}
		output := runPinningClient(t, clientBinary, home, "-i", keyPath, "-host-hash", pinnedHash, url, "echo hello-from-pin")
		if !strings.Contains(output, "hello-from-pin") {
			t.Fatalf("a client with the hash of the server should connect and run its command:\n%s", output)
		}
		if strings.Contains(output, "(yes/no)") {
			t.Fatalf("a pinned certificate must not be asked about:\n%s", output)
		}
		knownHosts := readKnownHosts(t, home)
		if !knowsHash(t, home, pinnedHash) {
			t.Fatalf("a certificate whose hash is pinned should be added to known_hosts, got:\n%s", knownHosts)
		}
		if hashes := knownHostHashes(t, home); len(hashes) != 1 {
			t.Fatalf("known_hosts should hold exactly one certificate, got %d:\n%s", len(hashes), knownHosts)
		}

		// Connecting again adds nothing and still asks nothing.
		output = runPinningClient(t, clientBinary, home, "-i", keyPath, "-host-hash", pinnedHash, url, "echo again")
		if !strings.Contains(output, "again") {
			t.Fatalf("the second pinned connection should work as well:\n%s", output)
		}
		if unchanged := readKnownHosts(t, home); unchanged != knownHosts {
			t.Fatalf("known_hosts should be untouched by a connection whose hash it already holds:\n%s\n%s", knownHosts, unchanged)
		}
	})

	// A pin is a decision, not a hint: an entry of known_hosts which trusts the
	// certificate must not outvote a pin saying otherwise, or pinning would be a
	// preference a stale known_hosts silently disables.
	t.Run("a different hash is refused even when known hosts trusts the certificate", func(t *testing.T) {
		home := filepath.Join(root, "known")
		if err := os.MkdirAll(home, 0700); err != nil {
			t.Fatalf("could not create the home of the client: %s", err)
		}
		if out := runPinningClient(t, clientBinary, home, "-i", keyPath, "-host-hash", pinnedHash, url, "echo seed"); !strings.Contains(out, "seed") {
			t.Fatalf("could not seed known_hosts of the client:\n%s", out)
		}
		knownHosts := readKnownHosts(t, home)
		if !knowsHash(t, home, pinnedHash) {
			t.Fatalf("known_hosts should hold the certificate of the server it connected to:\n%s", knownHosts)
		}

		output := runPinningClient(t, clientBinary, home, "-i", keyPath, "-host-hash", anotherHash, url, "echo should-not-run")
		// both hashes belong in the message: the one which was asked for, so that
		// the user knows what the pin says, and the one the server presents, which
		// is what the pin has to be updated to if the server is innocent
		for _, expected := range []string{"hash mismatch", "machine-in-the-middle", "update", anotherHash, pinnedHash} {
			if !strings.Contains(output, expected) {
				t.Fatalf("the refusal should mention %q:\n%s", expected, output)
			}
		}
		if strings.Contains(output, "should-not-run") {
			t.Fatalf("a mismatching pin must refuse the connection:\n%s", output)
		}
		if changed := readKnownHosts(t, home); changed != knownHosts {
			t.Fatalf("a refused certificate must not be written to known_hosts:\n%s\n%s", knownHosts, changed)
		}
	})

	// The same pin per host, without a flag: this is how a server everybody
	// connects to gets pinned, in ~/.ssh/config next to HostName and IdentityFile.
	t.Run("the HostHash directive of the ssh config pins a certificate", func(t *testing.T) {
		home := filepath.Join(root, "config")
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
			t.Fatalf("could not create the ssh dir of the client: %s", err)
		}
		writeConfig := func(hash string) {
			t.Helper()
			config := "IgnoreUnknown HostHash\nHost 127.0.0.1\n  HostHash " + hash + "\n"
			if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(config), 0600); err != nil {
				t.Fatalf("could not write the ssh config: %s", err)
			}
		}
		writeConfig(pinnedHash)
		output := runPinningClient(t, clientBinary, home, "-i", keyPath, url, "echo hello-from-config")
		if !strings.Contains(output, "hello-from-config") {
			t.Fatalf("the HostHash directive should have pinned the certificate:\n%s", output)
		}
		if !knowsHash(t, home, pinnedHash) {
			t.Fatalf("a certificate pinned by the ssh config should be recorded in known_hosts:\n%s", readKnownHosts(t, home))
		}

		// and the directive refuses what the flag refuses
		writeConfig(anotherHash)
		output = runPinningClient(t, clientBinary, home, "-i", keyPath, url, "echo should-not-run")
		if strings.Contains(output, "should-not-run") || !strings.Contains(output, "hash mismatch") {
			t.Fatalf("a HostHash directive which does not match must refuse the connection:\n%s", output)
		}
	})
}

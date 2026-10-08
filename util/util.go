package util

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	osuser "os/user"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type UnknownSSHPubkeyType struct {
	pubkey crypto.PublicKey
}

func (m UnknownSSHPubkeyType) Error() string {
	return fmt.Sprintf("unknown signing method: %T", m.pubkey)
}

// copied from "net/http/internal/ascii"
// EqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func EqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func ConfigureLogger(logLevel string) {
	switch strings.ToLower(logLevel) {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warning":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}
}

// HomeDir returns the current user's home directory.
// The HOME environment variable takes precedence; if it is unset or empty,
// the home directory declared for the current user in the password database
// is used, like OpenSSH does. It returns an empty string if the home
// directory cannot be determined.
func HomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if user, err := osuser.Current(); err == nil {
		return user.HomeDir
	}
	return ""
}

// expandEnvVars expands the "$VAR" and "${VAR}" constructs of the provided
// string using the process environment. Variables that are not set are left
// untouched, so a value containing an unrelated "$" is never silently turned
// into an empty path component.
func expandEnvVars(value string) string {
	if !strings.Contains(value, "$") {
		return value
	}
	return os.Expand(value, func(name string) string {
		if expanded, ok := os.LookupEnv(name); ok {
			return expanded
		}
		return "${" + name + "}"
	})
}

// expandTilde expands the leading "~" construct of a path, as documented in
// ssh_config(5):
//   - "~" and "~/..." expand to the current user's home directory
//   - "~user" and "~user/..." expand to the home directory of the given user
//
// If the path does not start with a "~", or if the requested home directory
// cannot be determined, the path is returned unchanged.
func expandTilde(filepath string) string {
	if filepath == "" || filepath[0] != '~' {
		return filepath
	}
	rest := filepath[1:]
	if rest == "" || rest[0] == '/' || rest[0] == '\\' {
		return joinHomeDir(HomeDir(), strings.TrimLeft(rest, "/\\"))
	}
	// "~user" or "~user/...": look up the requested user
	username := rest
	rest = ""
	if idx := strings.IndexAny(username, "/\\"); idx >= 0 {
		username, rest = username[:idx], username[idx+1:]
	}
	user, err := osuser.Lookup(username)
	if err != nil {
		// unknown user: leave the path untouched rather than breaking it
		log.Warn().Msgf("could not resolve home directory of user %s when expanding %s", username, filepath)
		return filepath
	}
	return joinHomeDir(user.HomeDir, strings.TrimLeft(rest, "/\\"))
}

// joinHomeDir joins a home directory and a relative path, returning the home
// directory itself when there is nothing left to append.
func joinHomeDir(homeDir string, relative string) string {
	if homeDir == "" {
		// no home directory available: strip the "~" separator and keep the
		// remaining path as-is, so the caller reports a meaningful error
		if relative == "" {
			return homeDir
		}
		return relative
	}
	if relative == "" {
		return homeDir
	}
	return path.Join(homeDir, relative)
}

// ExpandPath expands a file path coming from the OpenSSH configuration file
// (~/.ssh/config) or from the command line, the way OpenSSH does it:
//   - surrounding single or double quotes are removed (kevinburke/ssh_config
//     keeps them in the parsed values)
//   - a leading "~", "~/...", "~user" or "~user/..." is replaced by the
//     relevant home directory
//   - "$HOME/.ssh/id_ed25519"-like environment variable references are
//     expanded
//
// Examples, with HOME=/home/alice:
//
//	"~/.ssh/id_example"        -> "/home/alice/.ssh/id_example"
//	"~"                        -> "/home/alice"
//	"$HOME/.ssh/id_example"    -> "/home/alice/.ssh/id_example"
//	"\"~/.ssh/id_example\""    -> "/home/alice/.ssh/id_example"
//	"/etc/ssh/ssh_host_rsa_key" -> unchanged
func ExpandPath(filepath string) string {
	trimmed := strings.TrimSpace(filepath)
	if len(trimmed) > 1 && (strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`) ||
		strings.HasPrefix(trimmed, "'") && strings.HasSuffix(trimmed, "'")) {
		trimmed = trimmed[1 : len(trimmed)-1]
	}
	if trimmed == "" {
		return trimmed
	}
	if trimmed[0] == '~' {
		// expand the env vars of the remaining path, but never the home
		// directory itself, which must be substituted literally
		expanded := expandEnvVars(trimmed[1:])
		return expandTilde(trimmed[:1] + expanded)
	}
	return expandEnvVars(trimmed)
}

// ExpandTildeWithHomeDir expands the "~" construct of the provided path using
// the current user's home directory (see ExpandPath).
func ExpandTildeWithHomeDir(filepath string) string {
	return ExpandPath(filepath)
}

// Accept queue copied from https://github.com/quic-go/webtransport-go/blob/master/session.go
type AcceptQueue[T any] struct {
	mx sync.Mutex
	// The channel is used to notify consumers (via Chan) about new incoming items.
	// Needs to be buffered to preserve the notification if an item is enqueued
	// between a call to Next and to Chan.
	c chan struct{}
	// Contains all the streams waiting to be accepted.
	// There's no explicit limit to the length of the queue, but it is implicitly
	// limited by the stream flow control provided by QUIC.
	queue []T
}

func NewAcceptQueue[T any]() *AcceptQueue[T] {
	return &AcceptQueue[T]{c: make(chan struct{}, 1)}
}

func (q *AcceptQueue[T]) Add(str T) {
	q.mx.Lock()
	q.queue = append(q.queue, str)
	q.mx.Unlock()

	select {
	case q.c <- struct{}{}:
	default:
	}
}

func (q *AcceptQueue[T]) Next() T {
	q.mx.Lock()
	defer q.mx.Unlock()

	if len(q.queue) == 0 {
		return *new(T)
	}
	str := q.queue[0]
	q.queue = q.queue[1:]
	return str
}

func (q *AcceptQueue[T]) Chan() <-chan struct{} { return q.c }

type DatagramsQueue struct {
	c chan []byte
}

func NewDatagramsQueue(len uint64) *DatagramsQueue {
	return &DatagramsQueue{c: make(chan []byte, len)}
}

// returns true if added, false otherwise
func (q *DatagramsQueue) Add(datagram []byte) bool {
	select {
	case q.c <- datagram:
		return true
	default:
		return false
	}
}

// returns nil if added, the context closing error (context.Cause(ctx)) otherwise
func (q *DatagramsQueue) WaitAdd(ctx context.Context, datagram []byte) error {
	select {
	case q.c <- datagram:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (q *DatagramsQueue) Next() []byte {
	select {
	case datagram := <-q.c:
		return datagram
	default:
		return nil
	}
}

func (q *DatagramsQueue) WaitNext(ctx context.Context) ([]byte, error) {
	select {
	case datagram := <-q.c:
		return datagram, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func JWTSigningMethodFromCryptoPubkey(pubkey crypto.PublicKey) (jwt.SigningMethod, error) {
	log.Debug().Type("SigningMethodType", pubkey).Msg("fetching singing method from crypto.PublicKey")

	switch pubkey.(type) {
	case *ecdsa.PublicKey:
		log.
			Trace().
			Type("SigningMethodType", pubkey).
			Str("FoundSigningMethod", "ECDSA").
			Msg("found public key type")
		return jwt.SigningMethodES256, nil
	case *rsa.PublicKey:
		log.
			Trace().
			Type("SigningMethodType", pubkey).
			Str("FoundSigningMethod", "RSA").
			Msg("found public key type")
		return jwt.SigningMethodRS256, nil
	case ed25519.PublicKey:
		log.
			Trace().
			Type("SigningMethodType", pubkey).
			Str("FoundSigningMethod", "ED25519").
			Msg("found public key type")
		return jwt.SigningMethodEdDSA, nil
	default:
		log.
			Error().
			Type("SigningMethodType", pubkey).
			Str("FoundSigningMethod", "unknown").
			Msg("did not find public key type")
		return nil, UnknownSSHPubkeyType{pubkey: pubkey}
	}
}

func Sha256Fingerprint(in []byte) string {
	hash := sha256.Sum256(in)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func getSANExtension(cert *x509.Certificate) []byte {
	oidExtensionSubjectAltName := []int{2, 5, 29, 17}
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return e.Value
		}
	}
	return nil
}

func forEachSAN(der cryptobyte.String, callback func(tag int, data []byte) error) error {
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return errors.New("x509: invalid subject alternative names")
	}
	for !der.Empty() {
		var san cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !der.ReadAnyASN1(&san, &tag) {
			return errors.New("x509: invalid subject alternative name")
		}
		if err := callback(int(tag^0x80), san); err != nil {
			return err
		}
	}

	return nil
}

// returns true whether the certificat contains a SubjectAltName extension
// with at least one IP address record
func CertHasIPSANs(cert *x509.Certificate) (bool, error) {
	SANExtension := getSANExtension(cert)
	if SANExtension == nil {
		return false, nil
	}
	nameTypeIP := 7
	var ipAddresses []net.IP

	err := forEachSAN(SANExtension, func(tag int, data []byte) error {
		switch tag {
		case nameTypeIP:
			switch len(data) {
			case net.IPv4len, net.IPv6len:
				ipAddresses = append(ipAddresses, data)
			default:
				return fmt.Errorf("x509: cannot parse IP address of length %d", len(data))
			}
		default:
		}

		return nil
	})
	return len(ipAddresses) > 0, err
}

func GenerateKey() (crypto.PublicKey, crypto.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func GenerateCert(priv crypto.PrivateKey) (*x509.Certificate, error) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	cert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SSH3Organization"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 10),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"*", "selfsigned.ssh3"},
		IsCA:                  true,
	}

	return &cert, nil
}

func DumpCertAndKeyToFiles(cert *x509.Certificate, pubkey crypto.PublicKey, privkey crypto.PrivateKey, certPath, keyPath string) error {
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pubkey, privkey)
	if err != nil {
		return err
	}
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		return err
	}
	err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return err
	}

	return nil
}

type SyncMap[K comparable, V any] struct {
	inner sync.Map
}

func NewSyncMap[K comparable, V any]() SyncMap[K, V] {
	return SyncMap[K, V]{
		inner: sync.Map{},
	}
}

func (m *SyncMap[K, V]) Get(key K) (V, bool) {
	val, ok := m.inner.Load(key)
	if val == nil {
		// we can't return nil for *any* type, so we create a zero value for the type and return it, instead of nil
		var zero V
		return zero, ok
	}
	return val.(V), ok
}

func (m *SyncMap[K, V]) Insert(key K, val V) {
	m.inner.Store(key, val)
}

func (m *SyncMap[K, V]) Delete(key K) {
	m.inner.Delete(key)
}

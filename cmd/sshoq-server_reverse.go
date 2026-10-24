package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	ssh3 "github.com/h4sh5/sshoq"
	"github.com/h4sh5/sshoq/client"
	client_config "github.com/h4sh5/sshoq/client/config"
	"github.com/h4sh5/sshoq/util"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// reverseTunnelConfig is one -R request of sshoq-server: an sshoq server to
// connect to, the UDP port that server must open on its localhost, and the
// local address the traffic arriving on that port is delivered to - the local
// sshoq server's own socket by default.
//
// The forwarding is done with the reverse UDP mechanism of the protocol (the
// same one the sshoq client uses for -reverse-udp), because sshoq speaks QUIC,
// which is UDP: a remote user points a normal sshoq client at the port opened
// on the remote host's localhost, and its QUIC datagrams are tunneled here.
type reverseTunnelConfig struct {
	url        string       // the sshoq server to connect to, as user@host:port/url-path
	remoteBind *net.UDPAddr // address to open on the remote server (its localhost)
	localDest  *net.UDPAddr // address on this host where forwarded traffic goes
}

// parseReverseTunnelSpec parses the argument of sshoq-server's -R flag:
//
//	user@example.com:4443/sshoq-remote%4444
//
// which means: connect to the sshoq server at example.com:4443 on the URL path
// /sshoq-remote, and ask it to open UDP port 4444 on its localhost; everything
// connecting there is forwarded to the local sshoq server, at 127.0.0.1 plus
// the port this server listens on (the -bind argument, defaultLocalBind).
//
// The destination on this host may also be spelled out explicitly, with the
// same @ syntax as the forwarding flags of the sshoq client:
//
//	user@example.com:4443/sshoq-remote%4444@127.0.0.1@8443
func parseReverseTunnelSpec(spec string, defaultLocalBind string) (*reverseTunnelConfig, error) {
	sep := strings.Index(spec, "%")
	if sep < 0 {
		return nil, fmt.Errorf("invalid -R argument %q: expected sshoq-url%%remote-port (e.g. user@example.com:4443/sshoq-remote%%4444)", spec)
	}
	urlPart, forwardPart := spec[:sep], spec[sep+1:]

	raw := urlPart
	if !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("could not parse the sshoq server URL of -R (%q): %s", urlPart, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid -R argument %q: missing the remote sshoq server URL before '%%'", spec)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return nil, fmt.Errorf("invalid -R argument %q: missing the URL path of the remote sshoq server (e.g. %s/sshoq-remote%%...)", spec, urlPart)
	}
	if parsed.User == nil || parsed.User.Username() == "" {
		return nil, fmt.Errorf("invalid -R argument %q: the remote sshoq server URL must include a username (user@host:port/path)", spec)
	}

	// the forwarding part: remote-port, optionally followed by @localip@localport
	parts := strings.Split(forwardPart, "@")
	if len(parts) != 1 && len(parts) != 3 {
		return nil, fmt.Errorf("invalid -R forwarding spec %q: expected remote-port or remote-port@localip@localport", forwardPart)
	}
	remotePort, err := parseReverseTunnelPort(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid remote port in -R argument %q: %s", spec, err)
	}
	localIPStr := "127.0.0.1"
	localPort := 0
	if len(parts) == 3 {
		localIPStr = parts[1]
		localPort, err = parseReverseTunnelPort(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid local port in -R argument %q: %s", spec, err)
		}
	} else {
		// default: the local sshoq server's own port, taken from its -bind argument
		localPort, err = portFromHostPort(defaultLocalBind)
		if err != nil {
			return nil, fmt.Errorf("could not get the local port from the -bind argument %q to use as the -R destination: %s", defaultLocalBind, err)
		}
	}

	localIP := net.ParseIP(localIPStr)
	if localIP == nil {
		return nil, fmt.Errorf("could not parse the local IP %q of the -R argument %q", localIPStr, spec)
	}

	return &reverseTunnelConfig{
		url:        parsed.String(),
		remoteBind: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		localDest:  &net.UDPAddr{IP: localIP, Port: localPort},
	}, nil
}

// parseReverseTunnelPort parses a UDP port number given on the command line.
func parseReverseTunnelPort(s string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("could not parse port %q: %s", s, err)
	}
	if port <= 0 || port > 0xFFFF {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return port, nil
}

// portFromHostPort extracts the port of an address:port pair such as the one
// given to -bind ([::]:443, 0.0.0.0:443, ...).
func portFromHostPort(hostPort string) (int, error) {
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return 0, err
	}
	return parseReverseTunnelPort(portStr)
}

// parseRemotePublicKey accepts the argument of -rpub, which is either a
// public key given inline ("ssh-ed25519 AAAAC3Nza... comment") or the name of
// a file containing one. Anything which parses as an OpenSSH authorized-key
// line - every algorithm x/crypto/ssh knows: ssh-rsa, ssh-dss, ecdsa-sha2-*,
// ssh-ed25519, sk-ecdsa/ecdsa-sk and sk-ed25519/ed25519-sk - is treated as a
// key, anything else as a filename.
//
// The key is returned in its normalized authorized_keys form, so that the
// installed line is valid whatever spacing the argument used.
func parseRemotePublicKey(arg string) (string, error) {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" {
		return "", fmt.Errorf("empty -pubkey/-rpub argument")
	}
	// A key line always carries whitespace between the algorithm and the base64
	// blob; a filename on its own cannot parse. Trying the parse first is also
	// what guarantees the support of every algorithm, present and future, that
	// the SSH library accepts, instead of matching a hand-maintained prefix list.
	if pubkey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed)); err == nil {
		return normalizeAuthorizedKeyLine(pubkey, comment), nil
	}

	filename := util.ExpandPath(trimmed)
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("the -pubkey/-rpub argument %q is neither a valid public key nor a readable file: %s", arg, err)
	}
	// the file may carry one or several public keys, comments included, like an
	// .pub file or an authorized_keys file does
	pubkeys := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pubkey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return "", fmt.Errorf("could not parse a public key in %s (%q): %s", filename, line, err)
		}
		pubkeys += normalizeAuthorizedKeyLine(pubkey, comment) + "\n"
	}
	if pubkeys == "" {
		return "", fmt.Errorf("the -pubkey/-rpub file %s contains no public key", filename)
	}
	return strings.TrimSuffix(pubkeys, "\n"), nil
}

// normalizeAuthorizedKeyLine renders a parsed public key as a single
// authorized_keys line: MarshalAuthorizedKey output, plus the comment the
// argument carried, which the marshalling drops. The comment is stripped of
// line breaks so that one key always makes exactly one line.
func normalizeAuthorizedKeyLine(pubkey ssh.PublicKey, comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubkey)))
	if c := strings.TrimSpace(strings.ReplaceAll(comment, "\n", " ")); c != "" {
		line += " " + c
	}
	return line
}

// collectStaticAuthorizedIdentities turns the arguments of -pubkey and -rpub -
// each of them a public key given as a string or the name of a file containing
// public keys - into normalized authorized identity lines.
//
// The lines are registered with server_auth.AddStaticAuthorizedIdentities, so
// they are authorized by the running server only, in its memory: nothing is
// ever written to ~/.ssh3/authorized_identities, on this side of the -R tunnel
// nor on the other one. The keys thus live exactly as long as the server run
// they were given to, which is what one wants from keys handed out to people
// connecting through a forwarded port: stop the server, or drop the flag, and
// they are gone.
func collectStaticAuthorizedIdentities(pubkeyArgs []string) ([]string, error) {
	var lines []string
	for _, arg := range pubkeyArgs {
		normalized, err := parseRemotePublicKey(arg)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(normalized, "\n") {
			if line != "" {
				lines = append(lines, line)
			}
		}
	}
	return lines, nil
}

// reverseTunnelRetryDelay is how long sshoq-server waits before reconnecting
// to the remote sshoq server when the tunnel goes down (remote restart,
// network outage, authentication failure, ...).
const reverseTunnelRetryDelay = 5 * time.Second

// runReverseTunnel keeps a reverse forwarding of the local sshoq server
// towards a remote sshoq server: it connects and authenticates as an sshoq
// client, asks the peer to open the configured port on its localhost, and
// serves the channels it opens for the connecting users until the conversation
// dies - then it tries again, so that a server behind a NAT recovers by itself
// when the public relay comes back.
func runReverseTunnel(cfg *reverseTunnelConfig, identityFiles []string, insecure bool) {
	ctx := context.Background()
	for {
		err := reverseTunnelOnce(ctx, cfg, identityFiles, insecure)
		if err != nil {
			log.Warn().Msgf("reverse sshoq tunnel to %s on %s stopped: %s - retrying in %s",
				cfg.remoteBind, cfg.url, err, reverseTunnelRetryDelay)
		}
		select {
		case <-time.After(reverseTunnelRetryDelay):
		case <-ctx.Done():
			return
		}
	}
}

func reverseTunnelOnce(ctx context.Context, cfg *reverseTunnelConfig, identityFiles []string, insecure bool) error {
	parsedUrl, err := url.Parse(cfg.url)
	if err != nil {
		return fmt.Errorf("could not parse the remote sshoq server URL %s: %s", cfg.url, err)
	}
	port := 443
	if p := parsedUrl.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("invalid port in the remote sshoq server URL %s: %s", cfg.url, err)
		}
	}

	// authenticate to the remote server with the given private keys, or with
	// the default ~/.ssh keys when none were given, like the sshoq client does
	var authMethods []interface{}
	if len(identityFiles) == 0 {
		for _, method := range ssh3.NewDefaultPrivkeyFileAuthMethods() {
			authMethods = append(authMethods, method)
		}
	} else {
		for _, filename := range identityFiles {
			authMethods = append(authMethods, ssh3.NewPrivkeyFileAuthMethod(filename))
		}
	}

	clientConfig, err := client_config.NewConfig(
		parsedUrl.User.Username(),
		parsedUrl.Hostname(),
		port,
		parsedUrl.Path,
		authMethods,
		map[client_config.OptionName]client_config.Option{},
	)
	if err != nil {
		return fmt.Errorf("could not set up the client configuration for %s: %s", cfg.url, err)
	}

	ssh3Dir := resolveConfigDir("")
	knownHostsPath := path.Join(ssh3Dir, "known_hosts")
	knownHosts, skippedLines, err := ssh3.ParseKnownHosts(knownHostsPath)
	if err != nil {
		log.Warn().Msgf("error parsing known hosts file %s for the reverse tunnel: %s", knownHostsPath, err)
	}
	if len(skippedLines) != 0 {
		log.Warn().Msgf("%d lines in %s are invalid", len(skippedLines), knownHostsPath)
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}

	// no tty here: an unknown self-signed server certificate is refused unless
	// -R-insecure is set or the certificate is in the known hosts file
	qconn, status := setupQUICConnection(ctx, insecure, nil, ssh3Dir, certPool, knownHostsPath, knownHosts, nil, clientConfig, nil, nil)
	if qconn == nil {
		if status == 0 {
			return fmt.Errorf("the connection to %s was refused and reconnection is required", cfg.url)
		}
		return fmt.Errorf("could not set up the QUIC transport to %s (use -R-insecure if its self-signed certificate is unknown to %s)", cfg.url, knownHostsPath)
	}

	roundTripper := &http3.RoundTripper{EnableDatagrams: true}
	c, err := client.Dial(ctx, clientConfig, qconn, roundTripper, nil)
	if err != nil {
		return fmt.Errorf("could not authenticate to %s: %s", cfg.url, err)
	}
	defer c.Close()

	// ask the remote server to open the port on its localhost. The request
	// channel itself carries no traffic and is closed right away; the listener
	// on the peer lives for as long as this conversation does.
	forwardingChannel, err := c.RequestUDPReverseChannel(30000, 10, cfg.remoteBind, cfg.localDest)
	if err != nil {
		return fmt.Errorf("could not request the reverse forwarding of port %d on %s: %s", cfg.remoteBind.Port, cfg.url, err)
	}
	forwardingChannel.Close()

	fmt.Fprintf(os.Stderr, "Reverse sshoq tunnel up: %s is forwarding %s to the local sshoq server at %s\n",
		cfg.url, cfg.remoteBind, cfg.localDest)
	log.Info().Msgf("reverse sshoq tunnel up: %s forwards %s to %s", cfg.url, cfg.remoteBind, cfg.localDest)

	// serve the channels the remote server opens for every user connecting to
	// the forwarded port; returns when the conversation is gone
	return c.ServeReverseForwarding(ctx)
}

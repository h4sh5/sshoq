package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	osuser "os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/h4sh5/sshoq"
	"github.com/h4sh5/sshoq/auth/oidc"
	"github.com/h4sh5/sshoq/client"
	client_config "github.com/h4sh5/sshoq/client/config"
	"github.com/h4sh5/sshoq/internal"
	sshoqsftp "github.com/h4sh5/sshoq/sftp"
	"github.com/h4sh5/sshoq/util"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ssh/agent"

	"github.com/kevinburke/ssh_config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func homedir() string {
	user, err := osuser.Current()
	if err == nil {
		return user.HomeDir
	} else {
		return os.Getenv("HOME")
	}
}

// Prepares the QUIC connection that will be used by SSH3
// If non-nil, use udpConn as transport (can be used for proxy jump)
// Otherwise, create a UDPConn from udp://host:port
// returns nil, -1 on error, or nil, 0 if reconnection is required
func setupQUICConnection(ctx context.Context, skipHostVerification bool, keylog io.Writer, ssh3Dir string, certPool *x509.CertPool, knownHostsPath string, knownHosts ssh3.KnownHosts,
	oidcConfig []*oidc.OIDCConfig, options *client_config.Config, proxyRemoteAddr *net.UDPAddr, tty *os.File) (quic.EarlyConnection, int) {

	var err error
	remoteAddr := proxyRemoteAddr
	if remoteAddr == nil {
		remoteAddr, err = net.ResolveUDPAddr("udp", options.URLHostnamePort())
		if err != nil {
			log.Error().Msgf("could not resolve UDP address: %s", err)
			return nil, -1
		}
	}

	netString := "udp"
	if runtime.GOOS == "darwin" {
		// on MacOS, the don't fragment (DF) bit is not set on dual-stack socket ("udp")
		// This causes quic-go to not perform MTU discovery which can prevent the proxy jump from working at all.
		// cf: - https://github.com/francoismichel/ssh3/issues/129
		//     - https://github.com/quic-go/quic-go/issues/3793
		//
		// The fix here is to not use a dual-stack socket on MacOS and detect the IP version from the resolved peer address.

		if remoteAddr.IP.To4() != nil {
			// it is a v4 address
			netString = "udp4"
		} else {
			// it is a v6 address
			netString = "udp6"
		}
	}

	udpConn, err := net.ListenUDP(netString, nil)
	if err != nil {
		log.Error().Msgf("could not create UDP connection: %s", err)
		return nil, -1
	}

	tlsConf := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: skipHostVerification,
		NextProtos:         []string{http3.NextProtoH3},
		KeyLogWriter:       keylog,
		ServerName:         options.Hostname(),
	}

	var qconf quic.Config

	qconf.MaxIncomingUniStreams = 100000
	qconf.MaxIncomingStreams = 100000
	qconf.Allow0RTT = false
	qconf.EnableDatagrams = true
	qconf.KeepAlivePeriod = 1 * time.Second

	if certs, ok := knownHosts[options.CanonicalHostFormat()]; ok {
		foundSelfsignedSSH3 := false

		for _, cert := range certs {
			certPool.AddCert(cert)
			if cert.VerifyHostname("selfsigned.ssh3") == nil {
				foundSelfsignedSSH3 = true
			}
		}

		// If no IP SAN was in the cert, then assume the self-signed cert at least matches the .ssh3 TLD
		if foundSelfsignedSSH3 {
			// Put "ssh3" as ServerName so that the TLS verification can succeed
			// Otherwise, TLS refuses to validate a certificate without IP SANs
			// if the hostname is an IP address.
			tlsConf.ServerName = "selfsigned.ssh3"
		}
	}

	log.Debug().Msgf("dialing QUIC host at %s", remoteAddr)
	qClient, err := quic.DialEarly(ctx,
		udpConn,
		remoteAddr,
		tlsConf,
		&qconf)
	if err != nil {
		if transportErr, ok := err.(*quic.TransportError); ok {
			if transportErr.ErrorCode.IsCryptoError() {
				log.Debug().Msgf("received QUIC crypto error on first connection attempt: %s", err)
				if tty == nil {
					log.Error().Msgf("insecure server cert in non-terminal session, aborting")
					return nil, -1
				}
				if _, ok := knownHosts[options.CanonicalHostFormat()]; ok {
					log.Error().Msgf("The server certificate cannot be verified using the one installed in %s. "+
						"If you did not change the server certificate, it could be a machine-in-the-middle attack. "+
						"TLS error: %s", knownHostsPath, err)
					log.Error().Msgf("Aborting.")
					return nil, -1
				}
				// bad certificates, let's mimic the OpenSSH's behaviour similar to host keys
				tlsConf.InsecureSkipVerify = true
				var peerCertificate *x509.Certificate
				certError := fmt.Errorf("We don't want to start a totally insecure connection")
				tlsConf.VerifyConnection = func(ctx tls.ConnectionState) error {
					peerCertificate = ctx.PeerCertificates[0]
					return certError
				}

				_, err := quic.DialEarly(ctx,
					udpConn,
					remoteAddr,
					tlsConf,
					&qconf)
				if !errors.Is(err, certError) {
					log.Error().Msgf("could not create client QUIC connection: %s", err)
					return nil, -1
				}
				// let's first check that the certificate is self-signed
				if err := peerCertificate.CheckSignatureFrom(peerCertificate); err != nil {
					log.Error().Msgf("the peer provided an unknown, insecure certificate, that is not self-signed: %s", err)
					return nil, -1
				}
				// first, carriage return
				_, _ = tty.WriteString("\r")
				_, err = tty.WriteString("Received an unknown self-signed certificate from the server.\n\r" +
					"We recommend not using self-signed certificates.\n\r" +
					"This session is vulnerable a machine-in-the-middle attack.\n\r" +
					"Certificate fingerprint: " +
					"SHA256 " + util.Sha256Fingerprint(peerCertificate.Raw) + "\n\r" +
					"Do you want to add this certificate to ~/.ssh3/known_hosts (yes/no)? ")
				if err != nil {
					log.Error().Msgf("cound not write on /dev/tty: %s", err)
					return nil, -1
				}

				answer := ""
				reader := bufio.NewReader(tty)
				for {
					answer, _ = reader.ReadString('\n')
					answer = strings.TrimSpace(answer)
					_, _ = tty.WriteString("\r") // always ensure a carriage return
					if answer == "yes" || answer == "no" {
						break
					}
					tty.WriteString("Invalid answer, answer \"yes\" or \"no\" ")
				}
				if answer == "no" {
					log.Info().Msg("Connection aborted")
					return nil, 0
				}
				if err := ssh3.AppendKnownHost(knownHostsPath, options.CanonicalHostFormat(), peerCertificate); err != nil {
					log.Error().Msgf("could not append known host to %s: %s", knownHostsPath, err)
					return nil, -1
				}
				tty.WriteString(fmt.Sprintf("Successfully added the certificate to %s, reconnecting..\n\r", knownHostsPath))
				return nil, 0
			}
		}
		log.Error().Msgf("could not establish client QUIC connection: %s", err)
		return nil, -1
	}

	return qClient, 0
}

func parseAddrPort(addrPort string) (localIP net.IP, localPort int, remoteIP net.IP, remotePort int, err error) {
	array := strings.Split(addrPort, "@")

	if len(array) < 3 {
		return nil, 0, nil, 0, fmt.Errorf("Syntax incorrect for port forwarding. Use [bindip]:port:ip:port (bindip is optional), same as openssh")
	}
	localIPStr := "127.0.0.1" // always default to localhost if not specified
	remoteIPStr := "127.0.0.1"
	localPortStr := "0"
	remotePortStr := "0"
	if len(array) == 4 {
		localIPStr = array[0]
		localPortStr = array[1]
		remoteIPStr = array[2]
		remotePortStr = array[3]
	} else if len(array) == 3 {
		localPortStr = array[0]
		remoteIPStr = array[1]
		remotePortStr = array[2]
	}

	localIP = net.ParseIP(localIPStr)
	if localIP == nil {
		return nil, 0, nil, 0, fmt.Errorf("could not parse IP %s", localIPStr)
	}
	localPort, err = strconv.Atoi(localPortStr)
	if err != nil {
		return nil, 0, nil, 0, fmt.Errorf("could not convert %s to int: %s", localPortStr, err)
	} else if localPort > 0xFFFF {
		return nil, 0, nil, 0, fmt.Errorf("port too large %d", localPort)
	}
	remoteIP = net.ParseIP(remoteIPStr)
	if remoteIP == nil {
		return nil, 0, nil, 0, fmt.Errorf("could not parse IP %s", remoteIPStr)
	}
	remotePort, err = strconv.Atoi(remotePortStr)
	if err != nil {
		return nil, 0, nil, 0, fmt.Errorf("could not convert %s to int: %s", array[0], err)
	} else if remotePort > 0xFFFF {
		return nil, 0, nil, 0, fmt.Errorf("port too large %d", remotePort)
	}
	return localIP, localPort, remoteIP, remotePort, err
}

// stringSliceFlag is a flag.Value that accumulates every occurrence of the flag,
// allowing repeated flags such as multiple -L or -R (like OpenSSH).
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// localIPForForwarding picks the local bind IP according to the remote address
// family, defaulting to the loopback of the same family, like OpenSSH does.
func localIPForForwarding(localIP net.IP, remoteIP net.IP) net.IP {
	if remoteIP.To4() != nil {
		if localIP.To4() != nil {
			return localIP.To4()
		}
		return net.IPv4(127, 0, 0, 1)
	}
	if remoteIP.To16() != nil {
		if localIP.To16() != nil {
			return localIP.To16()
		}
		return net.IPv6loopback
	}
	return nil
}

// parseTCPForwarding parses a single forwarding spec "[bindip:]localport@remoteip@remoteport"
// into a local/remote TCP address pair.
func parseTCPForwarding(forwardSpec string) (local *net.TCPAddr, remote *net.TCPAddr, err error) {
	localIP, localPort, remoteIP, remotePort, err := parseAddrPort(forwardSpec)
	if err != nil {
		return nil, nil, err
	}
	bindIP := localIPForForwarding(localIP, remoteIP)
	if bindIP == nil {
		return nil, nil, fmt.Errorf("unrecognized remote IP length %d", len(remoteIP))
	}
	return &net.TCPAddr{IP: bindIP, Port: localPort}, &net.TCPAddr{IP: remoteIP, Port: remotePort}, nil
}

// parseUDPForwarding parses a single forwarding spec "[bindip:]localport@remoteip@remoteport"
// into a local/remote UDP address pair.
func parseUDPForwarding(forwardSpec string) (local *net.UDPAddr, remote *net.UDPAddr, err error) {
	localIP, localPort, remoteIP, remotePort, err := parseAddrPort(forwardSpec)
	if err != nil {
		return nil, nil, err
	}
	bindIP := localIPForForwarding(localIP, remoteIP)
	if bindIP == nil {
		return nil, nil, fmt.Errorf("unrecognized remote IP length %d", len(remoteIP))
	}
	return &net.UDPAddr{IP: bindIP, Port: localPort}, &net.UDPAddr{IP: remoteIP, Port: remotePort}, nil
}

// splitForwardingSpecs expands a single flag value into individual forwarding specs.
// Comma separated values (previously supported by -forward-udp/-reverse-udp) are
// kept for backwards compatibility, and repeated flags are all handled here too.
func splitForwardingSpecs(groups []string) []string {
	var specs []string
	for _, group := range groups {
		for _, spec := range strings.Split(group, ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			specs = append(specs, spec)
		}
	}
	return specs
}

// setupForwardings starts every local and remote port forwarding that was
// requested on the command line. Multiple -L, -R, -forward-tcp, -forward-udp,
// -reverse-tcp and -reverse-udp flags can be freely combined, in any order, and
// with a mix of TCP and UDP. It returns the updated multicast UDP connection
// (if any was created) that subsequent forwardings should reuse.
func setupForwardings(ctx context.Context, c *client.Client, forwardTCP, reverseTCP, forwardUDP, reverseUDP []string, fwUDPmulticonn *net.UDPConn) (*net.UDPConn, error) {
	// Local TCP forwardings (-L / -forward-tcp): a local port is forwarded to a remote port.
	for _, spec := range splitForwardingSpecs(forwardTCP) {
		local, remote, err := parseTCPForwarding(spec)
		if err != nil {
			return fwUDPmulticonn, fmt.Errorf("TCP forwarding parsing error for %q: %s", spec, err)
		}
		if _, err := c.ForwardTCP(ctx, local, remote); err != nil {
			return fwUDPmulticonn, fmt.Errorf("could not forward TCP %s -> %s: %s", local, remote, err)
		}
	}

	// Reverse TCP forwardings (-R / -reverse-tcp): a remote port is forwarded to a local port.
	for _, spec := range splitForwardingSpecs(reverseTCP) {
		local, remote, err := parseTCPForwarding(spec)
		if err != nil {
			return fwUDPmulticonn, fmt.Errorf("TCP reverse parsing error for %q: %s", spec, err)
		}
		if _, err := c.ReverseTCP(ctx, local, remote); err != nil {
			return fwUDPmulticonn, fmt.Errorf("could not reverse TCP %s -> %s: %s", local, remote, err)
		}
	}

	// Local UDP forwardings (-forward-udp): a local port is forwarded to a remote port.
	for _, spec := range splitForwardingSpecs(forwardUDP) {
		local, remote, err := parseUDPForwarding(spec)
		if err != nil {
			return fwUDPmulticonn, fmt.Errorf("UDP forwarding parsing error for %q: %s", spec, err)
		}
		_, conn, err := c.ForwardUDP(ctx, local, remote, fwUDPmulticonn)
		if err != nil {
			return fwUDPmulticonn, fmt.Errorf("could not forward UDP %s -> %s: %s", local, remote, err)
		}
		if local.IP.IsMulticast() {
			fwUDPmulticonn = conn
		}
	}

	// Reverse UDP forwardings (-reverse-udp): a remote port is forwarded to a local port.
	for _, spec := range splitForwardingSpecs(reverseUDP) {
		local, remote, err := parseUDPForwarding(spec)
		if err != nil {
			return fwUDPmulticonn, fmt.Errorf("UDP reverse parsing error for %q: %s", spec, err)
		}
		if _, err := c.ReverseUDP(ctx, local, remote); err != nil {
			return fwUDPmulticonn, fmt.Errorf("could not reverse UDP %s -> %s: %s", local, remote, err)
		}
	}

	return fwUDPmulticonn, nil
}

func getConfigOptions(hostUrl *url.URL, sshConfig *ssh_config.Config, optionParsers map[client_config.OptionName]client_config.OptionParser) (*client_config.Config, error) {
	urlHostname, urlPort := hostUrl.Hostname(), hostUrl.Port()

	configHostname, configPort, configUser, configUrlPath, configAuthMethods, pluginOptions, err := ssh3.GetConfigForHost(urlHostname, sshConfig, optionParsers)
	if err != nil {
		log.Error().Msgf("Could not get config for %s: %s", urlHostname, err)
		return nil, err
	}

	hostname := configHostname
	if hostname == "" {
		hostname = urlHostname
	}

	port := 443
	if urlPort != "" {
		if parsedPort, err := strconv.Atoi(urlPort); err == nil && parsedPort < 0xffff {
			// There is a port in the CLI and the port is valid. Use the CLI port.
			port = parsedPort
		} else {
			// There is a port in the CLI but it is not valid.
			// use WithLevel(zerolog.FatalLevel) to log a fatal level, but let us handle
			// program termination. log.Fatal() exits with os.Exit(1).
			log.WithLevel(zerolog.FatalLevel).Str("Port", urlPort).Err(err).Msg("cli contains an invalid port")
			fmt.Fprintf(os.Stderr, "Bad port '%s'\n", urlPort)
			return nil, err
		}
	} else if configPort != -1 {
		// There is no port in the CLI, but one in a config file. Use the config port.
		port = configPort
	}

	username := hostUrl.User.Username()
	if username == "" {
		username = hostUrl.Query().Get("user")
	}
	if username == "" {
		username = configUser
	}
	if username == "" {
		u, err := osuser.Current()
		if err == nil {
			username = u.Username
		} else {
			log.Error().Msgf("could not get current username: %s", err)
		}
	}
	if username == "" {
		return nil, fmt.Errorf("no username could be found")
	}

	urlPath := hostUrl.Path
	if urlPath == "" {
		if configUrlPath != "" {
			urlPath = configUrlPath
		} else {
			// default path
			urlPath = "sshoq-server"
		}

	}
	return client_config.NewConfig(username, hostname, port, urlPath, configAuthMethods, pluginOptions)
}

func getConnectionMaterialFromURL(hostUrl *url.URL, sshConfig *ssh_config.Config, cliAuthMethods []interface{}, cliOptions map[client_config.OptionName]client_config.Option, optionParsers map[client_config.OptionName]client_config.OptionParser) (agent.ExtendedAgent, *client_config.Config, error) {
	configOptions, err := getConfigOptions(hostUrl, sshConfig, optionParsers)
	if err != nil {
		return nil, nil, fmt.Errorf("could not apply config to %s: %s", hostUrl, err)
	}

	var agentClient agent.ExtendedAgent
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath != "" {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open SSH_AUTH_SOCK: %s", err)
		}
		agentClient = agent.NewClient(conn)
	}

	var authMethods []interface{}
	authMethods = append(authMethods, cliAuthMethods...)
	authMethods = append(authMethods, configOptions.AuthMethods()...)

	pluginOptionsFromConfig := configOptions.Options()
	for k, v := range cliOptions {
		if _, ok := pluginOptionsFromConfig[k]; ok {
			log.Debug().Msgf("override config option %s by the value provided by the CLI", k)
		}
		pluginOptionsFromConfig[k] = v
	}

	// If an identity file is explicitly provided on the command line (e.g.
	// via -i), it takes precedence over everything else and is the only
	// authentication method that should be used: config-derived IdentityFile
	// entries and their auth methods are discarded so that they cannot be
	// used (for instance as an agent-based pubkey auth fallback).
	if cliIdentityOptions := cliIdentityOptionNames(cliOptions, optionParsers); len(cliIdentityOptions) > 0 {
		authMethods = cliAuthMethods
		for optionName, optionParser := range optionParsers {
			if optionParser.OptionConfigName() != "IdentityFile" {
				continue
			}
			if _, fromCLI := cliIdentityOptions[optionName]; !fromCLI {
				delete(pluginOptionsFromConfig, optionName)
			}
		}
	} else if len(authMethods) == 0 {
		// When no identity is explicitly configured (neither via CLI flags
		// such as -i or -use-password, nor via IdentityFile entries in the
		// ssh config), try the default private keys from ~/.ssh (e.g.
		// ~/.ssh/id_rsa, ~/.ssh/id_ed25519, ...) like OpenSSH does.
		for _, defaultMethod := range ssh3.NewDefaultPrivkeyFileAuthMethods() {
			authMethods = append(authMethods, defaultMethod)
		}
	}

	options, err := client_config.NewConfig(configOptions.Username(), configOptions.Hostname(), configOptions.Port(), configOptions.UrlPath(), authMethods, pluginOptionsFromConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("could not instantiate invalid options: %s", err)
	}
	return agentClient, options, nil
}

// cliIdentityOptionNames returns the set of option names whose value was
// provided on the command line and whose parser is backed by the
// "IdentityFile" config keyword (e.g. the -i flag for private key files).
func cliIdentityOptionNames(cliOptions map[client_config.OptionName]client_config.Option, optionParsers map[client_config.OptionName]client_config.OptionParser) map[client_config.OptionName]bool {
	identityOptions := make(map[client_config.OptionName]bool)
	for optionName, optionParser := range optionParsers {
		if optionParser.OptionConfigName() != "IdentityFile" {
			continue
		}
		if opt, specified := cliOptions[optionName]; specified && opt != nil {
			identityOptions[optionName] = true
		}
	}
	return identityOptions
}

type FlagValue struct {
	pluginOptionName client_config.OptionName
	val              string
	parsedOption     client_config.Option
	client_config.CLIOptionParser
}

func NewFlagValue(optionName client_config.OptionName, parser client_config.CLIOptionParser) *FlagValue {
	return &FlagValue{
		pluginOptionName: optionName,
		CLIOptionParser:  parser,
	}
}

func (v *FlagValue) String() string {
	if v == nil {
		return ""
	}
	return v.val
}

func (v *FlagValue) Set(s string) (err error) {
	if v.CLIOptionParser.IsBoolFlag() {
		switch s {
		case "true":
			s = "yes"
		case "false":
			s = "no"
		default:
			return fmt.Errorf("when parsing a boolean flag, the input should be \"true\" or \"false\"")
		}
	}
	v.val = s
	v.parsedOption, err = v.CLIOptionParser.Parse([]string{s})
	if err != nil {
		return err
	}
	return nil
}

func (v *FlagValue) IsBoolFlag() bool {
	return v.CLIOptionParser.IsBoolFlag()
}

// parseScpArgs splits the two scp-mode arguments into a transfer direction and
// the local/remote paths. The remote argument uses '%' as the separator between
// the sshoq server URL and the remote path, since ':' is already used for the
// port designation
// (e.g. user@host:443/sshoq-server%/tmp/remotefile). When the remote argument
// is args[0] the transfer is a download, otherwise it is an upload.
func parseScpArgs(args []string) (upload bool, localPath, remotePath, urlParam string, err error) {
	if len(args) != 2 {
		return false, "", "", "", fmt.Errorf("scp mode requires exactly two arguments: <local-path> <remote-url> (upload) or <remote-url> <local-path> (download)")
	}
	remoteIdx := -1
	for i, arg := range args {
		if strings.Contains(arg, "%") {
			remoteIdx = i
			break
		}
	}
	if remoteIdx == -1 {
		return false, "", "", "", fmt.Errorf("could not find the remote path separator '%%' in the arguments: the remote argument must look like user@host:443/sshoq-server%%/remote/path")
	}
	urlPathParts := strings.SplitN(args[remoteIdx], "%", 2)
	if urlPathParts[0] == "" || urlPathParts[1] == "" {
		return false, "", "", "", fmt.Errorf("invalid remote argument %q: expected user@host:port/sshoq-server%%/remote/path", args[remoteIdx])
	}
	if remoteIdx == 1 {
		// upload: local source is args[0], remote destination is args[1]
		return true, args[0], urlPathParts[1], urlPathParts[0], nil
	}
	// download: remote source is args[0], local destination is args[1]
	return false, args[1], urlPathParts[1], urlPathParts[0], nil
}

func ClientMain() int {
	internal.CloseClientPluginsRegistry()
	internal.CloseServerPluginsRegistry()

	// for other auth-related CLI args, go see auth/plugins, as they define plugin-specific auth CLI args and config options, such a pubkey/privkey-based auth
	keyLogFile := flag.String("keylog", "", "Write QUIC TLS keys and master secret in the specified keylog file: only for debugging purpose")
	passwordAuthentication := flag.Bool("use-password", false, "if set, do classical password authentication")
	insecure := flag.Bool("insecure", false, "if set, skip server certificate verification")
	issuerUrl := flag.String("use-oidc", "", "if set, force the use of OpenID Connect with the specified issuer url as parameter (it opens a browser window)")
	oidcConfigFileName := flag.String("oidc-config", "", "OpenID Connect json config file containing the \"client_id\" and \"client_secret\" fields needed for most identity providers")
	verbose := flag.Bool("v", false, "if set, enable verbose mode")
	displayVersion := flag.Bool("version", false, "if set, displays the software version on standard output and exit")
	noPKCE := flag.Bool("no-pkce", false, "if set perform PKCE challenge-response with oidc")
	forcePTYAlloc := flag.Bool("force-pty", false, "if set, forces PTY allocation before command execution. Useful for interactive programs.")
	forwardSSHAgent := flag.Bool("forward-agent", false, "if set, forwards ssh agent to be used with sshv2 connections on the remote host")
	var forwardTCP stringSliceFlag
	var forwardUDP stringSliceFlag
	var reverseTCP stringSliceFlag
	var reverseUDP stringSliceFlag
	flag.Var(&forwardTCP, "forward-tcp", "forward a remote TCP port to a local port. Syntax same as SSH2 but with @ instead of : (e.g. 8080@::1@80 or 8080@192.168.1.1@80). May be specified multiple times.")
	flag.Var(&forwardUDP, "forward-udp", "forward a remote UDP port to a local port. Syntax same as SSH2 but with @ instead of : (e.g. 5353@::1@53). May be specified multiple times.")
	flag.Var(&reverseTCP, "reverse-tcp", "reverse forward a local TCP port to a remote port. Syntax same as SSH2 but with @ instead of : (e.g. 80@127.0.0.1@8080). May be specified multiple times.")
	flag.Var(&reverseUDP, "reverse-udp", "reverse forward a local UDP port to a remote port. Syntax same as SSH2 but with @ instead of : (e.g. 53@127.0.0.1@5353). May be specified multiple times.")
	flag.Var(&forwardTCP, "L", "alias for -forward-tcp (may be specified multiple times)")
	flag.Var(&reverseTCP, "R", "alias for -reverse-tcp (may be specified multiple times)")
	proxyJump := flag.String("proxy-jump", "", "if set, performs a proxy jump using the specified remote host as proxy (requires server with version >= 0.1.5)")
	sftpMode := flag.Bool("sftp", false, "if set, start an interactive SFTP session")
	scpMode := flag.Bool("scp", false, "if set, copy files to or from the remote host non-interactively, like scp")
	scpRecursive := flag.Bool("r", false, "if set with -scp, recursively copy directories")

	var flagValues []*FlagValue
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if *verbose && os.Getenv("SSH3_LOG_LEVEL") != "trace" {
		util.ConfigureLogger("debug")
	} else {
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))
	}

	cliParsers, err := internal.GetPluginsCLIArgs()
	if err != nil {
		log.Error().Msgf("error when retrieving plugins-defined CLI args: %s", err)
		return -1
	}
	for name, parser := range cliParsers {
		log.Debug().Msgf("Adding plugin-provided CLI arg: \"%s\"", parser.FlagName())
		flagValue := NewFlagValue(name, parser)
		flagValues = append(flagValues, flagValue)
		flag.Var(flagValue, parser.FlagName(), parser.Usage())
	}

	flag.Parse()
	args := flag.Args()

	if *displayVersion {
		fmt.Fprintln(os.Stdout, filepath.Base(os.Args[0]), "version", ssh3.GetCurrentSoftwareVersion())
		return 0
	}

	cliOptions := make(map[client_config.OptionName]client_config.Option)
	// gather the parsed CLI options (only options that were actually provided
	// on the command line; for unset flags, parsedOption is nil and must not
	// be stored, otherwise it would shadow config-derived options and be
	// mistaken for an explicitly specified identity)
	for _, v := range flagValues {
		if v.parsedOption != nil {
			cliOptions[v.pluginOptionName] = v.parsedOption
		}
	}

	useOIDC := *issuerUrl != ""

	ssh3Dir := path.Join(homedir(), ".ssh3")
	os.MkdirAll(ssh3Dir, 0700)

	if len(args) == 0 {
		log.Error().Msgf("no remote host specified, exit")
		flag.Usage()
		os.Exit(-1)
	}

	log.Debug().Msgf("version %s", ssh3.GetCurrentSoftwareVersion())

	if *noPKCE {
		log.Warn().Msgf("Disabling PKCE is considered insecure to machine-in-the-middle attacks. Consider enabling PKCE by default!")
	}

	knownHostsPath := path.Join(ssh3Dir, "known_hosts")
	knownHosts, skippedLines, err := ssh3.ParseKnownHosts(knownHostsPath)
	if len(skippedLines) != 0 {
		stringSkippedLines := []string{}
		for _, lineNumber := range skippedLines {
			stringSkippedLines = append(stringSkippedLines, fmt.Sprintf("%d", lineNumber))
		}
		log.Warn().Msgf("the following lines in %s are invalid: %s", knownHostsPath, strings.Join(stringSkippedLines, ", "))
	}
	if err != nil {
		log.Error().Msgf("there was an error when parsing known hosts: %s", err)
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		tty = nil
	}

	// In scp mode, one of the two arguments is the remote URL. It uses '%' to
	// separate the sshoq server URL from the remote path, since ':' is already
	// used for the port designation
	// (e.g. user@host:443/sshoq-server%/tmp/remotefile).
	var scpUpload bool
	var scpLocalPath, scpRemotePath string
	urlFromParam := args[0]
	command := args[1:]
	if *scpMode {
		if *sftpMode {
			log.Error().Msgf("cannot use -sftp and -scp at the same time")
			return -1
		}
		var err error
		scpUpload, scpLocalPath, scpRemotePath, urlFromParam, err = parseScpArgs(args)
		if err != nil {
			log.Error().Msgf("%s", err)
			return -1
		}
	}
	if !strings.HasPrefix(urlFromParam, "https://") {
		urlFromParam = fmt.Sprintf("https://%s", urlFromParam)
	}

	var fwUDPmulticonn *net.UDPConn
	fwUDPmulticonn = nil

	var sshConfig *ssh_config.Config
	var configBytes []byte
	configPath := path.Join(homedir(), ".ssh", "config")
	configBytes, err = os.ReadFile(configPath)
	if err == nil {
		sshConfig, err = ssh_config.DecodeBytes(configBytes)
		if err != nil {
			log.Warn().Msgf("could not parse %s: %s, ignoring config", configPath, err)
			sshConfig = nil
		}
	} else if !os.IsNotExist(err) {
		log.Warn().Msgf("could not open %s: %s, ignoring config", configPath, err)
		sshConfig = nil
	}

	// default to oidc if no password or privkey
	var oidcConfig oidc.OIDCIssuerConfig = nil
	var oidcConfigFile *os.File = nil
	if *oidcConfigFileName == "" {
		defaultFileName := path.Join(ssh3Dir, "oidc_config.json")
		log.Debug().Msgf("no OIDC config file specified, use default file: %s", defaultFileName)
		oidcConfigFile, err = os.Open(defaultFileName)
		if os.IsNotExist(err) {
			log.Debug().Msgf("%s does not exist", defaultFileName)
		} else if err != nil {
			log.Warn().Msgf("could not open %s: %s", defaultFileName, err.Error())
		}
	} else {
		log.Debug().Msgf("open OIDC config from %s", *oidcConfigFileName)
		oidcConfigFile, err = os.Open(*oidcConfigFileName)
		if err != nil {
			log.Error().Msgf("could not open %s: %s", *oidcConfigFileName, err.Error())
			return -1
		}
	}

	if oidcConfigFile != nil {
		data, err := io.ReadAll(oidcConfigFile)
		if err != nil {
			log.Error().Msgf("could not read oidc config file: %s", err.Error())
			return -1
		}
		if err = json.Unmarshal(data, &oidcConfig); err != nil {
			log.Error().Msgf("could not parse oidc config file: %s", err.Error())
			return -1
		}
		log.Debug().Msgf("successfully parsed OIDC config")
	}

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal().Msgf("%s", err)
		}
		defer f.Close()
		keyLog = f
	}

	var cliAuthMethods []interface{}
	// Only do privkey and agent auth if OIDC is not asked explicitly
	if !useOIDC {
		if *passwordAuthentication {
			cliAuthMethods = append(cliAuthMethods, ssh3.NewPasswordAuthMethod())
		}
	} else {
		// for now, only perform OIDC if it was explicitly asked by the user
		if *issuerUrl != "" {
			log.Debug().Msgf("add OIDC auth, %d issuers in configs", len(oidcConfig))
			for _, issuerConfig := range oidcConfig {
				if *issuerUrl == issuerConfig.IssuerUrl {
					log.Debug().Msgf("found issuer %s matching the issuer specified in the command-line", issuerConfig.IssuerUrl)
					cliAuthMethods = append(cliAuthMethods, ssh3.NewOidcAuthMethod(!*noPKCE, issuerConfig))
				} else {
					log.Debug().Msgf("issuer %s does not match issuer URL %s specified in the command-line", issuerConfig.IssuerUrl, *issuerUrl)
				}
			}
		} else {
			log.Error().Msgf("OIDC was asked explicitly but did not find suitable issuer URL")
			return -1
		}
	}

	parsedUrl, err := url.Parse(urlFromParam)
	if err != nil {
		log.Error().Msgf("could not parse URL: %s", err)
		return -1
	}

	ctx := context.Background()

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}

	optionsParsers, err := internal.GetPluginsClientOptionsParsers()
	if err != nil {
		log.Error().Msgf("Could not get plugins options parsers: %s", err)
		return -1
	}
	agentClient, options, err := getConnectionMaterialFromURL(parsedUrl, sshConfig, cliAuthMethods, cliOptions, optionsParsers)
	if err != nil {
		log.Error().Msgf("Could not get connection material for %s: %s", parsedUrl, err)
		return -1
	}

	if *proxyJump == "" && sshConfig != nil {
		*proxyJump, err = sshConfig.Get(parsedUrl.Hostname(), "UDPProxyJump")
		if err != nil {
			log.Error().Msgf("Could not get UDPProxyJump config value: %s", err)
			return -1
		}
	}

	var proxyAddress *net.UDPAddr
	if *proxyJump != "" {
		if !strings.HasPrefix(*proxyJump, "https://") {
			*proxyJump = fmt.Sprintf("https://%s", *proxyJump)
		}
		proxyParsedUrl, err := url.Parse(*proxyJump)
		if err != nil {
			log.Error().Msgf("Could not parse proxy host URL %s: %s", *proxyJump, err)
			return -1
		}
		proxyAgentClient, proxyOptions, err := getConnectionMaterialFromURL(proxyParsedUrl, sshConfig, cliAuthMethods, cliOptions, optionsParsers)
		if err != nil {
			log.Error().Msgf("Could not get connection material for proxy %s: %s", proxyParsedUrl, err)
			return -1
		}
		qconn, status := setupQUICConnection(ctx, *insecure, keyLog, ssh3Dir, pool, knownHostsPath, knownHosts, oidcConfig, proxyOptions, nil, tty)

		if qconn == nil && status != 0 {
			log.Error().Msgf("could not setup transport for proxy client.")
			return status
		} else if qconn == nil && status == 0 {
			// reconnect due to likely first time self signed cert error
			log.Info().Msgf("re-parsing known hosts and reconnecting via jump host now..")
			knownHosts, _, parsingErr := ssh3.ParseKnownHosts(knownHostsPath)
			if parsingErr != nil {
				log.Error().Msgf("Error parsing known hosts file (%s): %s", knownHostsPath, parsingErr)
				return -1
			}
			qconn, status = setupQUICConnection(ctx, *insecure, keyLog, ssh3Dir, pool, knownHostsPath, knownHosts, oidcConfig, proxyOptions, nil, tty)
		}
		// reconnect status
		if qconn == nil {
			log.Error().Msgf("Still could not connect through proxy client.")
			return status
		}

		roundTripper := &http3.RoundTripper{
			EnableDatagrams: true,
		}

		proxyClient, err := client.Dial(ctx, proxyOptions, qconn, roundTripper, proxyAgentClient)
		if err != nil {
			log.Error().Msgf("could not establish SSH3 proxy conversation: %s", err)
			return -1
		}

		baseAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if err != nil {
			log.Error().Msgf("Could not resolve 127.0.0.1:0: %s", err)
			return -1
		}
		remoteAddr, err := net.ResolveUDPAddr("udp", options.URLHostnamePort())
		if err != nil {
			log.Error().Msgf("Could not resolve remote address %s: %s", options.URLHostnamePort(), err)
			return -1
		}
		addr, _, err := proxyClient.ForwardUDP(ctx, baseAddr, remoteAddr, fwUDPmulticonn)
		if err != nil {
			log.Error().Msgf("Could not forward UDP for proxy jump: %s", err)
			return -1
		}
		proxyAddress = addr
		log.Debug().Msgf("started proxy jump at %s", proxyAddress)
	}

	qconn, status := setupQUICConnection(ctx, *insecure, keyLog, ssh3Dir, pool, knownHostsPath, knownHosts, oidcConfig, options, proxyAddress, tty)

	if qconn == nil && status != 0 {
		log.Error().Msgf("could not setup transport for client.")
		return status
	} else if qconn == nil && status == 0 {
		// reconnect
		log.Info().Msgf("re-parsing known hosts and reconnecting now..")
		knownHosts, _, parsingErr := ssh3.ParseKnownHosts(knownHostsPath)
		if parsingErr != nil {
			log.Error().Msgf("Error parsing known hosts file (%s): %s", knownHostsPath, parsingErr)
			return -1
		}
		qconn, status = setupQUICConnection(ctx, *insecure, keyLog, ssh3Dir, pool, knownHostsPath, knownHosts, oidcConfig, options, proxyAddress, tty)
	}
	if qconn == nil {
		if status != 0 {
			log.Error().Msgf("Still could not setup transport for client: %s", err)
		}
		return status
	}

	roundTripper := &http3.RoundTripper{
		EnableDatagrams: true,
	}

	c, err := client.Dial(ctx, options, qconn, roundTripper, agentClient)
	if err != nil {
		log.Error().Msgf("could not dial %s: %s", options.CanonicalHostFormat(), err)
		return -1
	}
	// Set up all requested local and remote port forwardings. Multiple -L, -R,
	// -forward-tcp, -forward-udp, -reverse-tcp and -reverse-udp flags can now
	// be combined freely, including a mix of TCP and UDP.
	fwUDPmulticonn, err = setupForwardings(ctx, c, forwardTCP, reverseTCP, forwardUDP, reverseUDP, fwUDPmulticonn)
	if err != nil {
		log.Error().Msgf("%s", err)
		return -1
	}

	if *sftpMode {
		err = sshoqsftp.RunInteractiveClient(c)
	} else if *scpMode {
		err = sshoqsftp.RunScpClient(c, scpUpload, *scpRecursive, scpLocalPath, scpRemotePath)
	} else {
		err = c.RunSession(tty, *forwardSSHAgent, *forcePTYAlloc, command...)
	}
	switch sessionError := err.(type) {
	case client.ExitStatus:
		log.Info().Msgf("the process exited with status %d", sessionError.StatusCode)
		return sessionError.StatusCode
	case client.ExitSignal:
		log.Error().Msgf("the process exited with signal %s: %s", sessionError.Signal, sessionError.ErrorMessageUTF8)
		return -1
	default:
		if err != nil {
			log.Error().Msgf("an error was encountered when running the session: %s", sessionError)
			return -1
		}
		return 0
	}
}

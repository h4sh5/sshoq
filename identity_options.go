package ssh3

import (
	"fmt"
	"net"
	"strings"
)

// IdentityOptions holds the OpenSSH-style options attached to an
// "authorized_keys" / "authorized_identities" line, i.e. the restrictions the
// user who owns the file asked for and which the server is expected to honour.
//
// They are parsed once, when the identity line is read, attached to the
// conversation which authenticated with that identity (see
// Conversation.SetIdentityOptions) and then enforced by the session layer.
// An option which cannot be enforced must make the identity line be refused:
// silently ignoring it would grant the user more rights than the file asks for.
type IdentityOptions struct {
	// ForcedCommand is the OpenSSH "command=" option: it replaces whatever the
	// client asks the server to run.
	ForcedCommand string
	// From is the OpenSSH "from=" option: a list of source address patterns
	// (address, CIDR, or a glob over the textual address), optionally prefixed
	// with "!" to exclude one. Hostname patterns are not supported: matching a
	// hostname would require a (cacheable, spoofable) DNS lookup, so a pattern
	// which is not an address simply never matches.
	From []string
	// NoPty is the "no-pty" option, set by "restrict".
	NoPty bool
	// NoPortForwarding is the "no-port-forwarding" option, set by "restrict".
	NoPortForwarding bool
	// NoAgentForwarding is the "no-agent-forwarding" option, set by "restrict".
	NoAgentForwarding bool
	// NoX11Forwarding is the "no-x11-forwarding" option, set by "restrict".
	NoX11Forwarding bool
	// NoEnv forbids the client from adding environment variables to the session
	// ("env" channel request). It is set by "restrict", which disables the
	// forwarding of the environment.
	NoEnv bool
}

// enforcesOptions lets the server know that an identity verifier was built from
// an identity line carrying options which the session layer must enforce.
type EnforcesOptions interface {
	IdentityOptions() *IdentityOptions
}

// ParseIdentityOptions parses the options of an authorized_keys-style line, as
// returned by ssh.ParseAuthorizedKey. It returns nil when the line carries no
// option. It returns an error for an option this server does not enforce: an
// administrator who asks for a restriction must never get a key which silently
// ignores it.
func ParseIdentityOptions(options []string) (*IdentityOptions, error) {
	if len(options) == 0 {
		return nil, nil
	}
	opts := &IdentityOptions{}
	sawOne := false
	for _, option := range options {
		option = strings.TrimSpace(option)
		if option == "" {
			continue
		}
		sawOne = true
		name, value := option, ""
		hasValue := false
		if i := strings.IndexByte(option, '='); i > 0 {
			name, value, hasValue = option[:i], unquoteIdentityOptionValue(option[i+1:]), true
		}
		// OpenSSH spells one of its options with a capital - "no-X11-forwarding" - and an
		// administrator copying that spelling out of sshd(8) must get the restriction they
		// asked for, not a key which stops working. Matching the name case-insensitively can
		// only ever apply a restriction which was meant, never lift one: every name below
		// restricts something.
		switch strings.ToLower(name) {
		case "command":
			if !hasValue || value == "" {
				return nil, fmt.Errorf("invalid command=\"...\" option: the command is missing")
			}
			if opts.ForcedCommand != "" {
				return nil, fmt.Errorf("duplicate command=\"...\" option")
			}
			opts.ForcedCommand = value
		case "from":
			if !hasValue || value == "" {
				return nil, fmt.Errorf("invalid from=\"...\" option: the address list is missing")
			}
			for _, pattern := range strings.Split(value, ",") {
				pattern = strings.TrimSpace(pattern)
				if pattern == "" {
					return nil, fmt.Errorf("invalid from=\"...\" option: empty address pattern")
				}
				opts.From = append(opts.From, pattern)
			}
		case "restrict":
			opts.NoPty = true
			opts.NoPortForwarding = true
			opts.NoAgentForwarding = true
			opts.NoX11Forwarding = true
			opts.NoEnv = true
		case "no-pty":
			opts.NoPty = true
		case "no-port-forwarding":
			opts.NoPortForwarding = true
		case "no-agent-forwarding":
			opts.NoAgentForwarding = true
		case "no-x11-forwarding":
			opts.NoX11Forwarding = true
		default:
			// the option is known to OpenSSH but not to sshoq (environment=,
			// permitopen=, tunnel=, no-touch-required, verify-required, ...), or is
			// unknown: it cannot be enforced, so the identity is refused rather than
			// accepted with a restriction which silently does nothing
			return nil, fmt.Errorf("authorized identity option %q is not enforced by sshoq: refusing the identity "+
				"instead of silently ignoring the restriction (supported options: command, from, restrict, no-pty, "+
				"no-port-forwarding, no-agent-forwarding, no-X11-forwarding)", name)
		}
	}
	if !sawOne {
		return nil, nil
	}
	return opts, nil
}

// unquoteIdentityOptionValue removes the double quotes of an option value and the
// backslash escapes they allow, like OpenSSH does.
func unquoteIdentityOptionValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		value = value[1 : len(value)-1]
		var b strings.Builder
		b.Grow(len(value))
		for i := 0; i < len(value); i++ {
			if value[i] == '\\' && i+1 < len(value) {
				i++
				switch value[i] {
				case '"', '\\', ',':
					b.WriteByte(value[i])
				default:
					b.WriteByte('\\')
					b.WriteByte(value[i])
				}
				continue
			}
			b.WriteByte(value[i])
		}
		value = b.String()
	}
	return value
}

// parsePeerIP extracts the IP of a peer address given as a string, generally
// "ip:port" as http.Request.RemoteAddr is set by the HTTP/3 server.
func parsePeerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

// matchesSourcePattern tells whether ip is described by a single "from=" pattern:
// an address, a CIDR block, or a glob over the textual address. A pattern naming a
// host does not match anything: no DNS lookup is performed.
func matchesSourcePattern(pattern string, ip net.IP) bool {
	if pattern == "" || ip == nil {
		return false
	}
	if _, network, err := net.ParseCIDR(pattern); err == nil {
		return network.Contains(ip)
	}
	if !strings.ContainsAny(pattern, "*?[") {
		if parsed := net.ParseIP(pattern); parsed != nil {
			// net.IP.Equal handles the IPv4-in-IPv6 forms
			return ip.Equal(parsed)
		}
		return false
	}
	// glob over the textual representation, in both the IPv4 and IPv6 forms when
	// the address may be written either way
	texts := []string{ip.String()}
	if v4 := ip.To4(); v4 != nil {
		texts = []string{v4.String(), ip.String()}
	}
	for _, text := range texts {
		if matchGlob(pattern, text) {
			return true
		}
	}
	return false
}

// matchGlob is OpenSSH's match_pattern(): "*" stands for any sequence, "?" for a single
// character. It is applied to the textual address only (never to the port and never to a
// hostname), which is what "from=" globs mean here.
func matchGlob(pattern, text string) bool {
	var rec func(p, t string) bool
	rec = func(p, t string) bool {
		for len(p) > 0 {
			switch p[0] {
			case '*':
				// a star stands for anything: try the rest of the pattern after every
				// possible prefix of t, as OpenSSH does
				for i := 0; ; i++ {
					if rec(p[1:], t[i:]) {
						return true
					}
					if i >= len(t) {
						return false
					}
				}
			case '?':
				if len(t) == 0 {
					return false
				}
				p, t = p[1:], t[1:]
			default:
				if len(t) == 0 || t[0] != p[0] {
					return false
				}
				p, t = p[1:], t[1:]
			}
		}
		return len(t) == 0
	}
	return rec(pattern, text)
}

// CheckSource enforces the "from=" option: it returns an error when the peer
// address is not one the identity accepts. It fails closed: a missing or
// unparsable source address is refused.
func (o *IdentityOptions) CheckSource(remoteAddr string) error {
	if o == nil || len(o.From) == 0 {
		return nil
	}
	ip := parsePeerIP(remoteAddr)
	if ip == nil {
		return fmt.Errorf("cannot determine the source address of the peer, which is required by the from=\"...\" restriction of this identity")
	}
	accepted := false
	for _, pattern := range o.From {
		negated := strings.HasPrefix(pattern, "!")
		trimmed := strings.TrimPrefix(pattern, "!")
		if matchesSourcePattern(trimmed, ip) {
			if negated {
				return fmt.Errorf("source address %s is excluded by the from=\"...\" restriction of this identity", ip)
			}
			accepted = true
		}
	}
	if !accepted {
		return fmt.Errorf("source address %s is not allowed by the from=\"...\" restriction of this identity", ip)
	}
	return nil
}

// CheckChannelOpen tells whether a channel of the given type may be opened by a
// client which authenticated with this identity.
func (o *IdentityOptions) CheckChannelOpen(channelType string) error {
	if o == nil {
		return nil
	}
	// some channel types carry extra data after a comma, e.g.
	// "open-request-reverse-tcp,<address>"
	family := channelType
	if i := strings.IndexByte(family, ','); i >= 0 {
		family = family[:i]
	}
	switch family {
	case "direct-tcp", "direct-udp", "request-reverse-tcp", "request-reverse-udp", "open-request-reverse-tcp", "open-request-reverse-udp":
		if o.NoPortForwarding {
			return fmt.Errorf("port forwarding is forbidden by the identity which authenticated this conversation")
		}
		if o.ForcedCommand != "" {
			return fmt.Errorf("the identity which authenticated this conversation is restricted to the command \"%s\": forwarding is not available", o.ForcedCommand)
		}
	case "sftp":
		if o.ForcedCommand != "" {
			return fmt.Errorf("the identity which authenticated this conversation is restricted to the command \"%s\": the sftp subsystem is not available", o.ForcedCommand)
		}
	}
	return nil
}

// CheckRequest tells whether a channel request is permitted. requestType is the type
// as announced on the wire (see message.ChannelRequest.RequestTypeStr), plus the
// pseudo-type "agent-forwarding" for the agent forwarding handshake.
func (o *IdentityOptions) CheckRequest(requestType string) error {
	if o == nil {
		return nil
	}
	switch requestType {
	case "pty-req":
		if o.NoPty {
			return fmt.Errorf("a terminal was requested but the identity which authenticated this conversation forbids it (no-pty)")
		}
	case "env":
		if o.NoEnv {
			return fmt.Errorf("the identity which authenticated this conversation forbids setting environment variables (restrict)")
		}
	case "x11-req":
		if o.NoX11Forwarding {
			return fmt.Errorf("X11 forwarding is forbidden by the identity which authenticated this conversation")
		}
	case "agent-forwarding":
		if o.NoAgentForwarding {
			return fmt.Errorf("agent forwarding is forbidden by the identity which authenticated this conversation")
		}
	}
	return nil
}

// SetIdentityOptions attaches the restrictions of the identity which authenticated
// this conversation to it, so that the session layer can enforce them. It must be
// called once, right after the authentication succeeded and before any channel is
// handled.
func (c *Conversation) SetIdentityOptions(options *IdentityOptions) {
	c.identityOptionsMutex.Lock()
	defer c.identityOptionsMutex.Unlock()
	c.identityOptions = options
}

// IdentityOptions returns the restrictions carried by the identity which
// authenticated this conversation, or nil when the identity was unrestricted.
func (c *Conversation) IdentityOptions() *IdentityOptions {
	c.identityOptionsMutex.Lock()
	defer c.identityOptionsMutex.Unlock()
	return c.identityOptions
}

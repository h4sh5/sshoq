package ssh3

import (
	"net"
	"testing"
)

func TestParseIdentityOptions(t *testing.T) {
	t.Run("no option", func(t *testing.T) {
		opts, err := ParseIdentityOptions(nil)
		if err != nil || opts != nil {
			t.Fatalf("expected no options, got %+v (err %v)", opts, err)
		}
	})

	t.Run("restrict disables everything", func(t *testing.T) {
		opts, err := ParseIdentityOptions([]string{"restrict"})
		if err != nil {
			t.Fatal(err)
		}
		if opts == nil || !opts.NoPty || !opts.NoPortForwarding || !opts.NoAgentForwarding || !opts.NoX11Forwarding || !opts.NoEnv {
			t.Fatalf("restrict did not disable everything: %+v", opts)
		}
	})

	// ssh.ParseAuthorizedKey splits the options on the commas which are outside quotes,
	// so a command containing a comma arrives as one element with its quotes still on it
	t.Run("command with quoted comma", func(t *testing.T) {
		opts, err := ParseIdentityOptions([]string{`command="/usr/bin/echo a,b"`, `no-pty`})
		if err != nil {
			t.Fatal(err)
		}
		if opts.ForcedCommand != "/usr/bin/echo a,b" {
			t.Fatalf("bad forced command: %q", opts.ForcedCommand)
		}
		if !opts.NoPty {
			t.Fatal("no-pty lost")
		}
	})

	t.Run("duplicate command refused", func(t *testing.T) {
		if _, err := ParseIdentityOptions([]string{`command="a"`, `command="b"`}); err == nil {
			t.Fatal("expected an error for a duplicate command= option")
		}
	})

	// an option nobody enforces must never look like a working restriction
	t.Run("unenforced option refuses the identity", func(t *testing.T) {
		for _, option := range []string{"environment=\"FOO=bar\"", "tunnel=5", "permitopen=\"localhost:22\""} {
			if _, err := ParseIdentityOptions([]string{option}); err == nil {
				t.Fatalf("option %q should have been refused", option)
			}
		}
	})
}

func TestIdentityOptionsCheckSource(t *testing.T) {
	opts := &IdentityOptions{From: []string{"192.168.0.0/16", "10.0.0.*", "!10.0.0.66"}}
	t.Run("in cidr", func(t *testing.T) {
		if err := opts.CheckSource("192.168.1.10:44443"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("glob", func(t *testing.T) {
		if err := opts.CheckSource("10.0.0.7:44443"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("excluded by negated pattern", func(t *testing.T) {
		if err := opts.CheckSource("10.0.0.66:44443"); err == nil {
			t.Fatal("the address excluded by !10.0.0.66 was accepted")
		}
	})
	t.Run("unrelated address refused", func(t *testing.T) {
		if err := opts.CheckSource("[2001:db8::1]:44443"); err == nil {
			t.Fatal("an address which is in none of the from= patterns was accepted")
		}
	})
	t.Run("outside", func(t *testing.T) {
		if err := opts.CheckSource("203.0.113.7:44443"); err == nil {
			t.Fatal("an address outside from= was accepted")
		}
	})
	t.Run("unparsable source fails closed", func(t *testing.T) {
		if err := opts.CheckSource("unknown"); err == nil {
			t.Fatal("a peer address which cannot be read must be refused")
		}
	})
	t.Run("hostname pattern never matches", func(t *testing.T) {
		hostnames := &IdentityOptions{From: []string{"*.trusted.example.org"}}
		ip := net.ParseIP("192.0.2.1")
		if err := hostnames.CheckSource(ip.String() + ":443"); err == nil {
			t.Fatal("a hostname pattern must not match an address: it would need a spoofable DNS lookup")
		}
	})
	t.Run("no from option allows anybody", func(t *testing.T) {
		var nilOptions *IdentityOptions
		if err := nilOptions.CheckSource("203.0.113.7:443"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIdentityOptionsCheckChannelOpen(t *testing.T) {
	restricted := &IdentityOptions{NoPortForwarding: true}
	for _, channelType := range []string{"direct-tcp", "direct-udp", "open-request-reverse-tcp,127.0.0.1:1111"} {
		if err := restricted.CheckChannelOpen(channelType); err == nil {
			t.Fatalf("forwarding channel %q should be refused", channelType)
		}
	}
	if err := restricted.CheckChannelOpen("session"); err != nil {
		t.Fatalf("a session must stay possible: %s", err)
	}

	forced := &IdentityOptions{ForcedCommand: "/usr/bin/true"}
	if err := forced.CheckChannelOpen("sftp"); err == nil {
		t.Fatal("the sftp subsystem must not be available on a key restricted to a command")
	}
	if err := forced.CheckChannelOpen("direct-tcp"); err == nil {
		t.Fatal("forwarding must not be available on a key restricted to a command")
	}
}

func TestIdentityOptionsCheckRequest(t *testing.T) {
	restricted := &IdentityOptions{NoPty: true, NoAgentForwarding: true, NoEnv: true, NoX11Forwarding: true}
	for _, requestType := range []string{"pty-req", "env", "x11-req", "agent-forwarding"} {
		if err := restricted.CheckRequest(requestType); err == nil {
			t.Fatalf("%s should be refused", requestType)
		}
	}
	var unrestricted *IdentityOptions
	if err := unrestricted.CheckRequest("pty-req"); err != nil {
		t.Fatal(err)
	}
	// a request which carries no restriction is never refused
	if err := restricted.CheckRequest("shell"); err != nil {
		t.Fatal(err)
	}
}

func TestUnquoteIdentityOptionValue(t *testing.T) {
	cases := map[string]string{
		`"/usr/bin/echo \"hi\""`: `/usr/bin/echo "hi"`,
		`/usr/bin/true`:          `/usr/bin/true`,
		`"a\\b"`:                 `a\b`,
	}
	for in, expected := range cases {
		if got := unquoteIdentityOptionValue(in); got != expected {
			t.Errorf("unquote(%s) = %q, expected %q", in, got, expected)
		}
	}
}

func TestMatchGlob(t *testing.T) {
	if !matchGlob("10.0.0.*", "10.0.0.77") {
		t.Fatal("should match")
	}
	if !matchGlob("10.0.*", "10.0.99.1") {
		t.Fatal("a star matches any sequence, as OpenSSH does")
	}
	if matchGlob("192.168.1.1", "192.168.1.2") {
		t.Fatal("a literal pattern must not match another address")
	}
	if !matchGlob("10.0.?.7", "10.0.4.7") {
		t.Fatal("? should match a single character")
	}
	if matchGlob("10.0.?.7", "10.0.44.7") {
		t.Fatal("? must match exactly one character")
	}
	if matchGlob("", "10.0.0.1") || !matchGlob("", "") {
		t.Fatal("an empty pattern matches the empty text only")
	}
}

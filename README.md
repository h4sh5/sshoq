# SSHOQ: faster and rich secure shell using QUIC and HTTP/3

This repo is a fork of https://github.com/francoismichel/ssh3 as the original repo seems quite abandoned. A number of community PRs has been merged into this fork and light maintenance of this repo will resume going forward. Please still raise your issues in the original repo, but feel free to PR here.

The renaming to "SSHOQ" (SSH Over QUIC) which is a better, easily pronounceable name that specifies that this is different software to SSH, not a next version of SSH.

The renaming of some source code has already begun, but for stability reasons "ssh3" has not been completely ripped out of the code yet.

**SSHOQ is a fork** of SSH3, is a complete revisit of the SSH protocol, mapping its semantics on top of the HTTP mechanisms. It comes from our research work and we (researchers) recently proposed it as an [Internet-Draft](https://www.ietf.org/how/ids/) ([draft-michel-remote-terminal-http3-00](https://datatracker.ietf.org/doc/draft-michel-remote-terminal-http3/)).

In a nutshell, SSHOQ uses [QUIC](https://datatracker.ietf.org/doc/html/rfc9000)+[TLS1.3](https://datatracker.ietf.org/doc/html/rfc8446) for
secure channel establishment and the [HTTP Authorization](https://www.rfc-editor.org/rfc/rfc9110.html#name-authorization) mechanisms for user authentication.
Among others, SSHOQ allows the following improvements:
- Significantly faster session establishment
- The server endpoint can be hidden (by a long URL path)
- New HTTP authentication methods such as [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) and [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) in addition to classical SSH authentication
- Robustness to port scanning attacks: your SSHOQ server can be made **invisible** to other Internet users
- UDP port forwarding in addition to classical TCP port forwarding
- All the features allowed by the modern QUIC protocol: including connection migration (soon) and multipath connections

SSHOQ implements the common password-based and public-key (RSA and EdDSA/ed25519) authentication methods. It also supports new authentication methods such as OAuth 2.0 and allows logging in to your servers using your Google/Microsoft/Github accounts.

### SSHOQ is still experimental
While SSHOQ shows promise for faster session establishment, it is still at an early proof-of-concept stage. As with any new complex protocol, **expert cryptographic review over an extended timeframe is required before reasonable security conclusions can be made**.

We are developing SSHOQ as an open source project to facilitate community feedback and analysis. However, we **cannot yet endorse its appropriateness for production systems** without further peer review. Please collaborate with us if you have relevant expertise!


### OpenSSH features implemented

This SSHOQ implementation already provides many of the popular features of OpenSSH, so if you are used to OpenSSH, the process of adopting SSHOQ will be smooth. Here is a list of some OpenSSH features that SSHOQ also implements:
- Parses `~/.ssh/authorized_keys` on the server
- Certificate-based server authentication
- `known_hosts` mechanism when X.509 certificates are not used.
- Automatically using the `ssh-agent` for public key authentication
- SSH agent forwarding to use your local keys on your remote server
- Direct TCP port forwarding (reverse port forwarding will be implemented in the future)
- Proxy jump (see the `-proxy-jump` parameter). If A is an SSHOQ client and B and C are both SSHOQ servers, you can connect from A to C using B as a gateway/proxy. The proxy uses UDP forwarding to forward the QUIC packets from A to C, so B cannot decrypt the traffic A<->C SSHOQ traffic.
- Parses `~/.ssh/config` on the client and handles the `Hostname`, `User`, `Port` and `IdentityFile` config options (the other options are currently ignored). Also parses a new `UDPProxyJump` that behaves similarly to OpenSSH's `ProxyJump`.

## Community support
Help us progress SSHOQ responsibly! We welcome capable security researchers to review our codebase and provide feedback. Please also connect us with relevant standards bodies to potentially advance SSHOQ through the formal IETF/IRTF processes over time.

With collaborative assistance, we hope to iteratively improve SSHOQ towards safe production readiness. But we cannot credibly make definitive security claims without evidence of extensive expert cryptographic review and adoption by respected security authorities. Let's work together to realize SSHOQ's possibilities!

## Installing SSHOQ

You can either download the last [release binaries](https://github.com/h4sh5/sshoq/releases),
[install it using `go install`](#installing-ssh3-and-sshoq-server-using-go-install) or generate these binaries yourself by compiling the code from source.


### Installing ssh3 and sshoq-server using Go install
```bash
go install github.com/h4sh5/sshoq/cmd/...@latest
```

### Running with Docker

The docker image is published to the Github Container Registry (GHCR) with github actions workflows. You can simply run the client and server like this:

client

```bash
docker run --rm -it ghcr.io/h4sh5/sshoq:main sshoq <args>
```

server

```bash
docker run --rm -it ghcr.io/h4sh5/sshoq:main sshoq-server <args>
```


### Compiling SSHOQ from source
You need a recent [Golang](https://go.dev/dl/) version to do this.
Downloading the source code and compiling the binaries can be done with the following steps:

```bash
git clone https://github.com/h4sh5/sshoq
cd sshoq
make
```

You will find the built client and server binaries in `bin/`


## Deploying an SSHOQ server
Before connecting to your host, you need to deploy an SSHOQ server on it. There is currently
no SSHOQ daemon, so right now, you will have to run the `sshoq-server` executable in background
using `screen` or a similar utility.


> [!NOTE]
> As SSHOQ runs on top of HTTP/3, a server needs an X.509 certificate and its corresponding private key. Public certificates can be generated automatically for your public domain name through Let's Encrypt using the `-generate-public-cert` command-line argument on the server. Alternatively you can generate a self-signed one using the `-generate-selfsigned-cert` command-line argument. Self-signed certificates provide you with similar security guarantees to SSHv2's host keys mechanism, with the same security issue: you may be vulnerable to machine-in-the-middle attacks during your first connection to your server. Using real certificates signed by public certificate authorities such as Let's Encrypt avoids this issue.


Here is the usage of the `sshoq-server` executable:

```
Usage of ./sshoq-server:
  -bind string
        the address:port pair to listen to, e.g. 0.0.0.0:443 (default "[::]:443")
  -cert string
        the filename of the server certificate (or fullchain) (default "./cert.pem")
  -key string
        the filename of the certificate private key (default "./priv.key")
  -enable-password-login
        if set, enable password authentication (disabled by default)
  -generate-public-cert value
        Automatically produce and use a valid public certificate usingLet's Encrypt for the provided domain name. The flag can be used several times to generate several certificates.If certificates have already been generated previously using this flag, they will simply be reused without being regenerated. The public certificates are automatically renewed as long as the server is running. Automatically-generated IP public certificates are not available yet.
  -generate-selfsigned-cert
        if set, generates a self-self-signed cerificate and key that will be stored at the paths indicated by the -cert and -key args (they must not already exist)
  -url-path string
        the secret URL path on which the ssh3 server listens (default "/ssh3-term")
  -v    verbose mode, if set
  -version
        if set, displays the software version on standard output and exit
```

The following command starts a public SSHOQ server on port 443 with a valid Let's Encrypt public certificate
for domain `my-domain.example.org` and answers to new sessions requests querying the `/ssh3` URL path:

    sshoq-server -generate-public-cert my-domain.example.org -url-path /ssh3

If you don't have a public domain name (i.e. only an IP address), you can either use an existing certificate
for your IP address using the `-cert` and `-key` arguments or generate a self-signed certificate using the
`-generate-selfsigned-cert` argument.

If you have existing certificates and keys, you can run the server as follows to use them=

    sshoq-server -cert /path/to/cert/or/fullchain -key /path/to/cert/private/key -url-path /ssh3

> [!NOTE]
> Similarly to OpenSSH, the server must be run with root priviledges to log in as other users.


### Deploying with systemd

An example systemd file has been provided at [sshoq.service](systemd/sshoq.service) - the command line arguments should be changed to fit your configuration, but overall it just works.


The sshoq-server binary should be copied to /usr/sbin/ for the example systemd configuration to work.

Copy the sshoq.service file to `/etc/systemd/system/sshoq.service` then run:

```sh
sudo systemctl enable sshoq
sudo systemctl start sshoq
sudo systemctl status sshoq
```

That should install the service and start it and show the status.

### Authorized keys and authorized identities
By default, the SSHOQ server will look for identities in the `~/.ssh/authorized_keys` and `~/.ssh3/authorized_identities` files for each user.
`~/.ssh3/authorized_identities` allows new identities such as OpenID Connect (`oidc`) discussed [below](#openid-connect-authentication-still-experimental).
Popular key types such as `rsa`, `ed25519` and keys in the OpenSSH format can be used.

## Using the SSHOQ client
Once you have an SSHOQ server running, you can connect to it using the SSHOQ client similarly to what
you did with your classical SSHv2 tool.

Here is the usage of the `ssh3` executable:

```
Usage of ssh3:
  -pubkey-for-agent string
        if set, use an agent key whose public key matches the one in the specified path
  -privkey string
        private key file
  -use-password
        if set, do classical password authentication
  -forward-agent
        if set, forwards ssh agent to be used with sshv2 connections on the remote host
  -forward-tcp string
        if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport
  -forward-udp string
        if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport
  -proxy-jump string
    	if set, performs a proxy jump using the specified remote host as proxy
  -insecure
        if set, skip server certificate verification
  -keylog string
        Write QUIC TLS keys and master secret in the specified keylog file: only for debugging purpose
  -use-oidc string
        if set, force the use of OpenID Connect with the specified issuer url as parameter
  -oidc-config string
        OpenID Connect json config file containing the "client_id" and "client_secret" fields needed for most identity providers
  -do-pkce
        if set, perform PKCE challenge-response with oidc
  -v    if set, enable verbose mode
```

### Private-key authentication
You can connect to your SSHOQ server at my-server.example.org listening on `/my-secret-path` using the private key located in `~/.ssh/id_rsa` with the following command:

      sshoq -privkey ~/.ssh/id_rsa username@my-server.example.org/my-secret-path

### Agent-based private key authentication
The SSHOQ client works with the OpenSSH agent and uses the classical `SSH_AUTH_SOCK` environment variable to
communicate with this agent. Similarly to OpenSSH, SSHOQ will list the keys provided by the SSH agent
and connect using the first key listen by the agent by default.
If you want to specify a specific key to use with the agent, you can either specify the private key
directly with the `-privkey` argument like above, or specify the corresponding public key using the
`-pubkey-for-agent` argument. This allows you to authenticate in situations where only the agent has
a direct access to the private key but you only have access to the public key.

### Password-based authentication
While discouraged, you can connect to your server using passwords (if explicitly enabled on the `sshoq-server`)
with the following command:

      sshoq -use-password username@my-server.example.org/my-secret-path

### Config-based session establishment
`sshoq` parses your OpenSSH config. Currently, it only handles the `Hostname`; `User`, `Port` and `IdentityFile` OpenSSH options.
It also adds new option only used by SSHOQ, such as `URLPath` or `UDPProxyJump`. `URLPath` allows you to omit the secret URL path in your
SSHOQ command. `UDPProxyJump` allows you to perform SSHOQ (#proxy-jump)[Proxy Jump] and has the same meaning as the `-proxy-jump` command-line argument.
Let's say you have the following lines in your OpenSSH config located in `~/.ssh/config` :
```
IgnoreUnknown URLPath
Host my-server
  HostName 192.0.2.0
  User username
  IdentityFile ~/.ssh/id_rsa
  URLPath /my-secret-path
```

Similarly to what OpenSSH does, the following `sshoq` command will connect you to the SSHOQ server running on 192.0.2.0 on UDP port 443 using public key authentication with the private key located in `.ssh/id_rsa` :

      sshoq my-server/my-secret-path

If you do not want a config-based utilization of SSHOQ, you can read the sections below to see how to use the CLI parameters of `sshoq`.

### OpenID Connect authentication (still experimental)
This feature allows you to connect using an external identity provider such as the one
of your company or any other provider that implements the OpenID Connect standard, such as Google Identity,
Github or Microsoft Entra. The authentication flow is illustrated in the GIF below.

<div align="center">
<img src="resources/figures/ssh3_oidc.gif" width=75%>

*Secure connection without private key using a Google account.*
</div>

The way it connects to your identity provider is configured in a file named `~/.ssh3/oidc_config.json`.
Below is an example `config.json` file for use with a Google account. This configuration file is an array
and can contain several identity providers configurations.
```json
[
    {
        "issuer_url": "https://accounts.google.com",
        "client_id": "<your_client_id>",
        "client_secret": "<your_client_secret>"
    }
]
```
This might change in the future, but currently, to make this feature work with your Google account, you will need to setup a new experimental application in your Google Cloud console and add your email as authorized users.
This will provide you with a `client_id` and a `client_secret` that you can then set in your `~/.ssh3/oidc_config.json`. On the server side, you just have to add the following line in your `~/.ssh3/authorized_identities`:

```
oidc <client_id> https://accounts.google.com <email>
```
We currently consider removing the need of setting the client_id in the `authorized_identities` file in the future.

### Proxy jump
It is often the case that some SSH hosts can only be accessed through a gateway. SSHOQ allows you to perform a Proxy Jump similarly to what is proposed by OpenSSH.
You can connect from A to C using B as a gateway/proxy. B and C must both be running a valid SSHOQ server. This works by establishing UDP port forwarding on B to forward QUIC packets from A to C.
The connection from A to C is therefore fully end-to-end and B cannot decrypt or alter the SSHOQ traffic between A and C.


### File Sharing

For the time being there's no plan for sftp or scp client or server implementations for this project. 

However, file sharing can be done by forwarding the existing sftp-server (part of OpenSSH) on an existing system over TCP port forwarding.

For example, this is how you can use it with [SSHFS](https://github.com/libfuse/sshfs):

#### File Sharing with SSHFS

open a session with tcp local port forwarding (1234 to 1234)

```
sshoq -forward-tcp 1234/127.0.0.1@1234/127.0.0.1  -privkey ~/.ssh/id_rsa -insecure user@192.168.1.2/ssh3-term
```

Then open a sftp-server listener over a localhost port **inside sshoq session** (openssh must be installed for the sftp-server binary to be available, and for the network server use ncat or socat):

```
# ncat
ncat -nkvl 127.0.0.1 1234 -e /usr/lib/openssh/sftp-server
# or socat
socat TCP-LISTEN:1234,reuseaddr,fork,bind=127.0.0.1 EXEC:/usr/lib/openssh/sftp-server
```

(the sftp-server binary may be in different locations depending on your distro, try `find /usr | grep sftp-server` since its usually not on the $PATH)

Finally, use sshfs (>= 3.7.5) to open mount a directory using the directport option

```
sshfs -o directport=1234 127.0.0.1:/home/ /tmp/mnt
```

The performance gains on a local network isn't great; testing on local network shows using sshfs with regular ssh can be faster than sshoq. However over the internet may be a different story.

Even if there're no performance gains, this does enable a method of bulk file transfer over sshoq since there's no builtin sshoq sftp command.


### Local port forwarding

Suppose you have a HTTP server on localhost port 3000 on the remote host, and wants to forward that locally to port 8080 so that you can access it via your browser. Do this with:

`sshoq -forward-tcp 8080/127.0.0.1@3000/127.0.0.1 user@example.com/secret-path`

Similarly, to forward a UDP port (5353) from the remote host to local port 8053:

`sshoq -forward-udp 8053/127.0.0.1@5353/127.0.0.1 user@example.com/secret-path`


### Reverse port forwarding

You can also now perform reverse port forwading to forward a port from localhost to the remote host.

For example, if you want to forward localhost port 3000 to the remote host on port 8080, do this:

`sshoq -reverse-tcp 8080/127.0.0.1@3000/127.0.0.1 user@example.com/secret-path`

Similarly for UDP:

`sshoq -reverse-udp 8080/127.0.0.1@3000/127.0.0.1 user@example.com/secret-path`

Warning: Reverse UDP port forwarding is not well tested and may not be working fully.



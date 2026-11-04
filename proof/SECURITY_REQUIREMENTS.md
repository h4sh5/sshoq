# SSHOQ security requirements catalogue

This document is the contract the formal proofs in `proof/` are written against.
Nothing in `proof/` is "verification for verification's sake": every Gobra file
implements a requirement listed here, and every requirement says exactly which
part of the running server it covers and how far the proof reaches.

Two kinds of guarantee are distinguished, and the difference matters:

* **`proved`** — a Gobra file checks the property deductively over *all* inputs of
  the modelled function (`make proof`). Memory safety (no panic, no out-of-bounds,
  no nil dereference) is proved by Gobra for free on top of the functional specs.
* **`conformant`** — the Gobra model is a transcription of a Go function, so the
  proof is only worth what the transcription is faithful. `proof/conformance_test.go`
  checks, on generated and enumerated inputs, that the model and the real Go
  function agree. `proved + conformant` is the strongest status this repository can
  claim without verifying the production files themselves.

Where a requirement lives in code that Gobra cannot ingest today (QUIC, `x509`,
`net/http`, cgo-backed `unix_util`, OIDC discovery), the requirement is stated
here with an explicit **out of scope** note and the reason. Those parts remain
covered by the ordinary test suite; pretending otherwise would oversell the proof.

Naming: `SR-<AREA>-<nn>`. Areas: `AUTH` (who may get in), `PERM` (what an
authenticated session may do), `TR` (transport and host trust), `RES`
(resource exhaustion / denial of service), `PARSE` (untrusted wire data).

---

## 1. Authentication — `AUTH`

The threat: an unauthenticated peer reaching `handlerFunc`, i.e. being handed a
session (shell, SFTP, forwarding) without having proved who they are.

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-AUTH-01 | A session handler is invoked **only** on a path where a verifier accepted the peer. There is no path to `handlerFunc` that does not first evaluate a verification result to true. | `server_auth/auth.go` (`HandleAuths`, `HandleBasicAuth`), `server_auth/handlers.go` (`HandleJWTAuth`) | `proved` (model: `proof/auth_flow.gobra`) + `conformant` |
| SR-AUTH-02 | **Password authentication cannot succeed when password login is disabled.** With `enablePasswordLogin == false`, a request carrying `Authorization: Basic …` is answered `401` and the session handler is not called; the password is never handed to the password database. | `server_auth/auth.go` | `proved` (model: `proof/auth_flow.gobra`) |
| SR-AUTH-03 | Password authentication **fails closed**: a lookup error (`err != nil`) is a rejection, not a "not ok, continue"; only `ok == true && err == nil` reaches the handler. | `server_auth/auth.go` (`HandleBasicAuth`) | `proved` (model: `proof/auth_flow.gobra`) |
| SR-AUTH-04 | An unknown user is rejected before any identity verifier is consulted, so a nonexistent account cannot be used to consume verifier work or to probe which verification method is configured. | `server_auth/auth.go` | `proved` (model: `proof/auth_flow.gobra`) |
| SR-AUTH-05 | A Bearer/JWT credential is only accepted against one of the identities authorized for the asserted user; an empty authorized-identity set never authenticates. | `server_auth/handlers.go` (`HandleJWTAuth`) | `proved` (model: `proof/auth_flow.gobra`) |
| SR-AUTH-06 | An OIDC token that carries no conversation-binding claim (`ssh3_conv_id`, `jti`) is **rejected**; a token bound to another conversation is rejected. A captured ID token is therefore not replayable on an arbitrary conversation. | `server_auth/authorized_identities.go` (`OpenIDConnectIdentity.Verify`) | `proved` (binding decision modelled in `proof/oidc_binding.gobra`); signature/claims verification itself is out of scope (goes through `go-jose` discovery) |
| SR-AUTH-07 | **Replay**: for a token identified by `(issuer, id)`, `Accept` returns true at most once while the remembered entry has not expired; an empty `id` is always refused. | `auth/oidc/replay.go` (`AcceptedTokenStore.Accept`) | `proved` (`proof/token_replay.gobra`), with `sync.Mutex` invariant |
| SR-AUTH-08 | **Password guessing is bounded**: within one failure window, a key that already failed `maxFailures` times is refused (`429`) *before* the password is checked, so further guessing costs no hashing. A successful login clears the counter for that key. | `server_auth/login_policy.go` (`loginThrottle.check/failure/success`) | `proved` (`proof/login_throttle.gobra`) |
| SR-AUTH-09 | Early data (0-RTT) is never authenticated: requests arriving before the TLS handshake completed are refused (`425 Too Early`), which is what makes the replay-resistance claims above meaningful. | `server_auth/auth.go` | **out of scope for Gobra** (quic-go `ConnectionState()`); covered by integration tests |

## 2. Session permissions — `PERM`

The threat: an identity whose owner asked for restrictions (`authorized_keys`
options: `command=`, `from=`, `restrict`, `no-pty`, …) getting a session with more
rights than the file grants — including "silently ignored option" bugs, which are
the classic way a restriction fails open.

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-PERM-01 | **Fail closed on unknown options**: parsing an `authorized_keys`-style option list returns an error for any option name sshoq does not enforce. No option is ever accepted-and-ignored. | `identity_options.go` (`ParseIdentityOptions`) | `proved` (model: `proof/identity_options.gobra`) + `conformant` |
| SR-PERM-02 | `restrict` sets **all** of `NoPty`, `NoPortForwarding`, `NoAgentForwarding`, `NoX11Forwarding`, `NoEnv`. | `identity_options.go` | `proved` + `conformant` |
| SR-PERM-03 | Parsing is **monotone**: processing an additional recognised option never clears a restriction flag; the resulting flags depend only on the set of option names present, not their order. | `identity_options.go` | `proved` (order-independence lemma in `proof/identity_options.gobra`) |
| SR-PERM-04 | `CheckRequest` denies exactly the requests the flags forbid: `pty-req` when `NoPty`, `env` when `NoEnv`, `x11-req` when `NoX11Forwarding`, `agent-forwarding` when `NoAgentForwarding`; it allows every other request type, and a `nil` option set allows everything. | `identity_options.go` (`CheckRequest`) | `proved` + `conformant` |
| SR-PERM-05 | `CheckChannelOpen` denies port/UDP/reverse-tcp channel opens and `sftp` when a forced command is set, and denies forwarding when `NoPortForwarding`; the check keys on the channel family, not on the parameter tail after `,`. | `identity_options.go` (`CheckChannelOpen`) | `proved` + `conformant` |
| SR-PERM-06 | `from=` **fails closed**: a missing or unparsable peer address is refused when a `from=` restriction exists; a negated pattern that matches is refused; nothing matching is refused. | `identity_options.go` (`CheckSource`) | `proved` (address-matching predicates modelled in `proof/source_check.gobra`) |
| SR-PERM-07 | `matchGlob` terminates, and a pattern containing no wildcard matches **exactly one** text (equality). `?` consumes exactly one character. | `identity_options.go` (`matchGlob`) | `proved` (`proof/source_check.gobra`, total correctness via `decreases`) |
| SR-PERM-08 | Option names are matched case-insensitively in a way that can only *add* restrictions: the case-folded name space contains only restricting names. | `identity_options.go` | `proved` (enumerated name set in `proof/identity_options.gobra`) |
| SR-PERM-09 | A forced command actually replaces the executed command, and the identity options attached to a conversation are the ones of the identity that authenticated it (set once, before any channel is handled). | `channel.go`, `conversation.go` | **out of scope for Gobra** (conversation state is entangled with QUIC streams); covered by integration tests + `cmd` tests |
| SR-PERM-10 | SFTP and tunneling are only offered on a session whose identity options allow them (subsystem/forwarding requests funnel through `CheckChannelOpen`/`CheckRequest`). | `channel.go`, `sftp/server.go` | partially proved: the decision function is `SR-PERM-04/05`; the dispatch path is out of scope |

## 3. Transport and host trust — `TR`

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-TR-01 | The client does not accept a server certificate for a hostname it does not already know, unless the user pinned that exact host hash; `Knows`/`KnowsHash` decide it, and both are total and never panic. | `known_hosts.go` | `proved` (model: `proof/known_hosts.gobra`) |
| SR-TR-02 | `ParseKnownHosts` classifies malformed lines as invalid instead of trusting them, and a line whose base64 or certificate does not parse never enters the map. | `known_hosts.go` | `proved` (line-decision modelled in `proof/known_hosts.gobra`); file/x509 layer out of scope |
| SR-TR-03 | A peer whose protocol version is not supported is refused before authentication. | `server_auth/auth.go` | out of scope for Gobra (version parsing lives in `version.go` with `strings`); covered by unit tests |
| SR-TR-04 | The untrusted `User-Agent` is never reflected in a response body and is logged truncated, so a pre-authentication reject cannot panic the server. | `server_auth/auth.go`, `login_policy.go` (`truncate`) | `proved` (`proof/truncate.gobra`, incl. memory safety and the UTF-8 boundary claim) + `conformant` |

## 4. Resource exhaustion — `RES`

Availability is part of security here: these structures are fed by untrusted,
pre-authentication input.

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-RES-01 | The login throttle remembers at most `capacity` keys; `startWindowLocked` evicts before inserting, so the memory an attacker can force is independent of the number of source addresses they spoof. | `server_auth/login_policy.go` | `proved` (`proof/login_throttle.gobra`) |
| SR-RES-02 | `truncate(s, max)` returns a string of length at most `max + 3`, equal to `s` when `len(s) <= max`, empty when `max <= 0`, and never indexes out of bounds. | `server_auth/login_policy.go` | `proved` + `conformant` |
| SR-RES-03 | The OIDC replay store holds at most `maxEntries` tokens, and `maxEntries < 1` is normalised to 1 at construction, so it cannot grow with network input nor degenerate into an accept-everything store. | `auth/oidc/replay.go` | `proved` (`proof/token_replay.gobra`) |
| SR-RES-04 | Delay granted to an attacker per failed attempt is capped by `maxDelay` (so throttling cannot be turned into an amplification/lock-up of server workers). | `server_auth/login_policy.go` | `proved` (`proof/login_throttle.gobra`) |

## 5. Untrusted wire data — `PARSE`

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-PARSE-01 | Parsing a channel request never reads past the declared payload length and never panics on truncated input. | `message/channel_request.go` | phase 3 (see roadmap); the existing fuzz corpus is the interim control |
| SR-PARSE-02 | `ParseBearerAuth` never panics for an `Authorization` value shorter than the prefix and only strips the prefix when it is really present (case-insensitive, ASCII). | `server_auth/handlers.go`, `util/util.go` (`EqualFold`) | `proved` (`proof/bearer.gobra`) + `conformant` |

---

## Proof architecture

```
proof/
  SECURITY_REQUIREMENTS.md   this file
  gobra.version              pinned Gobra tag (the proofs mean that version)
  <area>.gobra               one Gobra unit per requirement cluster
  conformance_test.go        binds the models to the production Go functions
```

Gobra verifies a *self-contained* subset of Go: no cgo, no reflection, and the
standard library only partially. Production files pull in `quic-go`, `x509`,
`zerolog` and cgo-backed user-database lookups, so the proofs are written against
models of the decision logic, and `proof/conformance_test.go` is what ties those
models back to the functions the server actually runs (same inputs, same verdicts,
including "is this a rejection"). A model whose behaviour drifts from the
implementation makes `make proof` fail, which is the property that keeps this
honest over time.

## Roadmap

1. **Phase 1 (this work)** — toolchain (`scripts/setup-gobra.sh`, `make proof`,
   `proof.yml` workflow), requirements catalogue, and the proofs above: auth
   decision flow, identity-option enforcement, login throttle, token replay,
   truncation, host-key knowledge. Any bug the proofs surface gets fixed and
   tagged with the requirement ID it violates.
2. **Phase 2** — push the proofs into the production files themselves where they
   are self-contained enough for Gobra to read (`identity_options.go` and
   `login_policy.go` are the candidates), so that the annotated code *is* the
   verified code and no transcription is involved.
3. **Phase 3** — `message/` wire parsing (bounded slicing for every message type)
   and the SFTP path handling of `sftp/server.go`, where directory traversal and
   permissions are the interesting properties.
4. **Phase 4** — the conversation/channel state machine: state transitions under
   concurrency (Gobra is good at this: predicates + mutexes + goroutines), which
   is where the remaining use-after-close and double-close class of bugs lives.

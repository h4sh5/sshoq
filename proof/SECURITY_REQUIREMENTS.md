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
  proof is only worth what the transcription is faithful. The correspondence checks
  are Go tests living in the package of the code they check (the modelled functions
  are unexported) and carrying `Proved` in their name:
  `identity_options_conformance_test.go`, `server_auth/truncate_conformance_test.go`.
  They enumerate the input space of each modelled decision and compare it with the
  decision table written out in Go — the same table the Gobra `ensures` clauses
  state. `make proof-conformance` runs them. `proved + conformant` is the strongest
  status this repository can claim without verifying the production files themselves.

Statuses below are deliberately uneven, and one of them is a finding rather than a
guarantee: SR-RES-01 was **disproved** by these tests and then fixed
([Findings](#findings)).

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
| SR-AUTH-01 | A session handler is invoked **only** on a path where a verifier accepted the peer. There is no path to `handlerFunc` that does not first evaluate a verification result to true. | `server_auth/auth.go` (`HandleAuths`, `HandleBasicAuth`), `server_auth/handlers.go` (`HandleJWTAuth`) | `proved` (model: `proof/authflow/model.gobra`, a 16-outcome decision table over the handler's gates) |
| SR-AUTH-02 | **Password authentication cannot succeed when password login is disabled.** With `enablePasswordLogin == false`, a request carrying `Authorization: Basic …` is answered `401` and the session handler is not called; the password is never handed to the password database. | `server_auth/auth.go` | `proved` (model: `proof/authflow/model.gobra`) |
| SR-AUTH-03 | Password authentication **fails closed**: a lookup error (`err != nil`) is a rejection, not a "not ok, continue"; only `ok == true && err == nil` reaches the handler. | `server_auth/auth.go` (`HandleBasicAuth`) | `proved` (model: `proof/authflow/model.gobra`) |
| SR-AUTH-04 | An unknown user is rejected before any identity verifier is consulted, so a nonexistent account cannot be used to consume verifier work or to probe which verification method is configured. | `server_auth/auth.go` | `proved` (model: `proof/authflow/model.gobra`) |
| SR-AUTH-05 | A Bearer/JWT credential is only accepted against one of the identities authorized for the asserted user; an empty authorized-identity set never authenticates. | `server_auth/handlers.go` (`HandleJWTAuth`) | `proved` (model: `proof/authflow/model.gobra`) |
| SR-AUTH-06 | An OIDC token that carries no conversation-binding claim (`ssh3_conv_id`, `jti`) is **rejected**; a token bound to another conversation is rejected. A captured ID token is therefore not replayable on an arbitrary conversation. | `server_auth/authorized_identities.go` (`OpenIDConnectIdentity.Verify`) | **open** — no unit yet. The binding decision is small enough to model (`proof/oidc_binding` planned); signature and claim verification stays out of Gobra's reach either way (it goes through `go-jose` discovery). |
| SR-AUTH-07 | **Replay**: for a token identified by `(issuer, id)`, `Accept` returns true at most once while the remembered entry has not expired; an empty `id` is always refused. | `auth/oidc/replay.go` (`AcceptedTokenStore.Accept`) | partially `proved` — `proof/replay/model.gobra` proves, for every store state and every token: an empty `id` is never accepted; a token is refused exactly when it is remembered and still live; a refusal leaves the store exactly as it was (so replay traffic can neither evict nor grow it); and the store stays inside its capacity for *every* trace of tokens. Not modelled: the signature/`iss`/`aud`/`exp` validation which happens before the store is consulted (SR-AUTH-01..04, still open) and the clock itself, which enters the model only as the two booleans the code actually asks it. + `conformant` (`auth/oidc/replay_conformance_test.go`) |
| SR-AUTH-08 | **Password guessing is bounded**: within one failure window, a key that already failed `maxFailures` times is refused (`429`) *before* the password is checked, so further guessing costs no hashing. A successful login clears the counter for that key. | `server_auth/login_policy.go` (`loginThrottle.check/failure/success`) | partially `proved` — `proof/throttle/model.gobra` proves the delay and lock-out arithmetic over every failure count, window length and capacity. The window *reset* keeps the table, so it is not modelled there; `server_auth/login_policy_test.go` covers it. |
| SR-AUTH-09 | Early data (0-RTT) is never authenticated: requests arriving before the TLS handshake completed are refused (`425 Too Early`), which is what makes the replay-resistance claims above meaningful. | `server_auth/auth.go` | **out of scope for Gobra** (quic-go `ConnectionState()`); covered by integration tests |

## 2. Session permissions — `PERM`

The threat: an identity whose owner asked for restrictions (`authorized_keys`
options: `command=`, `from=`, `restrict`, `no-pty`, …) getting a session with more
rights than the file grants — including "silently ignored option" bugs, which are
the classic way a restriction fails open.

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-PERM-01 | **Fail closed on unknown options**: parsing an `authorized_keys`-style option list returns an error for any option name sshoq does not enforce. No option is ever accepted-and-ignored. | `identity_options.go` (`ParseIdentityOptions`) | `proved` (model: `proof/identityopts/model.gobra`, `parseOptions`: a list parses exactly when every name is enforced, and a refused list yields no restriction set at all) + `conformant` (exhaustive over the enforced and the unenforced name space) |
| SR-PERM-02 | `restrict` sets **all** of `NoPty`, `NoPortForwarding`, `NoAgentForwarding`, `NoX11Forwarding`, `NoEnv` — and is the only name that sets `NoEnv`. | `identity_options.go` | `proved` (`applyOption`, `restrictedIdentityRefusesEverythingItSaysItRefuses`, `theFiveSpelledNamesAreExactlyRestrict`) + `conformant` |
| SR-PERM-03 | Parsing is **monotone**: processing an additional recognised option never clears a restriction flag; the resulting flags depend only on the set of option names present, not their order. | `identity_options.go` | partially `proved` — the per-option effect is proved for every restriction set (`applyOption`: each flag ends set exactly when its own name or `restrict` set it, and no option clears a flag), which is the monotone part; order-independence follows from those clauses and is checked in both orders for every pair of enforced names by the conformance test instead of as a separate lemma. |
| SR-PERM-04 | `CheckRequest` denies exactly the requests the flags forbid: `pty-req` when `NoPty`, `env` when `NoEnv`, `x11-req` when `NoX11Forwarding`, `agent-forwarding` when `NoAgentForwarding`; it allows every other request type, and a `nil` option set allows everything. | `identity_options.go` (`CheckRequest`) | `proved` (`checkRequest`: refuses exactly the four forbidden request/flag pairs and allows everything else, unknown request types included) + `conformant` (64 field combinations x 9 request types, `nil` options included) |
| SR-PERM-05 | `CheckChannelOpen` denies port/UDP/reverse-tcp channel opens and `sftp` when a forced command is set, and denies forwarding when `NoPortForwarding`; the check keys on the channel family, not on the parameter tail after `,`. | `identity_options.go` (`CheckChannelOpen`) | `proved` (`checkChannelOpen`) + `conformant` (64 field combinations x 13 channel types, including the `family,parameter` form). Note what the proof makes visible: `restrict` does **not** close `sftp`, only `command=` does — as in OpenSSH, and asserted as such so that a change of policy fails the proof. |
| SR-PERM-06 | `from=` **fails closed**: a missing or unparsable peer address is refused when a `from=` restriction exists; a negated pattern that matches is refused; nothing matching is refused. | `identity_options.go` (`CheckSource`) | **open** — no unit yet (`proof/source_check` planned: the negation/first-match decision fits on one page). The address matching itself works on `net.IP` and `net` CIDRs, which Gobra cannot ingest; `identity_options_test.go` covers CIDR, glob, negation, unparsable source and hostname patterns. |
| SR-PERM-07 | `matchGlob` terminates, and a pattern containing no wildcard matches **exactly one** text (equality). `?` consumes exactly one character. | `identity_options.go` (`matchGlob`) | **open** — recursive over two strings and a good Gobra target (`decreases` on the remaining lengths gives total correctness); enumerated in `identity_options_test.go` meanwhile. |
| SR-PERM-08 | Option names are matched case-insensitively in a way that can only *add* restrictions: the case-folded name space contains only restricting names. | `identity_options.go` | **open** — the model is handed the already case-folded name, so `strings.ToLower` sits outside it. Checkable in Go (fold every name of the supported space, assert the verdict equals the lower-case one); the next conformance test to write. |
| SR-PERM-09 | A forced command actually replaces the executed command, and the identity options attached to a conversation are the ones of the identity that authenticated it (set once, before any channel is handled). | `channel.go`, `conversation.go` | **out of scope for Gobra** (conversation state is entangled with QUIC streams); covered by integration tests + `cmd` tests |
| SR-PERM-10 | SFTP and tunneling are only offered on a session whose identity options allow them (subsystem/forwarding requests funnel through `CheckChannelOpen`/`CheckRequest`). | `channel.go`, `sftp/server.go` | partially proved: the decision function is `SR-PERM-04/05`; the dispatch path is out of scope |

## 3. Transport and host trust — `TR`

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-TR-01 | The client does not accept a server certificate for a hostname it does not already know, unless the user pinned that exact host hash; `Knows`/`KnowsHash` decide it, and both are total and never panic. | `known_hosts.go` | **open** — no unit yet. `proof/known_hosts` is the next one worth writing: the decision is a map lookup plus a hash comparison, and "total, never panics" is exactly what Gobra gives for free. `known_hosts_test.go` covers the behaviour today. |
| SR-TR-02 | `ParseKnownHosts` classifies malformed lines as invalid instead of trusting them, and a line whose base64 or certificate does not parse never enters the map. | `known_hosts.go` | **open** — the line-decision model is easy; the `x509`/base64 layer stays out of Gobras reach, so the claim would be about the classifier only. |
| SR-TR-03 | A peer whose protocol version is not supported is refused before authentication. | `server_auth/auth.go` | out of scope for Gobra (version parsing lives in `version.go` with `strings`); covered by unit tests |
| SR-TR-04 | The untrusted `User-Agent` is never reflected in a response body and is logged truncated, so a pre-authentication reject cannot panic the server. | `server_auth/auth.go`, `login_policy.go` (`truncate`) | `proved` (`proof/truncation/model.gobra`: memory safety for every input and bound, plus the character-boundary claim — this is the F10 panic class) + `conformant` |

## 4. Resource exhaustion — `RES`

Availability is part of security here: these structures are fed by untrusted,
pre-authentication input.

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-RES-01 | The login throttle remembers at most `capacity` keys; `startWindowLocked` evicts before inserting, so the memory an attacker can force is independent of the number of source addresses they spoof. | `server_auth/login_policy.go` | `proved` (`proof/throttle/model.gobra`: the delay handed to an attacker never exceeds `maxDelay`, for every failure count, step and cap) |
| SR-RES-02 | `truncate(s, max)` returns a string of length at most `max + 3`, equal to `s` when `len(s) <= max`, empty when `max <= 0`, and never indexes out of bounds. | `server_auth/login_policy.go` | `proved` (`proof/truncation/model.gobra`: the cut lands on a character boundary, `len(res) <= max+3`, and memory safety for every `s` and `max`) + `conformant` (`server_auth/truncate_conformance_test.go`) |
| SR-RES-03 | The OIDC replay store holds at most `maxEntries` tokens, and `maxEntries < 1` is normalised to 1 at construction, so it cannot grow with network input nor degenerate into an accept-everything store. | `auth/oidc/replay.go` | `proved` (`proof/replay/model.gobra`: `run` proves `len <= capacity` for every trace, and `len <= len(trace)`; the normalisation is proved to leave a store that still catches the replay of the token just accepted) + `conformant` (`auth/oidc/replay_conformance_test.go`). Unlike the login throttle (SR-RES-01), this store's stale-order rebuild keeps its bound — checked, not assumed. |
| SR-RES-04 | Delay granted to an attacker per failed attempt is capped by `maxDelay` (so throttling cannot be turned into an amplification/lock-up of server workers). | `server_auth/login_policy.go` | `proved` (`proof/throttle/model.gobra`: the delay never exceeds `maxDelay`, for every failure count, step and cap) |

## 5. Untrusted wire data — `PARSE`

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-PARSE-01 | Parsing a channel request never reads past the declared payload length and never panics on truncated input. | `message/channel_request.go` | phase 3 (see roadmap); the existing fuzz corpus is the interim control |
| SR-PARSE-02 | `ParseBearerAuth` never panics for an `Authorization` value shorter than the prefix and only strips the prefix when it is really present (case-insensitive, ASCII). | `server_auth/handlers.go`, `util/util.go` (`EqualFold`) | **open** — small unit (`proof/bearer`), worth doing next: it is pre-authentication input on the Bearer path. The length guard exists in the code and is exercised by `server_auth` tests, not yet by a proof. |

---

## Proof architecture

```
proof/
  SECURITY_REQUIREMENTS.md    this file
  gobra.version               the pinned Gobra ref - the proofs mean that version
  smoke/model.gobra           toolchain canary: does Gobra run at all here
  authflow/model.gobra        SR-AUTH-01..05: the authentication decision table
  identityopts/model.gobra    SR-PERM-01..05: identity restrictions, fail-closed parsing
  truncation/model.gobra      SR-TR-04, SR-RES-02: untrusted User-Agent handling
  throttle/model.gobra        SR-AUTH-08, SR-RES-04: throttle delay and lock-out arithmetic

identity_options_conformance_test.go   the identityopts model against identity_options.go
server_auth/truncate_conformance_test.go   the truncation model against login_policy.go
server_auth/login_policy_test.go       throttle behaviour, including the SR-RES-01 bound
```

One unit per requirement cluster, one Gobra package per unit, each verified on its own so
that a timeout or a failure in one cannot hide the verdict of another
(`scripts/run-proofs.sh` discovers `proof/*/model.gobra` and runs Gobra once per unit with
`-i`, a pinned `--packageTimeout`, and the backend from `proof/gobra.version`).

Gobra verifies a *self-contained* subset of Go: no cgo, no reflection, partial standard
library. The production files pull in `quic-go`, `x509`, `zerolog` and cgo-backed user
lookups, so the proofs are written against models of the decision logic and the
conformance tests tie those models back to the functions the server runs. A model that
drifts from the implementation makes `make proof-conformance` fail; that is what keeps the
catalogue honest over time. What the proofs therefore claim is: *the decision the code
implements, once transcribed faithfully, has no input that escapes the stated property* —
and the transcription is checked, not assumed.

Two limits worth stating where they bit:

* **`delete` does not exist in Gobra 26.09** (the builtins are `make`, `len`, `append`,
  `copy`, `min`, `max`). Modelling a map that forgets keys means rebuilding it in a loop
  under a ghost "visited" set — more proof than the throttle decision is worth. Its memory
  bound is pinned by tests instead, which is how F1 was found.
* **`assert` needs a pure expression.** The decision functions the models exist to specify
  are therefore written as `pure func` with a single `return`, and the lemmas call them from
  ordinary code and assert about the result. This shapes the models more than the logic does.

## Findings

### F1: the throttle could grow past its own capacity (SR-RES-01)

`loginThrottle` documents that `capacity` "bounds the number of remembered sources", and
that is what makes it safe to feed from untrusted, pre-authentication input: the memory an
attacker can force must not depend on how many sources they pretend to be.

`success(key)` deletes the entry but leaves the name in `order`, the ring used to pick a
victim. `startWindowLocked` looked at exactly one ring slot; when that slot named a source
which had already been forgiven, it deleted nothing and inserted anyway. So a client that
alternates a failure with a success keeps the ring pointing at ghosts, and the table grows
without bound:

```
fail a; fail b; fail c; success b; fail d; fail b     (capacity 3)
 -> 4 entries remembered
```

The pre-existing bound test sprayed distinct sources with no successes — precisely the case
where eviction works — so it stayed green while the property was false. `check` never
looked at the table size either, so nothing else reported it.

Fix: refresh in place when the source is already remembered; otherwise walk the ring until
a slot names a source the table really holds, and if every slot was rewritten with names
that are gone, forget the entry whose window opened first. The ring decides *which* source
is forgotten; the last resort guarantees that *some* is, which is the part the bound
depends on.

Pinned by `TestLoginThrottleCapacityHoldsWhenSourcesAreForgotten` (that witness) and
`TestLoginThrottleCapacityHoldsUnderMixedTraffic` (20 000 seeded failures, successes and
window rollovers, bound asserted after every operation). Both failed before the fix; the
20 000-operation one broke at operation 118.

## Roadmap

1. **Phase 1 (this work)** — toolchain (`scripts/setup-gobra.sh`, `make proof`,
   `make proof-conformance`, the `proof.yml` workflow), this catalogue, and the five
   verification units (`authflow`, `truncation`, `throttle`, `identityopts`, `replay`)
   plus the canary. Any bug a proof or a conformance test surfaces gets
   fixed and recorded here with the requirement ID it violates (F1).
2. **Phase 2** — the units marked **open**, in the order that buys the most: `known_hosts`
   (SR-TR-01), `bearer` (SR-PARSE-02), `source_check` (SR-PERM-06/07), then the
   case-folding conformance check (SR-PERM-08). The token *validation* path around the replay
   store (SR-AUTH-01..04: signature, `iss`, `aud`, `exp`) is the largest remaining hole in the
   authentication story and needs a model of the JWKS fetch, which is why it is not in this
   phase.
3. **Phase 3** — push specifications into the production files themselves where Gobra can
   read them (`identity_options.go` is the best candidate: no cgo, no reflection, and the
   decision logic is already separated from `net` by three small functions), so that the
   annotated code *is* the verified code and no transcription is involved.
4. **Phase 4** — `message/` wire parsing (bounded slicing for every message type) and the
   SFTP path handling in `sftp/server.go`, where directory traversal and permissions are the
   interesting properties.
5. **Phase 5** — the conversation/channel state machine: transitions under concurrency
   (predicates, mutexes, goroutines — Gobra is good at this), which is where the remaining
   use-after-close and double-close class of bugs lives.

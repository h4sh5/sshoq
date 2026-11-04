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
| SR-AUTH-01 | A session handler is invoked **only** on a path where a verifier accepted the peer. There is no path to `handlerFunc` that does not first evaluate a verification result to true. | `server_auth/auth.go` (`HandleAuths`, `HandleBasicAuth`), `server_auth/handlers.go` (`HandleJWTAuth`) | **[proved:model]** `proved` (model: `proof/authflow/model.gobra`, a 16-outcome decision table over the handler's gates) |
| SR-AUTH-02 | **Password authentication cannot succeed when password login is disabled.** With `enablePasswordLogin == false`, a request carrying `Authorization: Basic …` is answered `401` and the session handler is not called; the password is never handed to the password database. | `server_auth/auth.go` | **[proved:model]** `proved` (model: `proof/authflow/model.gobra`) |
| SR-AUTH-03 | Password authentication **fails closed**: a lookup error (`err != nil`) is a rejection, not a "not ok, continue"; only `ok == true && err == nil` reaches the handler. | `server_auth/auth.go` (`HandleBasicAuth`) | **[proved:model]** `proved` (model: `proof/authflow/model.gobra`) |
| SR-AUTH-04 | An unknown user is rejected before any identity verifier is consulted, so a nonexistent account cannot be used to consume verifier work or to probe which verification method is configured. | `server_auth/auth.go` | **[proved:model]** `proved` (model: `proof/authflow/model.gobra`) |
| SR-AUTH-05 | A Bearer/JWT credential is only accepted against one of the identities authorized for the asserted user; an empty authorized-identity set never authenticates. | `server_auth/handlers.go` (`HandleJWTAuth`) | **[proved:model]** `proved` (model: `proof/authflow/model.gobra`) |
| SR-AUTH-06 | An OIDC token that carries no conversation-binding claim (`ssh3_conv_id`, `jti`) is **rejected**; a token bound to another conversation is rejected. A captured ID token is therefore not replayable on an arbitrary conversation. | `server_auth/authorized_identities.go` (`OpenIDConnectIdentity.Verify`) | **[proved:model]** `proved` (`proof/oidcbinding`) + `conformant` — the unit models the binding decision and proves: a token carrying neither `ssh3_conv_id` nor `jti` is refused whatever else is true of it; a token is accepted for **at most one** conversation, because the value compared is the server's own id and not one the token names (so a captured token cannot be re-bound by whoever holds it); a `jti` naming this conversation does not rescue a token whose `ssh3_conv_id` names another; the replay key is `jti`, else the binding value, and is never empty at a point where the token is accepted; a refusal from the replay store is not advisory; and the identity check comes first, so a binding claim cannot buy a conversation on somebody else's identity. Signatures, `iss`, `aud` and `exp` stay premises (SR-AUTH-01..04) — they go through `go-jose` discovery, out of Gobra's reach either way. The two steps the model cannot see are checked in Go: `TestConformanceOIDCBindingBlockIsTheModelledDecision` holds `Verify` to the claim order and the compared values the proof assumes (a structured read of that one method, which fails with the message "change the model with it"), and `TestConformanceConversationIDEncodingIsInjective` shows the base64 form of a conversation id distinguishes ids — exhaustively on short inputs at every offset, bit by bit over all 256 bits of a real id, and 20 000 random pairs — because otherwise two conversations would share one binding value and the "at most one conversation" theorem would be about encodings, not connections. |
| SR-AUTH-07 | **Replay**: for a token identified by `(issuer, id)`, `Accept` returns true at most once while the remembered entry has not expired; an empty `id` is always refused. | `auth/oidc/replay.go` (`AcceptedTokenStore.Accept`) | **[partial]** partially `proved` — `proof/replay/model.gobra` proves, for every store state and every token: an empty `id` is never accepted; a token is refused exactly when it is remembered and still live; a refusal leaves the store exactly as it was (so replay traffic can neither evict nor grow it); and the store stays inside its capacity for *every* trace of tokens. Not modelled: the signature/`iss`/`aud`/`exp` validation which happens before the store is consulted (SR-AUTH-01..04, still open) and the clock itself, which enters the model only as the two booleans the code actually asks it. + `conformant` (`auth/oidc/replay_conformance_test.go`) |
| SR-AUTH-08 | **Password guessing is bounded**: within one failure window, a key that already failed `maxFailures` times is refused (`429`) *before* the password is checked, so further guessing costs no hashing. A successful login clears the counter for that key. | `server_auth/throttle_rules.go` (`windowElapsed`, `attemptIsRefused`, `failureDelay`, `retryAfter`, `failureDelayGrowsWithFailures`), `server_auth/login_policy.go` (`loginThrottle.check/failure/success/startWindowLocked`) | **[proved:shipped]** `proved` on the shipped arithmetic: the four questions `check` asks of its state are functions with contracts in `throttle_rules.go` — a window closes *strictly* after its length (so an exactly-as-old window still counts, and a clock that steps backwards hands nobody a fresh window); `attemptIsRefused` is `failures >= maxFailures` with the boundary stated on both sides, which is what finding **F7** is about; the delay is `failures x step` capped at `max`, never negative, zero exactly when there were no failures; and `RetryAfter` is floored at zero, because a refusal that reports a negative wait tells the client to come back before now. `failureDelayGrowsWithFailures` is the monotonicity lemma, kept next to the rule it quantifies over. `conformant` around them: `TestConformanceCheckAppliesTheRules` drives the real `check()` — table, window reset, refusal and delay — over four windows x four steps x four caps x eight clock positions x six failure counts, comparing with the pre-split expressions as finding **F6** requires; `throttle_rules_conformance_test.go`'s `TestConformanceThrottleRulesAreTheExpressions` checks each rule against the lines it replaced *in the same units the call sites use*, and `TestConformanceThrottleDelayIsInTheUnitsItLooksLike` says a step of one second still produces three seconds after three failures rather than three nanoseconds; `TestConformanceRefusalBoundaryIsTheLimit`, `TestConformanceThrottleDelayProperties`, `TestConformanceWindowExpiryIsTheComparison` and `TestConformanceFailureDelayAtTheOverflowBoundary` cover the boundary, the shape, the two consequences of strictness and the one place the cap is a premise. Outside the proof: the table, the mutex and the clock reading itself. `time` is not the obstacle — Gobra stubs it with real specs, `Duration` arithmetic included, so the rules speak Durations and convert nothing at the seam; `fmt` is the obstacle, which is why they are not in `login_policy.go` at all (below), and `TestConformanceThrottleDelayIsInTheUnitsItLooksLike` is the check that a split which moved no conversions could still have broken in units. The window *reset* keeping the table bounded is SR-RES-01 (**F1**) and `login_policy_test.go` covers it; `proof/throttle/model.gobra` remains as a second opinion. |
| SR-AUTH-09 | Early data (0-RTT) is never authenticated: requests arriving before the TLS handshake completed are refused (`425 Too Early`), which is what makes the replay-resistance claims above meaningful. | `server_auth/auth.go` | **[out-of-scope]** **out of scope for Gobra** (quic-go `ConnectionState()`); covered by integration tests |

## 2. Session permissions — `PERM`

The threat: an identity whose owner asked for restrictions (`authorized_keys`
options: `command=`, `from=`, `restrict`, `no-pty`, …) getting a session with more
rights than the file grants — including "silently ignored option" bugs, which are
the classic way a restriction fails open.

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-PERM-01 | **Fail closed on unknown options**: parsing an `authorized_keys`-style option list returns an error for any option name sshoq does not enforce. No option is ever accepted-and-ignored. | `identity_options.go` (`ParseIdentityOptions`) | **[proved:model]** `proved` (model: `proof/identityopts/model.gobra`, `parseOptions`: a list parses exactly when every name is enforced, and a refused list yields no restriction set at all) + `conformant` (exhaustive over the enforced and the unenforced name space) |
| SR-PERM-02 | `restrict` sets **all** of `NoPty`, `NoPortForwarding`, `NoAgentForwarding`, `NoX11Forwarding`, `NoEnv` — and is the only name that sets `NoEnv`. | `identity_options.go` | **[proved:model]** `proved` (`applyOption`, `restrictedIdentityRefusesEverythingItSaysItRefuses`, `theFiveSpelledNamesAreExactlyRestrict`) + `conformant` |
| SR-PERM-03 | Parsing is **monotone**: processing an additional recognised option never clears a restriction flag; the resulting flags depend only on the set of option names present, not their order. | `identity_options.go` | **[proved:model]** `proved` (model) + `conformant`. The model does not prove monotonicity and order-independence separately: `parseOptions` has a **closed form** for each field — on success, `noPty` equals "some name in the list was `no-pty` or `restrict`", and likewise for the other four and for `forcedCommand` — and a closed form mentions only *which* names occur, so both halves are corollaries of one clause. The per-option step is proved too (`applyOption`: each flag ends set exactly when its own name or `restrict` set it, and no option clears a flag). On the shipped side, `identity_options_closed_form_conformance_test.go` holds `ParseIdentityOptions` to the same closed form over **all 128 subsets** of the seven enforced names in six orders each (768 parses, `command=` text and `from=` list included, not just the five booleans), then to monotonicity directly over **2187 subset pairs** S ⊆ T, and to fail-closed by inserting one unenforced name at every position of every subset. Order-independence is therefore pinned in the code the server runs and not only in the model. This row used to say *partially* `proved`, which was wrong in the direction of understatement — see **F9**. |
| SR-PERM-04 | `CheckRequest` denies exactly the requests the flags forbid: `pty-req` when `NoPty`, `env` when `NoEnv`, `x11-req` when `NoX11Forwarding`, `agent-forwarding` when `NoAgentForwarding`; it allows every other request type, and a `nil` option set allows everything. | `identity_checks.go` (`requestVerdictFor`), `identity_options.go` (`CheckRequest`), `identity_checks_conformance_test.go` | **[proved:shipped]** `proved` on the shipped decision: `requestVerdictFor`'s postconditions say, for all inputs, that each of the four request types is refused exactly when its own flag is set and that the permitted verdict is exactly the negation of the four gated cases -- so an unknown request type, however spelled, is permitted by every flag. `conformant` at the ends the prover cannot see: `TestConformanceRequestVerdictIsTheGate` holds `CheckRequest` to that verdict over 14 request-type spellings x 16 flag combinations with a `nil` identity included, and holds each refusal to the wording that has always gone with it, so a verdict mapped to the wrong message fails. The model (`checkRequest` in `proof/identityopts`, 64 field combinations x 9 request types) is a second opinion now rather than the only argument. |
| SR-PERM-05 | `CheckChannelOpen` denies port/UDP/reverse-tcp channel opens and `sftp` when a forced command is set, and denies forwarding when `NoPortForwarding`; the check keys on the channel family, not on the parameter tail after `,`. | `identity_checks.go` (`channelVerdictFor`), `identity_options.go` (`CheckChannelOpen`) | **[proved:shipped]** `proved` on the shipped decision: `channelVerdictFor`'s postconditions say which family-and-flag combinations give which verdict, over all inputs, and `isForwardingFamily` states the forwarding set apart from the switch that uses it. `conformant` at the two ends the prover cannot see — `TestConformanceChannelVerdictIsTheGate` holds `CheckChannelOpen` to that verdict over 17 channel types (the `family,parameter` form included) x the forwarding flag x three forced-command values, including that the forwarding flag outranks the command in what the refusal blames, and `TestConformanceForwardingFamilyIsTheEnumeration` holds the stated set to the gate. Both compare against a locally rewritten copy of the pre-split code, for the reason given in finding **F6**. The model (`checkChannelOpen` in `proof/identityopts`, 64 field combinations x 13 channel types) is now a second opinion rather than the only argument. Note what the proof makes visible either way: `restrict` does **not** close `sftp`, only `command=` does — as in OpenSSH, and asserted as such so that a change of policy fails the proof. |
| SR-PERM-06 | `from=` **fails closed**: a missing or unparsable peer address is refused when a `from=` restriction exists; a negated pattern that matches is refused; nothing matching is refused. | `source_check.go` (`sourceVerdictFor`, `negatedMatch`, `inclusionMatch`, `isNegated`), `identity_options.go` (`CheckSource`, `sourceMatches`, `matchesSourcePattern`, `parsePeerIP`) | **[proved:shipped]** `proved` on the shipped decision: `sourceVerdictFor`'s postconditions are **bidirectional** over the four facts the check collects, so the four outcomes partition the inputs exactly — no restriction restricts nothing; a restriction whose address cannot be named refuses, and the proof makes that visible as a *precedence*, since `!addressKnown` is asked before either match; an exclusion outranks every inclusion; and acceptance is exactly "some non-exclusion pattern matched". The two predicates that read the flag arrays are pure, terminate on a checked index measure, and carry the read permissions their arrays need; `isNegated` is what "is an exclusion" means, specified as `pattern[0] == '!'`. `conformant` at the two ends the prover cannot see: `TestConformanceSourceVerdictIsTheRule` walks all sixteen inputs against the rule as the docs state it; `TestConformanceSourceMatchesSplits` holds `sourceMatches` plus the predicates to the single loop that used to run — same exclusion flags, same match results, same verdict — over 14 pattern spellings × 5 addresses including `nil`, `!!10.1.2.3` and `!*`; `TestConformanceMatchPredicatesAreTheScan` covers every flag array up to length four from every start index; `TestConformanceVerdictsAreReachableAndWorded` ties each verdict to a reachable `CheckSource` call and to the message that has always reported it. The table, permutation and model-premise rows above still run. The `net.IP`/CIDR layer stays outside the proof — Gobra's `net` stubs ask the address as an ownership predicate and have no `SplitHostPort` at all — and what it returns is asserted row by row in `TestConformanceMatchesSourcePatternStrategies`. The model (`fromListDecides` in `proof/sourcecheck`) is a second opinion now rather than the only argument. |
| SR-PERM-07 | `matchGlob` terminates, and a pattern containing no wildcard matches **exactly one** text (equality). `?` consumes exactly one character. | `glob.go` (`matchGlob`, verified where it ships) | **[conformant]** `proved` for termination and for two endpoints, on the shipped function: Gobra checks a two-component measure (retries left, then pattern characters left) so the matcher terminates on *every* pattern and text, and that an empty pattern matches exactly the empty text and that `"*"` matches everything. `conformant` for the rest of the meaning, and the reason is a property of the prover, recorded as F5 alongside SR-RES-05: a recursive *pure* function in Gobra v26.09 has its measure checked but is then opaque, and the step the glob needs is induction over `string`. What pins the meaning instead is `identity_options_source_conformance_test.go`: agreement between the shipped matcher, the recursion it replaced, and an independently written linear matcher over 530 255 pattern/text triples (stars in the texts too, since F6), plus an exhaustive check that a wildcard-free pattern matches exactly the text equal to it, and `?` exactly one character. |
| SR-PERM-08 | Option names are matched case-insensitively in a way that can only *add* restrictions: the case-folded name space contains only restricting names. | `identity_options.go` | **[conformant]** `conformant` — `identity_options_fold_conformance_test.go` closes the step the model is handed (`strings.ToLower(name)`) over the spellings that can arrive. Every ASCII case variant of every enforced name is accepted with exactly the lower-case name's restriction state — 205 232 variants, `NO-X11-FORWARDING` included, since OpenSSH itself spells that one with a capital. Nothing else folds in: the Kelvin sign, long s, dotted and dotless I, Angstrom sign, full-width and mathematical forms — 22 spellings — are all *refused*, so a restriction written in a spelling the server does not know loses the login loudly instead of quietly doing nothing (`strings.ToLower` is a Unicode function: it maps U+212A to 'k', and this refusal is what stands behind that). Accepted options always restrict, enforced names never fold together, and on ASCII input `strings.ToLower` is exactly ASCII folding, which is the definition the model's name space needs. |
| SR-PERM-09 | A forced command actually replaces the executed command, and the identity options attached to a conversation are the ones of the identity that authenticated it (set once, before any channel is handled). | `channel.go`, `conversation.go` | **[out-of-scope]** **out of scope for Gobra** (conversation state is entangled with QUIC streams); covered by integration tests + `cmd` tests |
| SR-PERM-11 | Repeating a scalar option (`identity_type`, `client_id`, `command`) with different values is either merged or refused, and never silently half-applied. | `identity_options.go` (`ParseIdentityOptions`) | **[open]** **open** — modelled and documented as-is by the identityopts unit (`parseIsFailClosed`: every listed option is processed, scalars by last assignment), so today the contract is "last wins"; see finding **F2** for why that is a deviation from the documentation rather than a memory-safety bug. |
| SR-PERM-10 | SFTP and tunneling are only offered on a session whose identity options allow them (subsystem/forwarding requests funnel through `CheckChannelOpen`/`CheckRequest`). | `channel.go`, `sftp/server.go` | **[partial]** partially proved: the decision function is `SR-PERM-04/05`; the dispatch path is out of scope |

## 3. Transport and host trust — `TR`

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-TR-01 | The client does not accept a server certificate for a hostname it does not already know, unless the user pinned that exact host hash; `Knows`/`KnowsHash` decide it, and both are total and never panic. | `known_hosts.go`, `cmd/sshoq.go` | **[proved:model]** `proved` (model: `proof/knownhosts/model.gobra`) + `conformant` (`known_hosts_conformance_test.go`). The store is modelled by the two answers the decision reads about one (host, certificate) pair, and proved: an empty store answers no to both (a missing `known_hosts` cannot trust the first certificate it sees); a known hash implies a known host; recording a pair sets both and never clears either, so **a server that changes certificate leaves the old one on file** and verification keeps failing instead of the client following the newest line; a rejected line leaves the store exactly as it was. The decision is one boolean — accepts exactly when a pin matched, or when there is no pin, no entry, a terminal and a yes — from which: a pin is never overruled by an answer, an unknown host with no terminal is refused, a host whose installed certificate fails to verify is refused, and there is no fourth way to connect. The TLS callbacks themselves are exercised by `cmd/sshoq_pinning_e2e_test.go`. |
| SR-TR-02 | `ParseKnownHosts` classifies malformed lines as invalid instead of trusting them, and a line whose base64 or certificate does not parse never enters the map. | `known_hosts.go` | **[proved:model]** `proved` (model: `proof/knownhosts/model.gobra`, classifier: three fields, the `x509-certificate` tag, and decodable data; the third field is only named when the count is three, so a truncated line is reported rather than read out of bounds) + `conformant` (`known_hosts_conformance_test.go`, which parses a real file with good lines interleaved with two-field, four-field, wrong-tag, non-base64 and non-certificate lines and asserts the invalid line numbers exactly). The `x509`/base64 layer itself stays outside Gobra, so `decodes` is a premise in the model: every claim holds whatever that layer decides, and the test says what it decides. |
| SR-TR-03 | A peer whose protocol version is not supported is refused before authentication. | `server_auth/auth.go` | **[proved:shipped]** **proved on the shipped code** + `conformant` — `versionSupported` in `version_rules.go` is `IsVersionSupported`'s decision, moved unchanged; `IsVersionSupported` is now the field handoff, because `version.go` imports `fmt` and a logger. The clauses: a protocol major/minor other than this server's is never accepted whatever else the announcement claims, so no software version or legacy allowance can smuggle a peer onto another protocol revision; a spec version other than `alpha-00` or the empty legacy one is never accepted, with no prefix matching and no "newer is fine"; inside the legacy family the answer is exactly "patch at least 3". `version_rules_conformance_test.go` holds the handoff against a copy of the pre-split gate over 108 000 announcements, the verdict table, the window's four boundaries, the claim that the software version is irrelevant away from the family, and 5 000 random announcements. It is the first test this gate ever had (**F9**); the *parsing* of the announcement stays outside the verified set — the `strconv` and `strings` stubs say nothing about what `Atoi` and `Split` return, so the numbers a parse produced are not facts a proof can use, and `TestConformanceVersionStringsRoundTripIntoTheGate` is the floor instead |
| SR-TR-04 | The untrusted `User-Agent` is never reflected in a response body and is logged truncated, so a pre-authentication reject cannot panic the server. | `server_auth/truncate.go` (`truncate`, verified where it ships), `server_auth/auth.go` | **[proved:shipped]** `proved` on the shipped function, in two ways at once. The checker's own obligations are the F10 panic class: the scan that backs off a multi-byte character may index `s[cut]` only because the loop invariant puts `cut` inside the string, so a bounds failure is a proof failure now. Three clauses state what an attacker-chosen header obeys — a non-positive bound gives the empty string, a header that fits comes back **identically** (the sentence the old `s[:100]` could not make), and a truncated line is between 3 and `max+3` bytes, which is the bound on how long one header can make a log line. What is not provable here is *which* prefix survives: Gobra knows the length of a string concatenation but has no rule for its characters — `(a + b)[i] == a[i]` for `i < len(a)` is not in its theory, so `prefixEq(res, s, len(res)-3)` is refused — and that half is `conformant`: `TestConformanceTruncateMatchesTheModel` pins it against `proof/truncation` over inputs whose boundary falls inside two- and three-byte characters, `TestTruncateUserAgent` keeps the UTF-8 claim, and the model remains the argument for the character-boundary property. |

## 4. Resource exhaustion — `RES`

Availability is part of security here: these structures are fed by untrusted,
pre-authentication input.

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-RES-01 | The login throttle remembers at most `capacity` keys; `startWindowLocked` evicts before inserting, so the memory an attacker can force is independent of the number of source addresses they spoof. | `server_auth/login_policy.go` | **[proved:model]** `proved` (`proof/throttle/model.gobra`: the delay handed to an attacker never exceeds `maxDelay`, for every failure count, step and cap) |
| SR-RES-02 | `truncate(s, max)` returns a string of length at most `max + 3`, equal to `s` when `len(s) <= max`, empty when `max <= 0`, and never indexes out of bounds. | `server_auth/login_policy.go` | **[proved:model]** `proved` (`proof/truncation/model.gobra`: the cut lands on a character boundary, `len(res) <= max+3`, and memory safety for every `s` and `max`) + `conformant` (`server_auth/truncate_conformance_test.go`) |
| SR-RES-03 | The OIDC replay store holds at most `maxEntries` tokens, and `maxEntries < 1` is normalised to 1 at construction, so it cannot grow with network input nor degenerate into an accept-everything store. | `auth/oidc/replay.go` | **[proved:model]** `proved` (`proof/replay/model.gobra`: `run` proves `len <= capacity` for every trace, and `len <= len(trace)`; the normalisation is proved to leave a store that still catches the replay of the token just accepted) + `conformant` (`auth/oidc/replay_conformance_test.go`). Unlike the login throttle (SR-RES-01), this store's stale-order rebuild keeps its bound — checked, not assumed. |
| SR-RES-05 | Matching a `from=` pattern takes time linear in `len(pattern) + len(text)`: the number of wildcard characters in a pattern cannot be used to make the server work, because `from=` arrives with the identity and is matched on every login attempt that carries one. | `glob.go` (`matchGlob`) | **[conformant]** `proved` for termination and two endpoints on the shipped function, `conformant` for the rest of the meaning (bound: eight star-heavy patterns, the worst 60 stars against an 80-character text, in 1.9µs, guarded by `TestConformanceMatchGlobIsBounded`; meaning: three-implementation agreement over 530 255 triples, stars in the texts included since **F6**) — the recursion this replaced was exponential, 2m56s for fourteen stars on that text; see finding **F5** |
| SR-RES-04 | Delay granted to an attacker per failed attempt is capped by `maxDelay` (so throttling cannot be turned into an amplification/lock-up of server workers). | `server_auth/login_policy.go` | **[proved:model]** `proved` (`proof/throttle/model.gobra`: the delay never exceeds `maxDelay`, for every failure count, step and cap) |

## 5. Untrusted wire data — `PARSE`

| ID | Requirement | Code | Status |
|----|-------------|------|--------|
| SR-PARSE-01 | Parsing a channel request never reads past the declared payload length and never panics on truncated input. | `message/channel_request.go` | **[phase-4]** phase 4 (see roadmap); the existing fuzz corpus is the interim control. The *arithmetic* it leans on — what a length means, how wide it is encoded, what ceiling it must clear — is proved in `util/varint.go` under **SR-PARSE-03**; what is left here is the slicing and the `io` around it |
| SR-PARSE-03 | A length announced by a peer is bounded **before** it is used to allocate, and the length arithmetic on the wire is exact: `VarIntLen` promises the number of bytes `AppendVarInt` writes, a reader's ceiling is the tighter of `MaxFieldLength` and whatever bound it knows itself, a field above that ceiling is refused rather than allocated, and the two readers that take a length (`ParseSSHString`, `ParseSSHBytes`) apply exactly that decision. Without it, ten bytes on the wire announce 2^62−1 and the process either exhausts its address space or panics inside `make` ("makeslice: len out of range"), which takes down every connection on the server, not just the hostile one. | `util/varint.go` (verified where it ships), `util/wire.go` (the readers), `util/varint_conformance_test.go` (the seam) | **[proved:shipped]** `proved` on the shipped arithmetic: `announcementIsBounded` states and proves the composed claim — for every announcement and every reader bound, an accepted field is at most `MaxFieldLength` and a refused one is above the ceiling that reader applies — with `fieldCeiling`'s and `fieldLengthAcceptable`'s bidirectional clauses beneath it, plus `VarIntLen`'s four ranges boundary-inclusive and `SSHStringLen`/`SSHBytesLen`'s "prefix plus payload, strictly more than the payload". `conformant` for everything the prover cannot see: `TestConformanceVarIntLenIsWhatAppendVarIntWrites` (a disagreement is a framing desynchronisation on a *locally chosen* value, invisible on the wire), `TestConformanceFieldLengthIsCheckedBeforeAllocating` (the 2^62−1 bomb, refused through the real readers, and the accept/refuse boundary at ceiling−1, ceiling, ceiling+1 for three reader bounds), `TestConformanceSSHFieldLensAreTheBytesWritten` (exact fit accepted, one byte short refused), and the canonical-encoding and padded-width tests. The encoder's half of the promise -- `AppendVarInt` writes exactly `VarIntLen(i)` more bytes than it was given -- is `conformant`, and not for the reason one would guess: it is not the `fmt.Sprintf` in its out-of-range panic that keeps it out of the verified file (a struct value would do, as `VarIntLen` a few lines away already shows) but `append`, which this Gobra frontend will not accept in a verified function in any spelling the Go surface offers -- "append expects first argument of type perm followed by a slice of type []Type and a variadic type Type... but got []byte, uint8" -- and annotating the parameter `acc(b)` or `acc(b, 1/2)` does not change the diagnosis. **A verified function may read, slice and compare bytes; it may not grow a slice**, which rules out encoders outright and rules out any parser that accumulates into a buffer: phase 4's verified half is confined to functions whose result is a decision or a view of what arrived. **Premise, named rather than assumed:** that the length handed to the guard is the length that was parsed and that nothing allocates in between — that ordering is four lines inside `ParseSSHString`/`ParseSSHBytes`, in a file the prover cannot read (`io`, `fmt`), and the tests above are what pin it |
| SR-PARSE-02 | `ParseBearerAuth` never panics for an `Authorization` value shorter than the prefix and only strips the prefix when it is really present (case-insensitive, ASCII). | `server_auth/handlers.go`, `util/util.go` (`EqualFold`) | **[proved:model]** `proved` (model: `proof/bearer/model.gobra`: memory safety for every header and every prefix length; the length guard is exactly the prefix length and is what refuses a short header; `ok` implies the prefix is really there and the token is byte-for-byte the remainder; a refused header yields the empty token; the fold is per-byte, reflexive, symmetric and ASCII-only, so the prefix cannot be smuggled in through Unicode case-variants) + `conformant` (`server_auth/bearer_conformance_test.go`). The one fact Gobra cannot check — that the prefix constant *is* the seven ASCII bytes — is pinned by that test, which also drives the real `ParseBearerAuth`, `HandleBearerAuth` and `util.EqualFold`. |

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

### F2: two disagreeing `identity_option` values resolve silently (SR-PERM-11)

The docs say `identity_option` may be repeated. `ParseIdentityOptions` does iterate all
values, so a *set* of restrictions accumulates — that part matches. But `identity_type` and
`client_id` are scalar fields assigned by each occurrence, so for

```
identity_option=identity_type:users,identity_option=identity_type:certs
```

the last value wins and the first is dropped with no error and no log line. The identityopts
unit documents this (`parseIsFailClosed` states it: every listed option is processed, scalars
by last assignment) rather than proving it away, because the model must describe the code that
runs.

This is a deviation from the documented behaviour, not a memory-safety or authorisation bug:
the winning value is still one the administrator wrote, and an empty `client_id` is still
caught downstream, where the identity is resolved. It is recorded because "silently ignore half of an administrator's
configuration" is the kind of thing an operator finds out the hard way. Options are to reject
a repeated scalar with conflicting values (fail closed, like a bad option value already does)
or to merge them and say so in the docs; either way the unit should prove whichever contract is
chosen. Not changed here, because it changes behaviour for configurations that exist today.

### F3: `-force-command-mismatch-exit=0` turns a restriction into advice (SR-PERM-09)

With that flag, a request whose command differs from `force_command` is *allowed*, and the
client is told the command it ran anyway. The restriction therefore holds only when the flag
keeps its default. That is deliberate (it is how a forced-command server can be used
interactively without losing the log line), but it means SR-PERM-03 is conditional on a
command-line flag, which the requirement text and `docs/server_config.md` do not say. The
identityopts unit models the refusing behaviour, so the flag is one of the places where the
proof and the deployed server can diverge; noted in that requirement's row.

### F4: the code moved out from under the models, twice (process, not a bug)

Between the first and the seventh unit, the identity-option code moved from `auth/oidc` to the
root package, the Bearer header parser moved from `auth/oidc` to `server_auth/handlers.go`, and
the JCS canonicalisation code was removed altogether — taking its proof unit and its catalogue
rows with it. Nothing failed. That is the failure mode of modelling instead of annotating: a
model that cites a file which no longer exists keeps verifying happily while describing nothing.

What keeps it honest is mechanical, and now in place: every model header names the tracked file
and function it models; every model has a `TestConformance...` test beside the code it models, so
the selector in `make proof-conformance` reports "no tests to run" when code moves out of a
package without its test — which is exactly how the drift above was caught; and the catalogue
rows name the same files. Deleting the JCS unit was then a removal in three places rather than a
slow rot. It was still three places, which is the argument for Phase 3: specs written into the
production files, where moving a function moves its proof or fails to compile.

### F5: a `from=` pattern could make the server work for three minutes (SR-RES-05)

`matchGlob` used to be the natural recursive matcher: for a star, try the rest of the pattern after
every possible prefix of the text. That is correct, terminates for every input, and is exponential in
the number of stars whenever the match fails late. Measured on the code as it was, against an
eighty-character text:

| stars in the pattern | time |
| --- | --- |
| 6 | 18 ms |
| 8 | 398 ms |
| 10 | 4.9 s |
| 12 | 36 s |
| 14 | 2 m 56 s |

Nothing bounds that. The pattern is not the peer's bytes, but it is not the administrator's either:
`from=` is an identity option, and identity options reach the server through the identity's own
option string, so a configuration — or a token claim, where the listener's attestation is what
stands between the two — with a handful of extra stars turns each authentication attempt that
carries it into a CPU burn, before the peer has been told anything. The throttle limits how often a
source address may try; it does not limit how long one check takes.

Fixed by replacing the recursion with the two-pointer matcher (`matchGlob` now), which needs no stack
beyond its own frame and runs in `len(pattern)+len(text)`: the same eight worst-case patterns, 60
stars included, now take 1.9µs in total. The rewrite is pinned by agreement rather than by argument —
the old recursion is kept verbatim in `identity_options_source_conformance_test.go` and compared with
the shipped matcher and a third, differently-written linear matcher over 530 255 triples, and the
time bound is a test so that a future "simpler" recursion fails CI. That the agreement corpus had to
be widened for this rewrite to be pinned at all is F6.

This is also the finding that says where the boundary of the proof programme is. SR-PERM-07 asks for
termination of a recursive string function, which is exactly the shape Gobra v26.09 will not take: a
recursive pure function's `decreases` measure is checked, and the function is then opaque, so no
concrete call can be proved of it (`f(3)` over ints unfolds; `gm("a","a",0,0)` over strings does not,
and slicing inside a pure function additionally needs element permissions). Recursion over integers
belongs in the prover; recursion over strings is settled by reference implementation and exhaustive
agreement. That is a line, drawn by experiment, and the catalogue now says which side of it each
requirement is on.

### F6: the linear matcher read a `*` in the *text* as a wildcard (SR-PERM-07)

The annotations Gobra checks in `glob.go` are the first written against shipped code instead of a
model, and the first thing they turned up. Both linear implementations — `matchGlob` and the
independently written `conformanceGlob` — tested "this pattern character equals this text character"
*before* "this pattern character is a star". A `*` arriving in the **text** is an ordinary character,
but it is equal to the `*` in the pattern, so it was consumed by the literal-equality case, no star
position was saved, and when the tail of the pattern failed there was nothing left to retry against:

```go
matchGlob("a*", "a*b") // was false; OpenSSH's match_pattern() — and the recursion the linear
                       // rewrite replaced — both say true: the star may stand for "*b"
```

Three things about it are worth writing down.

* *Reachability*: none, in the server. `matchesSourcePattern` applies the glob only to `ip.String()`
  (and to `ip.To4().String()`), and a formatted address never contains a star, so no `from=` value
  could be affected — and the error was in the *rejecting* direction, which refuses a login rather
  than granting one. It is recorded because the class is right even though the instance is harmless:
  the matcher is a general-purpose function with a documented meaning, and it did not have that
  meaning.
* *Why the safety net missed it*: the agreement corpus generated texts from `{a, b, .}`. No text in
  it could express the difference between the two orders, so 188 155 triples of agreement proved
  nothing about it — and the two implementations that agreed with each other share the same folklore
  about how a two-pointer glob matcher is written. Exhaustive agreement over a corpus that cannot
  state the difference is not evidence; the prover found it because it was asked to show something
  about `"*"` rather than shown examples.
* *What fixed it*: the star case moved in front of the equality case in both linear implementations;
  `*` joined the *text* alphabet, so the corpus is 530 255 triples and the two orders now separate
  (`TestConformanceMatchGlobIsTheGlob` fails on the old order); and
  `TestConformanceMatchGlobStarInText` keeps the hand-written cases with the old recursion as the
  reference, since that recursion is the implementation which encodes OpenSSH's order.

The proof of the ordering itself is not in Gobra — the prover cannot say "this case is tried first"
about a `switch`; what it can say, and now does, is what the function returns for the patterns whose
behaviour the two orders disagree on.

### F7: the sentence above the throttle's refusal counted one attempt too many (SR-AUTH-08)

`beforeAttempt` — the function that delays and refuses repeated password failures — carried this
sentence for as long as it existed:

```go
// ... returns an error when that key has failed more than maxFailures times since the
// beginning of the current window.
```

The code says `entry.failures >= maxFailures`, and the model in `proof/throttle/model.gobra` says the
same. So with a limit of N, the attempt made after the Nth failure is already refused: prose and code
differ by one guessing attempt. The code and the model were right and the sentence was wrong —
`docs/server_config.md` describes the option as the number of failures after which a source is
refused — so the fix was the comment, and the boundary is now an artifact instead of a sentence:

```go
// @ ensures refused == (failures >= maxFailures)
// @ ensures failures == maxFailures ==> refused
// @ ensures failures < maxFailures ==> !refused
```

and `TestConformanceRefusalBoundaryIsTheLimit` checks it for limits 0..6 at `limit-1`, `limit` and
`limit+1`, both on the rule and through `loginThrottle.check`.

No consequence at the configured limit — one password hash per window per key, in the direction that
refuses more, not fewer. The reason it is recorded is the class: the same off-by-one in the other
direction would have doubled the free guesses available to an attacker, and neither the prose nor the
bare `>=` in the code distinguishes the two readings. A property nobody wrote down cannot be reviewed,
and a comment is not a property — this one was wrong while the function it sat above was being read
in code review for years. Writing the spec costs three lines and forces the question the comment
skipped.

The same exercise turned up one place where the delay cap is a premise rather than a theorem: Go's
`int` is 64 bits, so `failures * step` overflows instead of saturating past about 9.2 billion failures
in one window. It is unreachable in a five-minute window, and the consequence is benign — a wrapped
delay is small or negative, `beforeAttempt` only sleeps on a positive one, and the count towards the
lock-out is untouched — so nothing was changed; `TestConformanceFailureDelayAtTheOverflowBoundary`
records that the shipped rule wraps exactly like the expression it replaced, which is all the
assurance that region can get from a test.

### F8: the ceiling that protects the process had no requirement, and no test (SR-PARSE-03)

`util/wire.go` has carried, since before this catalogue existed, a guard whose own comment describes
the failure it prevents:

```go
// MaxFieldLength is the absolute ceiling applied to any length-prefixed field ...
// a 10-byte message announcing a 2^62-1 length makes the process allocate up to
// 4 EiB of address space, and any length above Go's maxAlloc makes `make`
// panic ("makeslice: len out of range"), which kills the whole process.
```

That is a remote, unauthenticated, one-packet denial of service, and the catalogue had no row for it.
Nor did the code have a single direct test: `grep` for `VarIntLen`, `ParseSSHString` and
`checkFieldLength` across `util/*_test.go` before this change found nothing, so the guard was
protected by the fact that other tests happened to pass through it. The proofs and the eight tests
now attached to it are the subject of **SR-PARSE-03**; what is recorded here is how the gap came
about, because it is a different kind of gap from the rest of this document.

Every earlier requirement in this catalogue was written by reading the code and asking what it
promises. This one was missed because the promise lives in a *comment above a constant*, not in a
function name or a returned error: the guard reads as configuration (`MaxFieldLength uint64 = 1 << 24`)
rather than as a security property, and inventorying requirements by decision points walks straight
past it. The corrective is procedural and is now part of phase 4's method: constants whose declared
purpose is a bound, and any `make`/`append` whose size comes from the peer, are requirements whether
or not a decision depends on them.

One reassurance came out of the exercise, and it is the reason this is a catalogue finding rather than
an incident: the guard itself was correct. `fieldCeiling` and `fieldLengthAcceptable` are the two
halves of `checkFieldLength`, lifted unchanged, and they verify against a bidirectional spec — so the
refusal is exact (`length > ceiling`) and the acceptance is exact too (`length <= ceiling`), which
means the ceiling never silently refused fields it should have served. An off-by-one in either
direction, introduced later, now fails both the prover and `TestConformanceCheckFieldLengthAgreesWithThePredicate`.

### F9: the version gate's row claimed it was covered by unit tests, and nothing tested it (SR-TR-03)

SR-TR-03 said *"out of scope for Gobra ... covered by unit tests"* from the day this catalogue was
written. The first half was right — `version.go` imports `fmt` and the zerolog logger, so the prover
could not read the file where the decision lived. The second half was not. `grep` for
`IsVersionSupported`, `ParseVersionString` and `AVAILABLE_CLIENT_VERSIONS` across every `*_test.go` in
the repository found no caller of any of the three. The gate that decides, before a password, a token or
a certificate is offered, whether a peer may proceed at all had never been asserted about; the status
cell described tests somebody had assumed existed.

The tests written alongside the proof are the first, and they found nothing to fix and two things worth
recording. The first is that the legacy window is a window and not a floor. Inside protocol 3.0 with an
empty spec version, this project's own 0.1.3, 0.1.4 and 0.1.5 are accepted and 0.1.2 is refused as too
old — but so is 0.1.6, because the branch is guarded by `patch <= 5` and falls through to a comparison
that an empty spec version cannot satisfy. That is correct today (no 0.1.6 ever announced an empty spec
version) and it is *history* rather than policy: a hypothetical release that forgot to announce a spec
version would be refused rather than accepted as newer. Nothing in the code said so, and the boundary is
now a spec line with a literal in it plus four rows of a table, so the next reader learns the window
instead of redrawing it.

The second is that the same history is written down twice, in two different forms: the list
`AVAILABLE_CLIENT_VERSIONS` (the versions this project's client may announce) and the comparison inside
the gate. They agree today — every version in the list is one the gate accepts — and they are maintained
by different means, so `TestConformanceEveryVersionTheClientMayAnnounceIsSupportedByTheServer` is what
stops an edit to one of them producing a client that announces a version its own server refuses.

The same audit run in the other direction found the opposite error. SR-PERM-03 said "partially proved"
and explained that order-independence was left to a conformance test rather than a lemma. It is not left
there: `parseOptions` in the model has carried, since the **F5**/**F6** work, a closed form for every
field of the result -- `noPty` equals "some name in the list was `no-pty` or `restrict`", and so on -- and
a closed form mentions only which names occur, so monotonicity and order-independence were already
corollaries of a clause the prover checks. The row had simply not been re-read after the model changed,
which is the failure mode of a ledger kept by hand: a status column describes the proof as of the last
time someone looked at the row, not as of the last time someone looked at the proof. The row now says
what is proved, and the shipped parser was then held to the same closed form over every subset of the
enforced names, so the upgrade is not only a reclassification.

The corrective is procedural, and it is the second one this catalogue has had to write about itself.
**F8** was a requirement missed by inventorying decision points; **F9** is a coverage claim missed by not
looking. A status cell that says "covered by tests" is now written only after a `grep` for the symbol in
`*_test.go`, because the column is the argument's ledger and an unchecked entry in it is worse than an
admitted gap.

### F10: the rejection path panicked on a short User-Agent (SR-TR-04)

The oldest finding in this list is the one that never had a section. `F10` is named in the row above, in
`proof/README.md`'s description of `server_auth/truncate.go`, and in two commit messages, and until this
paragraph existed it named nothing. An identifier used as if it were defined is how a stale ledger reads:
the reader fills in a bug they half-remember and moves on. What keeps that from happening again is
`TestConformanceFindingsAreWrittenUp`, one of the five checks in `proof_ledger_conformance_test.go`, which
resolves every `F<digit>` reference to a section and every section back to a reference; the gap itself was
found by running those queries by hand, in a shell, before they were written as a test.

The authentication handler's first act is to read the request's `User-Agent` as a version string, and when
that parse failed it reflected the header back in the response body:

```go
http.Error(w, fmt.Sprintf("Unsupported user-agent: %s", r.UserAgent()[:100]), http.StatusForbidden)
```

`r.UserAgent()[:100]` slices a string the client chose. A header shorter than 100 bytes makes Go panic --
*slice bounds out of range* -- and every real client, scanner and browser sends one far shorter than that;
the only agent reliably long enough was this project's own. So the code path whose entire purpose was to
answer an unrecognised announcement with a clean 403 panicked instead for the ordinary ones, and the peer
received `H3_INTERNAL_ERROR` from a request that had not authenticated. No restriction was bypassed, which
is why it is not an authentication finding: what it cost was a goroutine and a connection per datagram,
chosen by the sender, on the path that runs before any credential is looked at.

The fix, in `0453c81` (the security-audit commit whose message lists it as "no panic on short User-Agent"),
stops reflecting the header at all and logs it through a bounded `truncate`; the comment now above the call
site says the same. What this directory contributed afterwards is the part that lasts: `truncate` is
verified where it ships, so a non-positive bound yields the empty string, a header that fits comes back
identically -- the sentence the old slice could not make true -- and a truncated header is between three
bytes and `max+3`, which bounds what one attacker-chosen header can do to a log line. The bounds argument
this finding is about is discharged by the checker rather than by a reader, because the scan that backs off
a split multi-byte character may index `s[cut]` only under the loop invariant that places `cut` inside the
string. Putting `[:100]` back fails `make proof`; `TestConformanceTruncateMatchesTheModel` holds the
surviving prefix to the model, which is the half the prover cannot reach.

## Roadmap

1. **Phase 1 (this work)** — toolchain (`scripts/setup-gobra.sh`, `make proof`,
   `make proof-conformance`, the `proof.yml` workflow), this catalogue, and eleven proof files:
   eight verification units (`authflow`, `truncation`, `throttle`, `identityopts`, `replay`,
   `bearer`, `knownhosts`, `sourcecheck`), the canary, and `glob.go` — a shipped file carrying its own
   specs. Any bug a proof or a conformance test
   surfaces gets fixed and recorded here with the requirement ID it violates: F1 (the throttle's
   memory bound, fixed), F5 (a `from=` pattern could cost exponential time, fixed), F6 (the linear
   matcher mis-read a star arriving in the text, fixed), F7 (the sentence describing the throttle's
   refusal count was off by one, fixed in the comment and now stated in a spec), and F2, F3, F4
   (behaviours the tests pinned rather than changed, each waiting on a product decision).

   The list above is what Phase 1 delivered. `make proof` now runs seventeen units: the ten models
   above plus six shipped files that carry their own specs — `glob.go`, `identity_checks.go`,
   `source_check.go`, `server_auth/throttle_rules.go`, `server_auth/truncate.go`,
   `util/varint.go` and `version_rules.go`.
2. **Phase 2** — what is left of the non-crypto surface, in the order that buys the most: the
   x509/base64 layer of `ParseKnownHosts` (SR-TR-02 is proved for the classifier; whether a line's
   data decodes to a certificate is a premise there and a test elsewhere). Persistence needs no
   unit: the store has no serialiser, only `AppendKnownHost`, and
   `TestConformanceAppendLeavesTheFileItFoundAlone` holds it to that at the byte level — every line
   it found, including comments, `@cert-authority` markers and lines the parser refuses, survives an
   append unchanged, and the file gains exactly one line. The token *validation* path
   around the replay store (SR-AUTH-01..04: signature, `iss`, `aud`, `exp`) is the largest remaining
   hole in the authentication story and needs a model of the JWKS fetch, which is why it is not in
   this phase. The case-folding step the identity-options model is handed (SR-PERM-08) landed with
   the `from=` work.
3. **Decide the two known deviations** — both are one-line-scale, and both are decisions rather than
   work, which is why they are still open. SR-PERM-11 (two `identity_option` values that disagree
   silently keep the last one): the recommendation is *accept an identical duplicate, refuse a
   conflicting scalar*, because `ParseIdentityOptions` already refuses `duplicate command="..."` and
   `from` accumulates, so the rule is the one the file already uses and it cannot break a
   configuration where every copy says the same thing; then the identityopts unit proves whichever
   contract is chosen. SR-PERM-09 (`-force-command-mismatch-exit=0` turns the forced-command
   restriction into advice): no code change recommended — the flag is deliberate — but
   `docs/server_config.md` and the requirement's own text should say that the restriction is
   conditional on the flag keeping its default, since the proof models the refusing behaviour and the
   deployed server may not.
4. **Phase 3 (started)** — push specifications into the production files themselves where Gobra can
   read them, so that the annotated code *is* the verified code and no transcription is involved.
   `glob.go` was the first: `matchGlob` moved out of `identity_options.go` unchanged, carrying its
   `// @` specs, terminating on a checked measure, verified by `make proof`. `identity_checks.go` is
   the second and the more instructive one, because it needed a change rather than a move: the
   channel-request and channel-open gates now compute a verdict that the proof covers, and
   `identity_options.go` turns that verdict into the message it always produced. That is the pattern
   for everything else in this category.

   What decides whether a file can join is what the prover can read, not difficulty. Two boundaries
   have been hit and both are now drawn in the code. The first is imports: Gobra v26.09 ships stubs
   with real specs for `strings` and `net`, and stubs that say "we do not support members defined in
   this package" for `fmt` — so a file that formats an error with `fmt.Errorf` cannot be verified
   where it lives until the formatting is separated from the decision.

   `source_check.go` is the third unit and it found a second boundary, one that took three
   restructurings to see: **permissions**. Slice elements are heap in a Gobra spec, so the natural
   statement of this rule — `exists k :: negated[k] && matched[k]`, written in the contract of an
   ordinary function — is refused as "Method contract is not well-formed. Permission to negated[k]
   might not suffice", and even a *pure* function must be told it may read its arrays
   (`forall i :: acc(&negated[i])`, the form Gobra's own `net` stubs use). That permission can then
   not be handed on: an impure caller that requires it cannot satisfy the precondition of a pure
   callee that asks for it, reported as "Precondition of call might not hold" and irreparable from
   Go — it is Silicon's handling of quantified permissions, not a missing annotation. What lands is
   therefore split where the prover stops: the array readers are pure functions taking the arrays and
   the permissions, and the rule itself takes their answers as plain `bool`s, which is where every
   clause of SR-PERM-06 is proved without touching a heap.

   The trivia, so the next file does not rediscover it: quantified variables need explicit types in
   the Go frontend (`forall k int ::`, not `forall k ::`); loop invariants and `decreases` go *above*
   the `for`, not in the body (in-body annotations are a parse error, "unexpected …, expecting
   forStmt"); every `pure` function needs a `decreases` measure; and `pure` further requires the body
   to be a single `return` of a pure expression, which is why there is no proved helper for stripping
   a leading `!` — "trim it if it is there" needs a branch.

   `server_auth/throttle_rules.go` is the fourth unit and it moved two more things about the
   method. A verified file need not live at the repository root: Gobra is handed a *directory* as a
   package, so a file in `server_auth/` verifies on its own as long as it stays free of what the
   prover cannot read — and it must stay free of its own package-mates too, since those are not
   handed in with it. What blocks that file, and `known_hosts.go`, and the auth code, is `fmt`: its stub says "We do not
   support members defined in this package". `time` by contrast *is* stubbed, with real specs --
   `Duration` arithmetic and pure `Before`/`After` are there to be claimed against -- which is worth
   recording precisely, because a file whose entire subject is durations invites the assumption that
   the clock package has to be abstracted away: `throttle_rules.go` speaks `time.Duration` and
   converts nothing. What Gobra v26.09 ships, in full, is `bytes`, `encoding`, `errors`, `fmt`
   (signatures only), `net`, `strconv`, `strings`, `sync` and `time` -- which is also to say there is
   no stub for `crypto/x509` or `crypto/ed25519`, so `known_hosts.go` has a second reason besides
   `fmt` to stay a modelled requirement. An earlier revision of this document said there was no
   `time` stub at all, on the strength of one failed import whose actual cause was elsewhere; the
   sentence is corrected here because a wrong claim about the toolchain gets copied into the next
   design decision. Two frontend details came with it: `min` and `max` are unknown
   identifiers in a `.go` file (so a cap is an `if`, and a function that a spec must call has to be
   rewritten or the claim moved into a lemma function), and `before` is a reserved word — using it as
   a variable name is a parse error.

   Next in this category: `known_hosts.go`, which needs the same treatment for its parser errors;
   `server_auth/login_policy.go`'s `truncate`, which is pure and stdlib-free but whose claims are all
   about string slicing and concatenation, where the prover has no theory (see F5's notes).
5. **Phase 4** — `message/` wire parsing (bounded slicing for every message type) and the
   SFTP path handling in `sftp/server.go`, where directory traversal and permissions are the
   interesting properties. What the toolchain offers for that, measured rather than hoped: it
   stubs `encoding/binary` with *pure* `Uint16`/`Uint32`/`Uint64` over `[]byte` for both byte
   orders — which is exactly the primitive the wire format's length prefixes need — but it does not
   stub `io` or `bufio`, and both `message/message.go` and `message/channel_request.go` import
   `fmt` as well. So `ReadFrom(io.Reader)` cannot be verified as it stands, and the Phase 4 shape is
   the one this catalogue already used three times: split the *decision* out of the reader — a pure
   `parse(data []byte) (msg, rest []byte, ok bool)`-shaped function that says what a byte sequence
   means and how long it is — verify that, keep the I/O beside it unverified, and cover the seam with
   a conformance test. The bound that matters (`a length field may not make us read past the datagram,
   and may not be trusted to size an allocation before it is checked against what arrived`) is a
   statement about `data`, so it survives the split intact. The first slice of that plan is in: `util/varint.go` carries the length arithmetic -- the encoding width, the reader ceiling, the accept/refuse decision, the SSH field sizes -- proved as **SR-PARSE-03**, with the readers left where they are and held to it by eight tests. Doing it first also turned up **F8**: the ceiling itself, guarding against a one-packet 4 EiB allocation, had no row in this catalogue and no direct test anywhere, because a promise written as a constant with a comment does not read as a decision point.
6. **Phase 5** — the conversation/channel state machine: transitions under concurrency
   (predicates, mutexes, goroutines — Gobra is good at this), which is where the remaining
   use-after-close and double-close class of bugs lives.

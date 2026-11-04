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
| SR-AUTH-05 | A Bearer/JWT credential is only accepted against one of the identities authorized for the asserted user; an empty authorized-identity set never authenticates. | `server_auth/handlers.go` (`HandleJWTAuth`); what an accepted verifier then insists on is SR-AUTH-12 (public key) and SR-AUTH-06/07 (OIDC) | **[proved:model]** `proved` (model: `proof/authflow/model.gobra`) |
| SR-AUTH-06 | An OIDC token that carries no conversation-binding claim (`ssh3_conv_id`, `jti`) is **rejected**; a token bound to another conversation is rejected. A captured ID token is therefore not replayable on an arbitrary conversation. | `server_auth/authorized_identities.go` (`OpenIDConnectIdentity.Verify`) | **[proved:model]** `proved` (`proof/oidcbinding`) + `conformant` — the unit models the binding decision and proves: a token carrying neither `ssh3_conv_id` nor `jti` is refused whatever else is true of it; a token is accepted for **at most one** conversation, because the value compared is the server's own id and not one the token names (so a captured token cannot be re-bound by whoever holds it); a `jti` naming this conversation does not rescue a token whose `ssh3_conv_id` names another; the replay key is `jti`, else the binding value, and is never empty at a point where the token is accepted; a refusal from the replay store is not advisory; and the identity check comes first, so a binding claim cannot buy a conversation on somebody else's identity. Signatures, `iss`, `aud` and `exp` stay premises (SR-AUTH-01..04) — they go through `go-jose` discovery, out of Gobra's reach either way. The two steps the model cannot see are checked in Go: `TestConformanceOIDCBindingBlockIsTheModelledDecision` holds `Verify` to the claim order and the compared values the proof assumes (a structured read of that one method, which fails with the message "change the model with it"), and `TestConformanceConversationIDEncodingIsInjective` shows the base64 form of a conversation id distinguishes ids — exhaustively on short inputs at every offset, bit by bit over all 256 bits of a real id, and 20 000 random pairs — because otherwise two conversations would share one binding value and the "at most one conversation" theorem would be about encodings, not connections. |
| SR-AUTH-07 | **Replay**: for a token identified by `(issuer, id)`, `Accept` returns true at most once while the remembered entry has not expired; an empty `id` is always refused. | `auth/oidc/replay.go` (`AcceptedTokenStore.Accept`) | **[partial]** partially `proved` — `proof/replay/model.gobra` proves, for every store state and every token: an empty `id` is never accepted; a token is refused exactly when it is remembered and still live; a refusal leaves the store exactly as it was (so replay traffic can neither evict nor grow it); and the store stays inside its capacity for *every* trace of tokens. Not modelled: the signature/`iss`/`aud`/`exp` validation which happens before the store is consulted (SR-AUTH-01..04, still open) and the clock itself, which enters the model only as the two booleans the code actually asks it. + `conformant` (`auth/oidc/replay_conformance_test.go`) |
| SR-AUTH-08 | **Password guessing is bounded**: within one failure window, a key that already failed `maxFailures` times is refused (`429`) *before* the password is checked, so further guessing costs no hashing. A successful login clears the counter for that key. | `server_auth/throttle_rules.go` (`windowElapsed`, `attemptIsRefused`, `failureDelay`, `retryAfter`, `failureDelayGrowsWithFailures`), `server_auth/login_policy.go` (`loginThrottle.check/failure/success/startWindowLocked`) | **[proved:shipped]** `proved` on the shipped arithmetic: the four questions `check` asks of its state are functions with contracts in `throttle_rules.go` — a window closes *strictly* after its length (so an exactly-as-old window still counts, and a clock that steps backwards hands nobody a fresh window); `attemptIsRefused` is `failures >= maxFailures` with the boundary stated on both sides, which is what finding **F7** is about; the delay is `failures x step` capped at `max`, never negative, zero exactly when there were no failures; and `RetryAfter` is floored at zero, because a refusal that reports a negative wait tells the client to come back before now. `failureDelayGrowsWithFailures` is the monotonicity lemma, kept next to the rule it quantifies over. `conformant` around them: `TestConformanceCheckAppliesTheRules` drives the real `check()` — table, window reset, refusal and delay — over four windows x four steps x four caps x eight clock positions x six failure counts, comparing with the pre-split expressions as finding **F6** requires; `throttle_rules_conformance_test.go`'s `TestConformanceThrottleRulesAreTheExpressions` checks each rule against the lines it replaced *in the same units the call sites use*, and `TestConformanceThrottleDelayIsInTheUnitsItLooksLike` says a step of one second still produces three seconds after three failures rather than three nanoseconds; `TestConformanceRefusalBoundaryIsTheLimit`, `TestConformanceThrottleDelayProperties`, `TestConformanceWindowExpiryIsTheComparison` and `TestConformanceFailureDelayAtTheOverflowBoundary` cover the boundary, the shape, the two consequences of strictness and the one place the cap is a premise. Outside the proof: the table, the mutex and the clock reading itself. `time` is not the obstacle — Gobra stubs it with real specs, `Duration` arithmetic included, so the rules speak Durations and convert nothing at the seam; `fmt` is the obstacle, which is why they are not in `login_policy.go` at all (below), and `TestConformanceThrottleDelayIsInTheUnitsItLooksLike` is the check that a split which moved no conversions could still have broken in units. The window *reset* keeping the table bounded is SR-RES-01 (**F1**) and `login_policy_test.go` covers it; `proof/throttle/model.gobra` remains as a second opinion. |
| SR-AUTH-09 | Early data (0-RTT) is never authenticated: requests arriving before the TLS handshake completed are refused (`425 Too Early`), which is what makes the replay-resistance claims above meaningful. | `server_auth/auth.go` | **[out-of-scope]** **out of scope for Gobra** (quic-go `ConnectionState()`); covered by integration tests |
| SR-AUTH-10 | The set of things that may authenticate a user is fixed before the server serves, and no plugin can widen it by accident: registration after the registry is closed is refused with `util.ClosedPluginsRegistry` and changes nothing; a duplicate plugin name fails loudly and the plugin registered *first* is the one that survives; a plugin that errors, or that returns no identity for a line it does not recognise, contributes no identity -- an identity exists only because a verifier a plugin returned accepts it, and an empty registry authenticates nobody (**F12**). | `internal/plugins.go` (`pluginsRegistry.registerPlugin`, `closeRegistry`, `FindIdentitiesFromAuthorizedIdentityString`, `GetPluginsCLIArgs`), `auth/plugins/plugins.go`, `server_auth/auth.go` (`WrappedPluginVerifier`), `internal/plugins_conformance_test.go` | **[conformant]** Five tests, the first this package has had. `TestConformanceRegistrationIsRefusedAfterClose` refuses a late registration, checks the error *is* `util.ClosedPluginsRegistry` rather than merely non-nil, checks the map is untouched, and checks that closing twice neither reopens nor drops anything; `TestConformanceDuplicateNameFailsLoudlyAndKeepsTheFirstPlugin` pins the direction of the collision -- the panic happens before the map write, so the first plugin is still the one that answers that identity line -- and that the mutex is not left held, so the registry still works afterwards; `TestConformanceNilRegistryPanics` covers the two degenerate registries; `TestConformanceIdentitySearchIsFailClosed` runs the search fifty times over a registry holding a broken plugin, a plugin that recognises nothing and a plugin that produces a verifier, because map iteration order is random and the answer must not be, and expects exactly one identity every time; `TestConformanceClientOptionNamesCannotCollide` is the same no-shadowing rule on the client side, where two plugins offering the same config keyword are an error and the refusal returns no half-built map. Not proved, and not modelled: the verifiers themselves are plugin code behind an interface (`auth.RequestIdentityVerifier` is a premise about whoever wrote the plugin), the registry is a mutex-guarded map so the concurrency is a premise, and the panic-on-duplicate policy is documented behaviour rather than a claim -- what is tested is *which* plugin survives it, because that is the part with a security consequence. |
| SR-AUTH-11 | A login is refused for an account the system considers closed, *before* the password is compared, so knowing the password buys nothing: a password field that is empty or begins with `!` or `*`; `sp_flag` carrying a lock bit, but only when that field is actually set (glibc reports all bits set for an empty one, so taken at face value it would lock out every account on the system); an account past `sp_expire`; a password past `sp_lstchg`+`sp_max`, which this server cannot ask the user to change; a login shell that is missing, relative, or one of the programs that opens no session; or any non-root account while a `nologin(5)` file exists. `-1` means there is no rule; `0` is a date. | `util/unix_util/account_rules.go` (`passwordFieldIsLocked`, `accountIsExpired`, `accountExpiryIsMonotone`, `passwordIsExpired`, `loginShellNeedsRefusing`, `pathBaseName`, `pathIsAbsolute`, `shellsLineCarriesNoPath`, `firstSpaceSeparatedField`), `util/unix_util/account_policy.go` (`CheckAccountUsable`, `lockedPasswordReason`, `checkLoginShell`, `shellIsListedIn`), `util/unix_util/account_rules_conformance_test.go` | **[partial]** The decisions are verified in the file the server calls, which is listed with the other in-place units in `scripts/run-proofs.sh`: each is bidirectional, the unset-`sp_flag` rule and the `-1`-means-never rules are explicit, and expiry is `>=` on the day itself. Three mutants die twice over -- the expiry boundary (1 prover error, 6 test failures), the unset-flag guard (1, 13), the relative-shell clause (1, 4). What keeps the row `partial` is named: the fields are what `shadow(5)` and `Getspnam` say they are, `today` is `time.Now()`, and the two filesystem questions -- the contents of `/etc/shells` and the presence of the nologin file -- are asked of the machine. `pathBaseName` is proved only to its length clauses: the prover will not carry "no slash at these positions" across the point where the return value becomes a suffix, because `name[i]` and `trimmed[i0+1+i]` are the same byte and different terms, so the no-separator clause is stated in `TestConformancePathBaseNameIsFilepathBase` instead, over 26 paths and against `filepath.Base` itself (likewise `pathIsAbsolute` against `filepath.IsAbs`); `loginShellNeedsRefusing` is therefore proved *given* the program name and the test supplies it. Also tested, because they are where a shells file is misread rather than mis-decided: the line grammar of `shells(5)` (`TestConformanceShellsFileParsing` -- a commented-out entry admits nothing, an entry with an argument admits its path), the ten closed-account shapes through the gate itself (`TestConformanceGateStillRefusesEndToEnd`), and the one edge the prover cannot see at all -- `sp_lstchg + sp_max` overflows in Go and is unbounded in Gobra, and the wrapped answer refuses rather than admits (`TestConformancePasswordExpiryOverflowRefuses`). **Not covered: the gate is on the password path only -- finding F14.** |
| SR-AUTH-12 | The public-key credential is checked by the key, not by the claim: a Bearer JWT authenticates a user **only** if the key named in that user's `authorized_identity` line verifies its signature with an algorithm that key type allows (`RS256`, `EdDSA`, `ES256`), `iss` is the user, `sub` is `ssh3`, `aud` is `unused`, `client_id` is `ssh3-<user>`, `jti` is **this** conversation's base64 id, `exp` is present and not past (plus a 60 s leeway), and -- after all of that -- the connection comes from an address the identity line permits (`from=`). **No bypass**: each clause refuses on its own, the checks are made on the parsed-and-verified token rather than on a decoded one, and the signature is verified before any claim is read. | `auth/plugins/pubkey_authentication/server/server_plugin_conformance_test.go` — seven units over real tokens: the client's own `BuildJWTBearerToken` verified through `PubkeyAuthPlugin` (the seam, so a claim renamed on one side fails rather than drifts), then one arm per claim in both directions with an accepted control inside the refusal table; a token signed by another key, a MAC token "signed" with the public key (algorithm confusion), an unsigned `alg: none` token, and a well-formed token with its signature stripped, all refused; `from=` enforced on the connection rather than on the token, with the same key unrestricted when the line says nothing; the identity-line shapes that must yield *no identity and no error* so a different plugin may answer (SR-AUTH-10, F12); and the malformed `Authorization` forms. | **[conformant]** the decision table over claims and connection is exercised exhaustively in both directions, the signature itself is a premise (crypto has no specs). `TestConformanceMissingExpiryIsRefusedByHand` measures the one line that is not the library's work: it refuses a token with no `exp` **and** shows `jwt.Parse` with the same options accepts that same token, so the hand-written presence check is pinned as load-bearing rather than left to be deleted as redundant (F15). |
| SR-AUTH-13 | A password authenticates **only** when `crypt(candidate, stored)` reproduces the stored string byte for byte, in a comparison that does not stop at the first difference; a stored value libc cannot use is a **hard refusal**, never a mismatch to ignore -- which matters because `crypt(3)` answers an unusable setting (`*`, `*LK$`, `!!`, `$99$x`, bcrypt's `$2b$`) with a string of its own rather than with an error, so a bare `==` against a locked account would compare equal for *every* guess; and the `C.CString` truncation at a NUL byte, on either side of the call, must never widen what is accepted. The salt is read out of the stored string: nothing about the candidate chooses it. | `util/unix_util/password_compare_conformance_test.go` — three hash families (md5-, sha256-, sha512-crypt) taken verbatim from `openssl passwd`, each accepting its password and refusing the near-miss at the end, at the start, empty, a prefix, an extension, a leading and a trailing space, and the hash of a *different* password presented as the candidate; the same password under a second salt, so the salt is seen to come from the stored string; the unusable spellings refused for four candidates each, with the error text asserted so the test says *which* guard fired; `$6$` -- an algorithm marker with an empty salt -- measured as usable and refused by the comparison instead, so the two refusal routes are distinguished rather than conflated; NUL bytes in candidate and in stored hash; and a run-time three-way agreement (OpenSSL makes a hash for a fresh random password, libc through this package decides, the stored hash itself does not authenticate as a password). `util/unix_util/password_auth_fallback_conformance_test.go` is the other half of the build-tag pair: on a build with no way to read a hash -- any Unix that is not Linux, or `-tags disable_password_auth` -- a password attempt refuses *with an error*, the scheme reports itself unavailable (the flag `cmd/sshoq-server.go` consults before registering the handler at all), and the uid/gid/home lookup key logins depend on still works. | **[conformant]** the comparison is exercised over real hashes and real `crypt(3)`; constant time is a premise (`subtle.ConstantTimeCompare`, one call, no early exit) and the arithmetic of `crypt` belongs to libc. What the tests establish is the guard, the truncation, and the two refusal routes -- see **F16** for the shape of the hole the guard closes, measured. The fallback build now runs in `make proof-conformance` on its own command line, which is the first time that file has been compiled and asserted by anything. |
| SR-AUTH-14 | The credentials a user may present come from two files under that user's home (`.ssh3/authorized_identities`, then `~/.ssh/authorized_keys`), and reading them must neither invent a credential nor destroy one: a missing file is the normal case; a file that cannot be read contributes nothing **and does not take away the identities the server holds in memory** (`-pubkey`, `-rpub`); one unparseable line does not spoil the lines around it; the comment and blank-line grammar is what the code documents; and both files are read, so a key kept for `sshd` also logs in over ssh3. | `server_auth/authorized_identities_conformance_test.go` — the two names, in order, under the home the account names; no files at all → no error and exactly the server-held identity; the identities file replaced by a *directory* (root ignores permission bits, so this is how a read error is produced faithfully) → nothing from it, and the server-held identity still there; a twelve-arm grammar table over blank, whitespace-only, column-zero comments, mid-file comments, an indented comment, garbage among keys, an empty file, comments only, no trailing newline, and CRLF; both files present → both sets of credentials; and two absences pinned as behaviour rather than as luck -- the reader's line ceiling (below) and the fact that nothing asks who may write the file. | **[conformant]** the decisions are over file shapes rather than arithmetic, and the plugin that turns a line into a credential is a stub here on purpose (importing the real one from this package is a cycle): what a key credential must satisfy is SR-AUTH-12. Two absences found while writing it are findings, not gaps in this row -- **F17**. |

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
| SR-TR-05 | The name a server is trusted under is one string, computed the same way when it is written and when it is consulted: `hostname + ":" + port + path`, the hostname verbatim, the port in decimal, the path with the leading `/` `NewConfig` insists on. It is written to the store as a single whitespace-separated field and read back as one, and a name with whitespace in it is dropped as an invalid line rather than trusted under half of it; and no two meanings share a name, because the slash that separates the port from the path is guaranteed rather than hoped for (**F13** reports what the verbatim hostname costs). | `client/config/config.go` (`NewConfig`, `CanonicalHostFormat`, `URLHostnamePort`), `known_hosts.go` (`AppendKnownHost`, `ParseKnownHosts`, `Knows`, `KnowsHash`), `cmd/sshoq.go` (every lookup and every pin), `host_identity_conformance_test.go` | **[conformant]** Six tests, none of which existed: `TestConformanceCanonicalHostFormatIsExactlyTheNameSplitsIntoThePartsThatBuiltIt` pins the shape at the port boundaries a human mistypes (0, 1, 22, 80, 443, 65535) and shows that an omitted path and `/` are one identity while a different port or path is another; `TestConformanceKeyWrittenIsKeyLookedUp` appends through the real `AppendKnownHost` and finds every one under both answers with the string the config recomputes, so a pin cannot be recorded under one name and consulted under another -- the way host-key checking classically fails open, since an unknown name is what first-contact trust answers; `TestConformanceKeySurvivesTheFileOrIsDropped` writes names with spaces and tabs and requires each to be reported invalid and known under no prefix of itself (a lost pin, not a wrong pin); `TestConformanceHostAndPortCannotRunIntoThePath` crosses six host spellings with six ports and six paths and requires as many names as distinct meanings -- 216 of each, the 36 apparent duplicates being `""` and `"/"` after normalisation -- which is the boundary claim, since `"h", 44, "30/"` and `"h", 443, "0/"` would be the same name without the slash; `TestConformanceSpellingChangesThePin` measures **F13**; and `TestConformanceCanonicalHostFormatDoesNotDependOnUnusedConfigFields` says the identity is not a function of the username, options or `SetEnv` values, so one user cannot inherit another's pin. Not proved: `CanonicalHostFormat` is `fmt.Sprintf`, and the `%d` of a port is a stub with no postcondition in this Gobra, so even the concatenation facts a reader wants ("ends with the path") are string-equality claims of the kind `server_auth/truncate.go` records as out of reach -- hence enumeration over a mixed alphabet of spellings rather than a proof |

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
| SR-PARSE-04 | A remote or local file name that tab completion writes back into the command line comes back out of the tokeniser as **the same name, as one argument**: completion can neither split a name into two arguments, nor change the path a command receives, nor have a hostile name rejected as an unterminated quote (**F11**). | `sftp/quoting.go` (`makeargv`, `escapePath`, `unescape`, `undoGlobEscape`), `sftp/client.go` (the completion writer and the seven literal-path call sites), `sftp/quoting_roundtrip_conformance_test.go` | **[conformant]** Exhausted in Go, over every string of up to four bytes drawn from the ten characters the tokeniser gives a meaning to -- `'`, `"`, `\\`, `?`, `*`, `[`, `#`, space, tab, and `a` for the ordinary case -- in all three shapes `client.go` writes (unquoted, single-quoted, double-quoted): 33333 cases each. Five properties, one per test: `unescape(escapePath(s, q)) == s`; `makeargv` in strict mode accepts the completed line and yields exactly one argument for it, with a span that covers the completed text and nothing else; for the commands that must not glob, `undoGlobEscape(argument)` is the name that was completed -- this is the value that reaches `os.Chdir` and `resolveLocalPath`; for the commands that do glob, `path.Match(escapePath(s, 0), s)` holds, so a name containing `*` lists that file and not the directory; and strict and sloppy mode agree on every completed name, which is what makes the line on screen the line that runs. Not proved: the tokeniser itself, which is a state machine over bytes that grows four accumulators -- `append` is not in a pure function's repertoire, so Gobra cannot read it where it runs (see `util/varint.go`'s header for the measurement); a model of `makeargv` would be a rewrite, not a transcription, and the exhaustive enumeration above is the honest substitute at this size. What the enumeration does *not* cover is a name longer than four bytes: the alphabet is per-position, so five bytes would be 111111 cases, still tractable, and a name whose hostile character sits at position nine is out by assumption rather than by experiment. |
| SR-PARSE-05 | The one case-insensitive comparison this server performs on input a peer chose is ASCII case-insensitive equality and nothing else: it requires the two sides to be the same length, it folds only `A`-`Z`, and it is never *looser* than Go's own `strings.EqualFold` -- so the `Authorization: Bearer ` prefix test can refuse a prefix Go would have honoured (a Unicode look-alike) but can never accept one Go would have refused, and the token it hands on is exactly the bytes after a seven-byte prefix it saw. | `util/equalfold.go` (verified where it ships), `server_auth/handlers.go` (`BearerAuth`, `ParseBearerAuth`), `util/equalfold_conformance_test.go`, `server_auth/bearer_fold_conformance_test.go` | **[proved:shipped]** `proved` on the shipped comparison, which is also the whole of its implementation (`lower` plus one loop, in a file that imports nothing): the contract states the decision in both directions -- a match holds exactly when the lengths are equal and every position is equal after an ASCII-only lowercasing, spelled over bytes because a spec may not call the impure `lower` -- together with the three consequences a caller leans on, proved as lemmas (`equalFoldIsReflexive`, `equalFoldIsSymmetric`, `equalFoldDistinguishesLengths`, `equalFoldRefusesLongerPrefixes`) and the byte-level fact that with no capitals involved folding equal *is* being equal (`foldEqualityIsByteEqualityWithoutCapitals`, whose contract is a complete case definition of `lower`, which is what lets the prover reason about a call to it in another function's postcondition). Mutants die: `'A' <= b` to `'A' < b`, `!=` to `==` in the loop, and `len(s) != len(t)` to `len(s) > len(t)` each fail verification. `conformant` for the sentence a reader actually wants -- "this is what Go means by case-insensitive" -- which is out of Gobra's reach for the reason `server_auth/truncate.go` records: it knows a string's length and one byte of it, and has no rule turning `s == t` into characters. So `TestConformanceEqualFoldAgreesWithStringsEqualFoldOnAscii` checks all 1,234,321 pairs of ASCII strings up to three characters over an alphabet mixing cases, digits, space and punctuation, and `TestConformanceEqualFoldIsFinerThanStringsEqualFold` checks the direction that keeps the prefix check safe over 80,420 pairs including *every* pair of single bytes: wherever this fold says yes, `strings.EqualFold` says yes, and all 72 divergences found are Unicode simple case folds needing a byte outside ASCII (U+212A KELVIN SIGN, U+017F LATIN SMALL LETTER LONG S, U+00C5, `\u03a3`/`\u03c3`, `\u03c2`/`\u03c3`), asserted by name so that a change in either implementation is reported rather than absorbed; `TestConformanceBearerPrefixUsesTheVerifiedFold` and `TestConformanceBearerDecisionIsTheVerifiedRuleRecomputed` then tie the one caller to it, recomputing its accept/refuse from `util.EqualFold` over every header shape and refusing the look-alike prefixes. Recorded as measured behaviour, not proved: `ParseBearerAuth("Bearer ")` yields an *empty* token and `ok`, which is harmless only because an empty token satisfies no verifier -- see **SR-PARSE-02** for the header decision around this one |
| SR-PARSE-06 | The SFTP frames a logged-in peer sends are raw bytes handed to `DecodeRequest`/`DecodeResponse`, and both ends of a session are peer code: **a frame is either decoded or refused, never half-trusted** -- no prefix, no lying length field and no single mutated byte may make the parser read past the frame or crash; the entry count a peer announces is refused *before* it becomes an allocation; the command byte decides the command and nothing else (unknown codes reach an inert empty command, which the server answers "unknown command"); and the size arithmetic used to preallocate a frame matches the bytes the encoder writes, because the reused-buffer path is handed exactly that many. | `sftp/frame_robustness_conformance_test.go` — round trip over eleven request shapes and nine response shapes (empty path, empty data, embedded NUL/newline, offset `MinInt64`, a path at the 65535 ceiling, entries, an info struct, both, neither); **every truncation point** of every one of those frames; **every four-byte window** of every frame poisoned to `0xFFFFFFFF`/`0x80000000`/`0x7FFFFFFF`/`0x0000FFFF`; **every byte** of two frames replaced by all 256 values, ~15k decodes, each guarded so a panic is reported with the byte offset that caused it; the entry-count guard told apart from an incidental truncation by *which* error says no; the nine command codes required distinct, exact-round-tripping, and every other byte inert; `responseFrameSize`/`fileInfoFrameSize` and the inline request size required equal to `len(Encode...)`. | **[conformant]** the parser is stateful over a byte slice (`frameCursor`), so it is measured rather than proved, and measured exhaustively rather than by sample: the three loops above are 100% of single-byte mutations and 100% of truncation points for the sample frames. Bounds hold -- no finding on the decode side. The encode side has one: `appendStr` writes `uint16(len(s))` with no length check, so a string over 64 KiB is announced with a wrapped length, silently (**F18**). |

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

### F11: the largest pure surface in the tree had no requirement row (SR-PARSE-04)

`makeargv` is four functions and roughly two hundred and fifty lines of state machine -- the OpenSSH
command-line tokeniser, reimplemented here -- and it sits between a name the server chose and `os.Chdir`,
`resolveLocalPath` and the seven `undoGlobEscape` call sites in `client.go` that hand a string to the
filesystem. It had no row in this catalogue. Neither did `escapePath`, the function whose *entire reason to
exist* is that a name which tab completion writes back into the line must survive being tokenised again.

The absence was not an absence of tests. `sftp/quoting_test.go` has nineteen of them and they are good:
single and double quotes, mismatched quotes inside quotes, comments, spans, unterminated quotes in strict
and sloppy mode, the glob metacharacters preserved for `glob(3)`. What none of them said is the one
sentence the pair is for -- that escaping a name and parsing it back yields the name, once, unchanged. The
tests describe the rules; nothing described the guarantee the rules add up to, which is the difference
between "completing a file called `a b`" and "completing `a`, adding an argument called `b`, and `cd`-ing
into neither".

The guarantee holds, and is now exhausted rather than asserted: 33333 strings over the ten characters the
tokeniser reads specially, in the three shapes `client.go` writes, five properties, every case passing.
The interesting part of writing it is a composition that is *not* the identity and must not be "fixed":
`unescape(undoGlobEscape(escapePath(s)))` drops a trailing backslash, because `unescape` sees the `\` that
`undoGlobEscape` has just produced as an escape with nothing after it. The shipped pipeline is
`makeargv` then `undoGlobEscape`, and the tokeniser has already removed the non-glob escapes by then, so
the code is right and the plausible one-line property is wrong -- which is exactly the sort of thing a
future reader, seeing `unescape` unused next to `undoGlobEscape`, would be tempted to tidy. It is written
in the test file's header instead of living in someone's memory.

Why a model was not written for this one is in the row: `makeargv` grows four accumulators with `append`,
and a pure Gobra function cannot, so a unit would be a rewrite of the state machine rather than a
transcription of it, and a rewrite that agrees with itself proves nothing about the Go. The exhaustive
enumeration is the honest substitute, with its limit stated -- four bytes, so a hostile character at
position nine is out by assumption rather than by experiment.

The method note is the same as **F8**'s, which makes it a pattern rather than a slip: rows written from a
list of decision points miss the places where the code makes a promise in a *name* -- a constant with a
ceiling, a function called `escape` -- because those do not read as decisions. Both were found by walking
the pure functions and asking what each one promises, and both were added as rows afterwards. The next
time, the walk comes first.

### F12: an authentication mechanism had no requirement row (SR-AUTH-10)

F8 was a promise in a comment; F11 was a promise in a function name. This one is bigger: the plugin
authentication path -- `internal/plugins.go`, the registry that decides which code gets to say whether an
`authorized_keys` identity line is satisfiable, and `auth/plugins`, the extension point that feeds it -- had
no row in this catalogue and no test in the repository. `grep -i plugin proof/SECURITY_REQUIREMENTS.md`
returned nothing in a document whose whole subject is who may authenticate.

The walk that found it is the point. After F11 the obvious next question was not "what else can I prove" but
"which functions does this catalogue not mention at all", and running that question over the tree turns up,
besides the transport and CLI files one would expect, a registry whose contents are an authentication
decision. A requirement list written from decision points -- parse, compare, refuse -- will keep missing
this shape, because a registry does not look like a decision until you ask who is allowed to be in it.

What the rules turn out to be, now that they are written down:

  * registration after `closeRegistry` is refused with `util.ClosedPluginsRegistry` and leaves the map
    untouched, so the plugin set is fixed for the life of the serving process;
  * a duplicate plugin name panics -- a startup failure, which is right for a collision between two
    `init()` functions -- and it panics *before* the map write, so the plugin that registered first is the
    one that survives. That direction is the one with a consequence: had it written first and panicked
    after, the same identity line would mean something different in a crashed process's successor;
  * a plugin returning an error is logged and skipped, and a plugin recognising nothing returns a nil
    verifier, which is likewise not an identity. The registry is not where fail-closed lives: the login path
    accepts a request because a verifier someone returned accepted it, and an empty or broken plugin set
    contributes the empty set, which authenticates nobody.

Five tests in `internal/plugins_conformance_test.go` hold those, including fifty iterations of the identity
search over a registry holding a broken plugin, an unrecognising plugin and a working one -- map iteration
order is random and the answer must not be. The row is `conformant` and not more: what a plugin *is* lives
behind `auth.RequestIdentityVerifier`, so any claim about a plugin's own verdict is a premise about code this
repository does not contain, and the mutex-guarded map is a premise about the runtime. The panic policy is
recorded as behaviour, not proved correct; the property tested is which plugin survives a collision.

### F13: the pinned name is the typed name (SR-TR-05)

`CanonicalHostFormat` is the identity a server is trusted under, and it is built from the hostname exactly
as the user typed it. Nothing normalises it, and three consequences follow, none of them written down
anywhere in this repository before `host_identity_conformance_test.go` measured them:

  * **case is part of the pin.** DNS names are case-insensitive (RFC 4343), so `https://Example.org/` and
    `https://example.org/` are the same server and different known_hosts entries. The first is pinned; the
    second is a first contact, which the client answers by trusting and recording. Whoever can hand a user
    a differently-cased link therefore gets a second, independent trust-on-first-use on the same host — and
    a certificate pinned under one spelling says nothing about the other. `TestConformanceSpellingChangesThePin`
    asserts this rather than complaining about it, so that the day the key is normalised, that test is where
    the change has to be written;
  * **an IPv6 server is stored under a name that is not the name in the URL.** `URLHostnamePort` brackets
    `::1` as `[::1]:443` because a URL demands it; the identity is `::1:443/`. A person who reads the URL
    and writes the file by hand in the bracketed form has written a name the client will never ask about,
    and the entry is silently inert;
  * **a trailing dot is a different host.** `example.org.` — the fully-qualified spelling that appears in
    zone files and in other tools' output — pins separately.

None of these is a hole in the *check*: when a name is in the store, the certificate is verified against
what is stored, and the same string is used for the write and the read (`TestConformanceKeyWrittenIsKeyLookedUp`),
so the failure is a pin that does not apply, never a pin that points at the wrong server. And every failure
mode here is the loss of a *protection*, not the introduction of a bypass: a name nobody pinned is treated
as unknown, which is what first-contact trust is for.

What the finding asks for is a decision, not a proof, and it is the same shape as **F2** and **F3**:

  1. **Leave it**, and let these tests be the documentation — cheap, and defensible while the known_hosts
     format has no other implementation to interoperate with;
  2. **Lowercase the hostname** (IDNA aside) when building the identity — kills the case variant, which is
     the realistic one, at the cost of invalidating every existing entry whose hostname had capitals in it,
     which is most likely a handful of hand-written lines;
  3. **Normalise the host fully** — lowercase, brackets for IPv6 in the identity too, no trailing dot —
     which makes the file match what a person reads off the URL, and needs a migration or a
     "check-both-old-and-new-key" transition in `cmd/sshoq.go`, because a client that normalises without
     reading the old names reports every pinned host as new and trusts the next certificate it sees.

Recommendation: 3 with a transition that consults both spellings, because option 2 leaves the bracket
asymmetry — the one that makes a hand-written entry inert rather than merely separate — and inert entries
are how a pin stops protecting without anybody noticing. What is not acceptable is option 1 plus the
assumption that pinning is spelling-insensitive, which is what nearly everybody, including the comment
above `CanonicalHostFormat`, has been assuming.

### F14: the account gate stands on one door, and its shape is the wrong shape for the others

`CheckAccountUsable` is a good gate -- see SR-AUTH-11, where its decisions are now proved -- and it is
called from exactly one place: `userPasswordAuthentication` in `util/unix_util/linux_user.go`. A
public-key login never consults it, and neither does an OIDC login. So on a server with the default
plugins:

  * an account expired with `chage -E 2024-01-01` still authenticates by key and gets a session;
  * a system with `/etc/nologin` present still admits key logins for everybody;
  * an account whose shell is `/usr/sbin/nologin` still completes the authentication and establishes the
    conversation, and the `nologin` program that eventually runs prints its message and exits -- which
    looks like protection from the outside, and is one program's politeness rather than a policy:
  * `sp_flag` lock bits, which is the field an account-management tool sets to close an account rather
    than to disable a password, are consulted only when there is a password to check.

OpenSSH with `UsePAM yes` -- the configuration on most Linux installs -- runs the PAM `account` phase for
every authentication method, so this is a difference from the reference behaviour of the tool sshoq is
replacing, in the direction of more access, for the mechanism that is the common one.

The obvious patch is wrong, and this is the part of the finding worth more than the gap itself. The
predicate that decides "this account is closed" currently begins with "this password field is not a
password": `passwordFieldIsLocked` returns true for an empty field, a `!`, a `!!`, or any value starting
with `!`. For an account that is *configured for key access only* -- which is how lock-hardened images
ship service accounts, with `!!` or `!` in `sp_pwdp` and no password at all -- that verdict is correct
about passwords and fatal about keys: `usermod -L` locks the password, and Linux still lets that account
log in with a key. Reusing the gate wholesale on the public-key path would therefore refuse logins the
administrator intends, which is a worse failure than the one it fixes because it is silent at the point
where it matters.

So the fix is a split, not a call:

  1. `passwordLoginAllowed(policy)` -- the password-field markers and `sp_flag`: what the gate does today,
     and it belongs on the password path;
  2. `accountLoginAllowed(policy, now)` -- `sp_expire`, `sp_lstchg`/`sp_max`, the login shell, the
     nologin file, and nothing about the password field: this is the one that belongs where an
     *identity* is accepted, which is after a plugin's verifier returns true and before the session is
     created, once per accepted identity rather than per mechanism;
  3. the shell question needs one further decision of its own: `nologin(8)` refuses a shell that is not in
     `/etc/shells`, and a key-authenticated session that runs a non-listed shell today fails when the
     program is exec'd. Making that an authentication refusal changes the error a user sees, from a
     confusing exec failure to a clear `401` -- which is the point, but it is a user-visible change.

Both halves are already the shape this catalogue likes: pure functions over an `AccountPolicy` with all
the I/O as arguments, so the second half can be verified in the same file as the first. What is missing
is the plumbing decision -- where the session layer asks -- and that is a maintainer call about the
error a locked account should receive, not a proof.

### F15: the function that decides whether a key belongs to a user had no test and no row

`PubkeyJWTIdentityVerifier.Verify` in
`auth/plugins/pubkey_authentication/server/server_plugin.go` is the check behind every
public-key login: a signature, an algorithm set, seven claims and a source address turning into
`true`. Before this programme touched it the file had **no test of any kind** and **no row in
this catalogue cited it** -- the same shape as F11 and F12, in a more consequential place: every
proof about identity options, plugin registries and conversation binding rests on the assumption
that this function refuses what it should. It now has SR-AUTH-12 and seven conformance units, and
they measure four things nobody had written down.

The first is the reason the row exists at all. Among the claim checks is:

```go
if _, ok = claims["exp"]; !ok {
    return false
}
```

That line does something the library does not. `jwt.Parse` treats a missing `exp` as *no expiry*
-- a token saying nothing about time never expires -- and `WithExpirationRequired()` is the
option that would have made it an error, which this call site does not pass. So those five lines
are the only thing between a captured key-proof and permanent validity. Someone tidying the
function would reasonably delete them, since the library "already validates expiry", and the
deletion would be invisible: every test that existed passed before, and none existed after.
`TestConformanceMissingExpiryIsRefusedByHand` therefore refuses the token **and** asserts that the
library with the same options accepts it, which makes the line's necessity a fact inside the test
rather than a hope.

The second: `jwt.WithIssuedAt()` **does not require `iat`**. Its name says "issued at"; what it
sets is `validator.verifyIat` -- "check `iat` if it is there". A token with no `iat` is accepted,
measured. That is harmless here, because the clause limiting a token to one conversation is `jti`
and not `iat`, but it is exactly the option whose name will be trusted by whoever reads this call
site next, so the table records it as measured rather than as intended.

The third is the acceptance window, which is the sum of two numbers in two files: the client
signs `exp` at **10 seconds** (`client_auth.go`), the server allows **60 seconds** of leeway
(`server_plugin.go`). A key-proof is good for a little under seventy seconds from the moment the
client mints it, and the boundary is exclusive -- an `exp` exactly sixty seconds old already
fails, because the comparison is `now.After(exp + leeway)` and microseconds have gone by. Both
numbers are now pinned from their working side (fifty seconds old accepted, two minutes refused),
so changing either one is a decision with a failing test attached to it.

The fourth belongs to F12 rather than here, and is worth repeating because it decides whether a
malformed file costs a login or costs a connection: a key type the `ssh` package cannot parse
(`ssh-dss` is not compiled in) does **not** reach the switch that returns an error for unsupported
types -- it fails to parse, and the plugin returns *no identity and no error*. The key is inert,
the connection survives. A type the package knows but this plugin does not sign with returns an
error, and by F12 that error kills the whole request. Whether an unusable key line is a shrug or a
catastrophe therefore depends on which of two parsers noticed first. Both are pinned, because
"fail closed" is only a good outcome if you know which door you are standing at.

One more measurement, from writing the test rather than from reading the code: the `ssh`
authorised-key parser does not accept a quoted option value followed by a second option after a
space (`command="echo hi" no-agent-forwarding KEY` reports `ssh: no key found`), so a file written
that way makes the key inert rather than restricted. OpenSSH's own spelling is comma separated
with no spaces, and that parses and is refused for the reason `identity_options.go` gives.

**Fix direction:** no behaviour change requested in the checks themselves -- they are sound, and
now they are pinned. Two hardenings are worth taking while the file is open: pass
`jwt.WithExpirationRequired()` and delete the hand-written presence check, so that one mechanism
does the job instead of two; and decide deliberately, in the light of F12, whether an unparseable
or unsupported key line should be an error or a skipped identity. If F12 is fixed so a plugin
error no longer kills the conversation, this distinction stops mattering -- one more reason to fix
F12 first.

### F16: the password comparison had no test, and the guard above it is two lines wide

`ComparePasswordWithHashedPassword` is the last step of the only credential that sshoq verifies
itself rather than delegating to a plugin. It is four lines and a comment, and until now the
comment was the only evidence anyone had that it does what it says. Two things came out of
measuring it, and one of them is the reason `SR-AUTH-13` is a row.

`crypt(3)` does not report an unusable stored hash by failing. Give it a stored value of `*` -- the
spelling `passwd -l` writes -- and it *answers*, with a string of its own, and so for `!!`, `*LK$`,
`$99$x`, bcrypt's `$2b$`. The wrapper in `linux_user.go` deals with this in the only way available:

```go
hashedPassword := C.GoString(ccrypt_ret)
if hashedPassword == "" || hashedPassword[0] == '*' {
    return "", fmt.Errorf("bad password hashing")
}
```

Those two lines are the difference between "locked account, nothing to try" and "locked account, any
password works": if the answer libc returns is compared with `==` against the stored value, a stored
`*` matches, and the login opens. The test pins the guard by its **error text**. `Crypt` has two
failure messages, `"crypt() failed"` for the NULL return and `"bad password hashing"` for the
empty-or-`*`-prefixed answer, and the `*`/`!!`/`$99$x` family provokes the second one -- which is
the measurement that says libc returned a string rather than nothing, i.e. that there was something
there to compare equal. A test that only asserted "refused" would still pass if someone deleted the
guard and the comparison happened to fail; this one fails, because it also asserts *why*.

Two neighbours of that guard are recorded, because they look like holes and are not. A stored
`$6$` -- an algorithm marker with an empty salt -- is a *usable* setting: libc hashes with an empty
salt, and the refusal comes from the comparison, not from a guard. And `C.CString` truncates at a
NUL byte on both sides of the call, so libc can be handed a prefix of what Go was given; measured,
truncation only ever changes which hash is computed, never what is accepted (`abc\x00xyz` is seen as
the DES salt `ab`, and the answer is not the stored string).

There is a second, quieter gap here, and it is the one that will bite a maintainer cross-compiling.
`util/unix_util` has three implementations of the password question, selected by build tags:
`linux_user.go` (`linux && !disable_password_auth`), `non_password_auth_user.go`
(`unix && (!linux || disable_password_auth)`), and the untagged `user.go` that dispatches to
whichever exists. Before today **nothing compiled or ran the fallback one** -- no test file carried
its tag, so on a macOS or `-tags disable_password_auth` build the code that decides what a password
attempt does had zero executed assertions behind it. `TestConformanceFallbackBuildRefusesPasswordAuthentication`
now runs in `make proof-conformance` on a second command line, and it asserts the part a caller
cannot recover: the refusal comes *with an error*, not `(false, nil)`, because `(false, nil)` reads
as "this account is closed" while the truth is "this build cannot authenticate", and those two
answers should not be the same value.

**Fix direction:** no behaviour change requested -- the guard, the constant-time comparison and the
fail-closed fallback are all correct, and now all three are pinned. Two small things are worth it
while the file is open: pass the stored hash to `crypt_r` through `crypt_gensalt`-style validation
(or at least reject a stored value that does not begin with `$` and is not 13 characters) so the
"usable setting" question is answered by sshoq rather than by whatever libc decides a marker means;
and add the two cross-builds to CI (`GOOS=darwin go build ./...`,
`go build -tags disable_password_auth ./...`) -- both compile today, which is exactly the kind of
fact that stops being true silently.

### F17: three things the identity files are trusted for that nothing asked

`GetAuthorizedIdentities` opens `~/.ssh3/authorized_identities` and `~/.ssh/authorized_keys` for the
account being authenticated. The lines inside them are the user's say-so about who may log in, and
the reading of them is short, quiet code. Writing the row above turned up three properties that were
never asked about, all three measured in `authorized_identities_conformance_test.go` (`SR-AUTH-14`).

**1. A line longer than 64 KiB silently deletes the rest of the file.**

`ParseAuthorizedIdentitiesFile` reads with a `bufio.Scanner` and never looks at `scanner.Err()`:

```go
for scanner.Scan() {
    ...
}
return identities, nil
```

A `Scanner` stops at its maximum token size, 64 KiB by default, and reports the reason through that
unchecked `Err()`. So a line longer than that -- a key with a long comment field, a file something
large was appended to, one long line of paste from a mail client -- ends the read, and every identity
after it is gone. Measured: with a 70 KiB line between two valid keys, the server finds exactly one
credential and reports **no error at all**. The failure is fail-closed for the logins it removes, so
this is not a hole in authentication; it is a hole in diagnosis, which is worse in the long run,
because the user whose key was skipped is told "invalid credentials" while the file plainly contains
it. It is also unbounded in the other direction: a user can grow the amount the server reads per
attempt.

*Fix direction:* read with `bufio.Reader.ReadString('\n')` (or raise the buffer and *check*
`scanner.Err()`), and log the file, the line number and the length when a line is refused for length.
One function, and the error path stops being silent.

**2. An account with no home directory gets identity files relative to the server's working
directory.**

`DefaultIdentitiesFileNames` is `path.Join(user.Dir, ".ssh3", "authorized_identities")` and
`path.Join(user.Dir, ".ssh", "authorized_keys")`. For `Dir == ""` -- the normal state of a service
account, and what an LDAP or NSS backend can hand back -- those are `.ssh3/authorized_identities` and
`.ssh/authorized_keys`: relative paths, resolved by `os.Open` against the process working directory.
So for such an account the question "whose key is this?" is answered by whoever can write
`$PWD/.ssh/authorized_keys` in the directory the server happened to be started from, which is a
property of the launch script and not of the account. Nothing tested this before, because nothing
asks.

*Fix direction:* treat an empty `user.Dir` as "no identity files" (and say so in the log), rather than
as "the current directory"; if a relative home is ever legitimate, resolve it against a configured
root. Worth deciding together with **F2**, which is the same class of question -- what the server
assumes about the accounts it is handed.

**3. Nothing checks who may write the file.**

OpenSSH has `StrictModes` for this, and it is on by default: an `authorized_keys` that is group- or
world-writable, or not owned by the account, is refused, because the key in the file is only as
trustworthy as the write permission on the file. sshoq opens the file and parses it, and asks nothing
about it: `0666`, a directory writable by the group, a file owned by another account -- all read as
identity files like any other. The test asserts today's behaviour as behaviour, so that the day a
check appears, the test fails and points at the decision instead of the check going in unnoticed.

This is a policy call and not a bug to patch, which is why it is a finding rather than a change: a
server whose user homes are managed by a configuration tool that leaves them group-writable will stop
authenticating anyone if the check is turned on silently. What is missing is the *switch* and the
*log*, not the check; and the premise that makes it matter -- that the server runs as root and reads
other users' files -- is exactly the deployment the documentation recommends.

**Relations:** F12 decides what happens when a *plugin* cannot make sense of a line; F17 decides what
happens when the *file* cannot. Both are currently silent, in opposite directions: F12 is loud where
it should be quiet (a plugin error kills the conversation), F17 is quiet where it should be loud (a
read error kills the identities).

### F18: a string field longer than 64 KiB is announced with a wrapped length, silently

`appendStr` is the whole of the SFTP string encoding:

```go
func appendStr(b []byte, s string) []byte {
	b = appendU16(b, uint16(len(s)))
	return append(b, s...)
}
```

`uint16(len(s))` is a conversion with no check, so a string longer than 65535 bytes is written with its
length modulo 65536 and its full body: the peer reads a short string, and then takes the remaining
bytes for whatever field comes next. `appendBytes` has the same shape with a `uint32`, which is a
4 GiB ceiling rather than a 64 KiB one and is not reachable in practice.

What fields go through `appendStr`: the request path, the response path, the response **error string**,
and every `FileInfo` name, link target, user name and group name. The decoder survives it -- `take`
bounds every read, and the exhaustive truncation and mutation loops in `SR-PARSE-06` found no panic and
no overread -- so this is a corrupted transfer, not a memory error. Measured: a request for a 65536-byte
path is announced as `0` bytes and the peer's decode fails; the same path one byte shorter round-trips.

Why it is worth closing anyway: nothing in the code states the ceiling, so it is a limit that exists
only as an accident of a type. The strings that could reach it are the ones the server builds out of
other people's paths -- an error message quoting a deep path, a link target, a name from a filesystem
that allows long names -- and today the failure mode is a garbled frame on the wire rather than a
message naming the field. It is also the kind of thing that becomes live when someone raises a limit
elsewhere.

*Fix direction:* make the ceiling explicit where the length is written -- refuse (or truncate with a
logged error, at the call site that knows which field it is) rather than convert. A `uint16` cast that
can silently wrap is the sort of thing the type should not be allowed to hide; if 64 KiB is the real
limit, `appendStr` should say so and the callers should check against it, which is one guard per
encoder and a test that a 64 KiB+1 path is refused rather than mangled.

**Relations:** F18 is the encode-side twin of SR-PARSE-06's decode claim, and the same shape as **F13**:
in both, a value that must satisfy a property is produced by a conversion rather than by a check, so
the property holds only for the inputs anyone happened to try.

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

   The list above is what Phase 1 delivered. `make proof` now runs eighteen units: the ten models
   above plus eight shipped files that carry their own specs — `glob.go`, `identity_checks.go`,
   `source_check.go`, `server_auth/throttle_rules.go`, `server_auth/truncate.go`,
   `util/varint.go`, `util/equalfold.go` and `version_rules.go`.
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

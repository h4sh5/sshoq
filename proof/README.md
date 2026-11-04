# Formal verification

Three commands, in this order:

```sh
make proof-setup          # JDK, sbt, Z3, pinned Gobra -> .proof-tools (idempotent)
make proof-conformance    # the models still behave like the Go code they model
make proof                # Gobra checks every proof obligation in proof/*/model.gobra
```

`make proof-all` runs all three. CI does the same in `.github/workflows/proof.yml`.

## State of the programme

Twelve verified files — ten model units (`proof/*/model.gobra`) plus two shipped ones carrying their
own specs, [`../glob.go`](../glob.go) and [`../identity_checks.go`](../identity_checks.go) — and 46
`TestConformance...` tests in
the packages of the code they check, and a catalogue of 31 requirements
([`SECURITY_REQUIREMENTS.md`](SECURITY_REQUIREMENTS.md)) whose status column is the only place a
claim about coverage is written:

| status | rows | what it means |
|---|---|---|
| proved (model) + conformant | 17 | a Gobra unit proves the decision over all modelled inputs, and a test says the modelled function still behaves that way |
| proved (shipped) + conformant | 2 | the same, except the proof is of the function the server calls: SR-PERM-04 and SR-PERM-05, in `identity_checks.go`. The model of each is a second opinion now, not the argument |
| conformant | 3 | checked in Go alone, because the prover cannot hold the shape of the whole claim (the recursive glob: findings **F5**, **F6**) — `glob.go` does have a proved *part* of one of them, termination, in the shipped file |
| partially proved | 4 | the decision function is proved, the surrounding machinery is a premise named in the row |
| out of scope for Gobra | 3 | QUIC conversation state and version parsing; integration and unit tests are the control |
| open | 1 | SR-PERM-11 / finding **F2**: a decision the maintainer owes, not a proof that is missing |
| phase 3 | 1 | SR-PARSE-01: the frame parser, where specs have to live in the production file. Phase 3 itself has started on easier ground: `glob.go` is shipped code with its specs in it, verified by `make proof` |

Three real bugs came out of writing this, all fixed and recorded with the requirement they violated:
the login throttle could grow past the capacity it documents (**F1**, `server_auth/login_policy.go`),
a `from=` pattern with a handful of stars cost exponential time — fourteen stars, 2m56s of one
core per authentication attempt (**F5**, `identity_options.go`), and the rewritten matcher read a `*`
arriving in the *text* as a wildcard, so `matchGlob("a*", "a*b")` was false where OpenSSH says true
(**F6**, `glob.go`) — the first bug the prover itself found rather than a test, and the reason
"three implementations agree over half a million triples" is stated with its corpus next to it.
Three more findings are behaviour
documented rather than changed, each needing a product decision: **F2** above, **F3**
(`-force-command-mismatch-exit=0` makes a forced command advisory, which the documentation does not
say), and **F4** (modelling drift, mitigated mechanically and the argument for Phase 3).

The boundary of what this approach can prove is drawn by experiment and not asserted: recursion over
strings is opaque in Gobra v26.09 (Gotchas below), crypto and `go-jose` discovery are premises, and
nothing here says that a Go compiler, the OS, or `net` behave as assumed. Where a premise is
load-bearing the catalogue row names it. Some of them are then checked by a named test — base64
distinguishing conversation ids, what `net.ParseCIDR` decides, that a rejected spelling is refused —
and the ones that are not (signature verification, the TLS exporter behind a conversation id) are the
assumptions the argument rests on, listed as such rather than buried in a model header.

## Verification in place: the specs live in the shipped file

Two files in the proof are not models. [`../glob.go`](../glob.go) is the `from=` matcher the server
calls, moved out of `identity_options.go` and annotated where it ships.
[`../identity_checks.go`](../identity_checks.go) is the channel-request and channel-open gate -- the
code that enforces `no-pty`, `restrict`, `no-port-forwarding` and a forced command -- separated from
the messages it produces and annotated there. `make proof` verifies both: the code that runs in
production is the code the proof talks about, with no transcription step in between. That is roadmap
Phase 3, and what decides whether a file can join it is **imports**, not difficulty:

* Gobra v26.09 ships stubs with real specs for `strings`, `net`, `strconv`, `errors`, `time`, `sync`,
  `bytes` and `encoding` (`.proof-tools/src/gobra/src/main/resources/stubs/`), so a file that uses
  only those is readable — which is why `net.ParseCIDR` and the `strings` helpers in this server are
  not obstacles.
* For `fmt` the stub says "We do not support members defined in this package", so any file that
  formats an error with `fmt.Errorf` — which is every decision file in this server that refuses
  something — cannot be verified where it lives until the formatting is separated from the decision.
  `identity_checks.go` is that separation carried out: the gate returns an enum, the method in
  `identity_options.go` switches over the enum to produce the wording, and the proof is of the gate.
  The wording is not nothing -- a refusal that blamed the wrong flag would be a different gate -- so
  `TestConformanceRequestVerdictIsTheGate` and `TestConformanceChannelVerdictIsTheGate` hold each
  refusal to the phrase it has always used, against a locally rewritten copy of the pre-split code.
* A verified file is handed to Gobra alone (`gobra -i glob.go`), so its package-mates are not its
  problem. `scripts/run-proofs.sh` lists such files in `INPLACE_UNITS` rather than discovering them,
  so that someone adding an import to a verified file sees the proof fail rather than watching it
  quietly shrink.

What the annotations on `matchGlob` prove, and what they do not, is written in the file. In short:
termination on a two-component measure (so the linear-time claim of **F5** is a theorem and not a
reading of the code), an empty pattern matching exactly the empty text, and `"*"` matching
everything. The equivalence with the declarative `globMatch` in the same file needs induction over
`string`, which Silicon does not have — it has induction over inductive datatypes, which is exactly
how `proof/sourcecheck` discharges the same decision over its own model. The soundness half
(`res ==> globMatch(pattern, text, 0, 0)`) was written down and did not verify: it needs the invariant
that every star earlier than the saved one has already failed at every longer stretch of the text,
and stating *that* needs a predicate over a range of a string, which is the slicing the prover has no
theory for.

## How the argument is built

Gobra cannot read the server: the production files reach into `quic-go`, `x509`,
`zerolog` and cgo-backed user lookups, and Gobra verifies a self-contained subset of Go
with a partial standard library. So each unit here is a *model* of one decision — the
authentication decision table, the identity-option gates, the `User-Agent` truncation, the
throttle arithmetic — written with specs, verified over all inputs of the modelled
function, with memory safety (no panic, no out-of-bounds, no nil dereference) proved for
free on top.

That leaves the obvious question: why should a proof about a model say anything about the
server? The answer is the conformance tests, and it is the part of this directory that
keeps the rest honest:

* `identity_options_conformance_test.go` enumerates the input space of the identity-option
  decisions — 64 combinations of the restriction fields against 9 request types and 13
  channel types, and every enforced and unenforced option name in both orders — and
  compares the real `CheckRequest`, `CheckChannelOpen` and `ParseIdentityOptions` with the
  decision table, written out in Go, that the Gobra `ensures` clauses state.
* `server_auth/truncate_conformance_test.go` does the same for `truncate`.
* `server_auth/bearer_conformance_test.go` checks `ParseBearerAuth`, `HandleBearerAuth` and
  `util.EqualFold`: the accepted spellings of the scheme, the boundary at seven bytes, the
  verbatim token, the fact that the fold is ASCII-only rather than Unicode, and that an
  unparseable header produces 401 without the verifier ever being called. It also pins the
  seven ASCII bytes of the prefix, the one fact Gobra cannot check because it does not
  evaluate string literals.
* `identity_options_source_conformance_test.go` is where the `from=` glob lives, since Gobra cannot
  hold a recursive string function (see Gotchas): the shipped `matchGlob`, the recursion it replaced
  — kept verbatim as `legacyMatchGlob` — and an independently written linear matcher agree on 530 255
  pattern/text triples, **stars in the texts included** (they were not, and that blind spot is
  **F6**); a wildcard-free pattern is shown to match exactly the text equal to it;
  star-heavy patterns are held to a time bound; and `matchesSourcePattern`, `parsePeerIP` and
  `CheckSource` are run over real addresses, real CIDRs, the two textual forms of one IPv6 address,
  host names, negations, and every permutation of every pattern list.
* `server_auth/oidc_binding_source_conformance_test.go` is the step between `proof/oidcbinding` and
  `Verify`, which cannot be called without a live issuer: it locates that one method by AST and holds
  it to the claim order and compared values the proof assumes (refusing to be satisfied with a marker
  comment, and failing with "change the model with it"), and it executes the one function between a
  conversation id and the string the binding compares — `base64` of the 32 id bytes, i.e.
  `ConversationID.String()` — showing it distinguishes ids, so that "a token is accepted for at most
  one conversation" is a statement about conversations (SR-AUTH-06).
* `known_hosts_conformance_test.go` parses real files with real self-signed certificates through
  the real `ParseKnownHosts`, `Knows`, `KnowsHash` and `AppendKnownHost`: the grammar with good
  lines interleaved with two-field, four-field, wrong-tag, non-base64 and non-certificate lines
  (invalid line numbers asserted exactly), a missing file being an empty store rather than an
  error, and the append-only property the trust argument rests on — after a certificate is
  replaced, both are still on file.
* `auth/oidc/replay_conformance_test.go` drives the real store over a seeded token stream,
  including the cases the model's invariant is really about: a replay attempt must not evict,
  a store of capacity one must still catch a replay, and a remembered token whose expiry claim
  is unreadable must be refused on sight.

Every one of them is named `TestConformance...`, which is how `make proof-conformance` selects
exactly the correspondence checks and nothing else. The two tests that bound the throttle's
memory and its lock-out live in `server_auth/login_policy_test.go` without that prefix, since
they check no model output; Gobra cannot express them because it has no `delete`.

Change the code without changing the table and `make proof-conformance` fails; change the
model without changing the code and the same test fails from the other side. What remains
uncovered is stated in `SECURITY_REQUIREMENTS.md`, requirement by requirement, including
the requirements that are simply **open** because no unit exists yet.

`SECURITY_REQUIREMENTS.md` is the contract: read it first, then the unit that cites it.
It also holds the [findings](SECURITY_REQUIREMENTS.md#findings) — F1 is a bound that a
conformance-style test disproved in the real code, which is the reason the tests exist.

## Layout

One Gobra package per unit, one unit per requirement cluster:

| unit | requirements | models |
|------|--------------|--------|
| `smoke/` | — | toolchain canary, no security claim |
| `authflow/` | SR-AUTH-01..05 | `HandleAuths`, `HandleBasicAuth`: 16-outcome decision table |
| `identityopts/` | SR-PERM-01..05 | `IdentityOptions`, `ParseIdentityOptions`, `CheckRequest`, `CheckChannelOpen` |
| `truncation/` | SR-TR-04, SR-RES-02 | `truncate`, the pre-authentication `User-Agent` path |
| `throttle/` | SR-AUTH-08, SR-RES-04 | the delay and lock-out arithmetic of `loginThrottle` |
| `replay/` | SR-AUTH-07, SR-RES-03 | `AcceptedTokenStore.Accept`, `evictExpired`, `NewAcceptedTokenStore` |
| `bearer/` | SR-PARSE-02 | `ParseBearerAuth`, `util.EqualFold`, `util.lower` — pre-authentication header parsing |
| `knownhosts/` | SR-TR-01, SR-TR-02 | `Knows`, `KnowsHash`, `ParseKnownHosts`, `AppendKnownHost`, and the client's trust decision in `cmd/sshoq.go` |
| `oidcbinding/` | SR-AUTH-06 | `OpenIDConnectIdentity.Verify`'s binding decision: the claim precedence, the comparison against the server's own conversation id, the replay key |
| `sourcecheck/` | SR-PERM-06, SR-PERM-07 | `matchesSourcePattern` and `CheckSource` — the `from=` restriction's guards, three matching strategies and negated list |

`scripts/run-proofs.sh` discovers `proof/*/model.gobra` and runs Gobra once per unit, so a
timeout or a failure in one unit cannot hide the verdict of another.

## Writing one, notes from the ones here

The toolchain is pinned (`proof/gobra.version`, currently `v26.09`) because a proof means a
specific version of a specific verifier. Things that cost time to learn:

* **`assert` and specs need pure expressions.** A decision function that has to appear in
  assertions must be `pure func` with a body that is a single `return` of a pure
  expression; lemmas call it from ordinary code and assert about the result.
* **`==` binds tighter than `&&` in specs.** `ensures res == !a && !b` is read as
  `(res == !a) && !b`, i.e. it demands `!b` unconditionally. Parenthesise the right-hand
  side of an equivalence.
* **A helper predicate can swallow a claim.** `ensures gatesOk(...) && false` in an earlier
  draft made three outcomes vacuous: fold decisions into an explicit table instead.
* **A `pure func` body is one `return` of a pure expression.** No `if`/`else`, and no `? :`
  either — the conditional expression is ghost-only, so a decision function must be written as
  boolean arithmetic (`pinned && match || !pinned && !known && terminal && yes`) with the shape of
  the Go code kept in the comment above it. Anything that cannot be written that way becomes a
  lemma `func` that calls the pure part and `assert`s the case.
* **Go's newline rules apply to specs.** A `return` (or `ensures`) expression that continues onto
  the next line must break *after* an operator: `a &&` newline `b` parses, `a` newline `|| b` is
  read as two statements and dies with "unexpected || in block, expecting '}'."
* **Every `pure func` needs a `decreases` clause, even a non-recursive one** (`decreases 0`).
* **A recursive `pure func` is checked and then opaque.** Its `decreases` measure is verified, but
  no concrete call can be proved of it afterwards: recursion over `int` unfolds (`f(3)` verifies),
  recursion over `string` does not (`gm("a", "a", 0, 0)` stays unknown), recursion with several
  call sites does not, and indexing a slice inside a pure function additionally demands `perm` for
  the elements. So arithmetic models — the throttle's delay, a truncation length — belong in the
  prover, and string-shaped recursion does not: `matchGlob`'s meaning is pinned by three
  implementations agreeing instead, which is written up as the boundary of the programme in
  `SECURITY_REQUIREMENTS.md` (finding F5) rather than quietly worked around. The work-around that does
  exist is to keep the strings fixed and recurse over an **index**: `prefixEq(a, b, n)` unfolds one
  character at a time, and `prefixEq(a, b, p+1) == (prefixEq(a, b, p) && a[p] == b[p])` is provable.
* **String slicing parses and has no theory.** `a[0:n]` type-checks in a spec and `a[0:0] == b[0:0]`
  is *not* provable; nor is extensionality (equal length plus equal characters does not give
  `a == b`). Write string properties with `len` and byte indices or they will not discharge.
* **Specs in a `.go` file are comments, one clause per line.** `// @ ensures ...` above the signature;
  loop specs (`// @ invariant`, `// @ decreases`) go *before* the `for`, not inside the body; a
  lexicographic measure is a bare list, `decreases a, b`, not `decreases (a, b)`. A clause may run on
  over `// @`-prefixed continuation lines, and length is not a problem -- `identity_checks.go` has a
  240-character `ensures` that verifies -- but a continuation line without the prefix is a parse
  error, and there is no `<==>`: write `(A ==> B) && (B ==> A)`.
* **A `pure` function must be one `return` of a pure expression.** No `switch`, no `if`, no loop.
  That is why `isForwardingFamily` is a long boolean expression while the gate that uses the same set
  is a `switch`: only the first can be named inside another function's postcondition. Note what
  purity is *for* -- being called from a spec. `requestVerdictFor` and `channelVerdictFor` are not
  `pure` (they are imperative, with `acc`-free value parameters), and their contracts are still
  proved of their bodies; a function only needs `pure` if a spec has to talk about it.
* **A contract on an impure function is still a theorem about its body.** The distinction worth
  keeping is between proving a body satisfies its contract (what `make proof` does for every function
  here, pure or not) and being able to *use* a function inside another spec (which needs `pure`, and
  therefore needs the single-return shape).
* **There is no `delete`.** The builtins are `make`, `len`, `append`, `copy`, `min`, `max`.
  A map that forgets keys has to be rebuilt in a loop under a ghost "visited" set, which is
  why the throttle's *memory* bound is a Go test rather than a lemma.
* **Ghost sequences are the right shape for set-like state.** `ghost` + `seq[T]` gives a
  store model with no permissions at all, eviction as `s[1:len(s)]` and insertion as
  `s ++ seq[string]{k}`, so a memory bound is literally `len(res) <= capacity` and a
  trace theorem is a recursive function (`run` in `replay/`) whose `ensures` holds for every
  trace. Three catches, all learned the slow way: a function whose parameters or result are
  ghost types needs the `ghost` modifier *first*, above its other annotations; a `pure func`
  returning an `int`/`bool` cannot have a ghost body, so define conditionals with `&&`/`||`
  or a ternary only where the result is itself ghost; and `s[1:]` on a sequence is not
  accepted where `s[1:len(s)]` is.
* **Membership and `++` do not mix by induction.** A `mem` defined by peeling the *last*
  element discharges `mem(s ++ seq{k}, k)` in one step but cannot relate `mem(drop(s), k)` to
  `mem(s, k)`. State eviction results as structural equalities and index facts
  (`res == drop(s) ++ seq[string]{k}`, `res[0] == s[1]`) rather than as quantified
  membership; guard every index in a contract (`1 < len(s) ==> res[0] == s[1]`), since
  contracts are checked for well-formedness before the case split.
* **Spec reads need a matching permission.** Every field or slice element a contract reads
  must be covered by an `acc` in the same state, and a folded predicate is not always
  unfolded where the contract needs it. Models that pass restriction sets *by value*
  sidestep this entirely: locals carry no permission in Gobra.
* **Quantifiers over slices want triggers** (`exists j int :: { names[j] } ...`) or the
  prover never instantiates them.
* `none` is a keyword.

The style that works: state the decision as an exact table (`ensures res == <the whole
formula>`), then write the security claims as small `func`s that build a case and `assert`
the outcome. A table whose cell is wrong fails immediately and names the row.

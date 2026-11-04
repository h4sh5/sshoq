# Formal verification

Three commands, in this order:

```sh
make proof-setup          # JDK, sbt, Z3, pinned Gobra -> .proof-tools (idempotent)
make proof-conformance    # the models still behave like the Go code they model
make proof                # Gobra checks every proof obligation in proof/*/model.gobra
```

`make proof-all` runs all three. CI does the same in `.github/workflows/proof.yml`.

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
* **There is no `delete`.** The builtins are `make`, `len`, `append`, `copy`, `min`, `max`.
  A map that forgets keys has to be rebuilt in a loop under a ghost "visited" set, which is
  why the throttle's *memory* bound is a Go test rather than a lemma.
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

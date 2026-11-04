#!/usr/bin/env bash
#
# run-proofs.sh -- run the Gobra proofs of the sshoq security requirements.
#
# Every file under proof/ is a self-contained Gobra unit: Go code (a model of the
# decision logic of the server) annotated with the contract the requirement in
# proof/SECURITY_REQUIREMENTS.md states. Gobra discharges those contracts
# deductively, so "it works on the inputs we thought of" is not part of the
# argument.
#
# Usage:
#   ./scripts/run-proofs.sh              # verify every proof/*.gobra
#   ./scripts/run-proofs.sh proof/x.gobra  # verify only the given units
#
# Environment:
#   SSHOQ_TOOLS_DIR  where setup-gobra.sh installed the toolchain
#   GOBRA_SETUP=1    run scripts/setup-gobra.sh first if it is missing
#   PROOF_TIMEOUT    per-package verification timeout (default 300s)
#   PROOF_ASSERT_TIMEOUT  per-Z3-query timeout in ms (default 300000)
#   PROOF_BACKEND    silicon (default) or carbon
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="${SSHOQ_TOOLS_DIR:-$REPO_ROOT/.proof-tools}"
GOBRA="$TOOLS_DIR/bin/gobra"
PROOF_TIMEOUT="${PROOF_TIMEOUT:-120s}"
PROOF_ASSERT_TIMEOUT="${PROOF_ASSERT_TIMEOUT:-60000}"
PROOF_BACKEND="${PROOF_BACKEND:-SILICON}"

if [[ ! -x "$GOBRA" ]]; then
	if [[ "${GOBRA_SETUP:-0}" == "1" ]]; then
		"$REPO_ROOT/scripts/setup-gobra.sh"
	else
		echo "error: gobra is not installed at $GOBRA" >&2
		echo "       run ./scripts/setup-gobra.sh (or make proof-setup) first" >&2
		exit 2
	fi
fi

# Z3_EXE and JAVA_HOME are pinned by the installer; a stale environment must not
# silently point the proof at a different solver build.
# shellcheck disable=SC1091
source "$TOOLS_DIR/env.sh"

# Shipped files with their own annotations. Listed, not discovered: a file belongs to the proof when
# its specs do, and a file that stops compiling because someone added an import is a proof that
# silently stopped covering anything.
#
# identity_checks.go reached that list by separating a decision from the message that goes with it --
# the fmt stub makes that the only way into this list for a file that refuses things -- and the same
# move is what every remaining Phase 3 candidate needs.
INPLACE_UNITS=(
	"$REPO_ROOT/cmd/host_trust_rules.go"
	"$REPO_ROOT/glob.go"
	"$REPO_ROOT/identity_checks.go"
	"$REPO_ROOT/source_check.go"
	"$REPO_ROOT/server_auth/throttle_rules.go"
	"$REPO_ROOT/server_auth/truncate.go"
	"$REPO_ROOT/util/equalfold.go"
	"$REPO_ROOT/util/unix_util/account_rules.go"
	"$REPO_ROOT/util/varint.go"
	"$REPO_ROOT/version_rules.go"
)

mapfile -t UNITS < <(
	if [[ $# -gt 0 ]]; then
		printf '%s\n' "$@"
	else
		find "$REPO_ROOT/proof" -name '*.gobra' | sort
		printf '%s\n' "${INPLACE_UNITS[@]}"
	fi
)

if [[ ${#UNITS[@]} -eq 0 ]]; then
	echo "error: no proof units found under $REPO_ROOT/proof" >&2
	exit 2
fi

echo "== formal verification of sshoq (gobra ${GOBRA_REF:-unknown}, backend=$PROOF_BACKEND, package timeout=$PROOF_TIMEOUT)"
printf '   unit: %s\n' "${UNITS[@]#$REPO_ROOT/}"

status=0
# Each unit is verified separately: one unit failing must not hide the verdict of
# the others, and a Z3 timeout in one must not abort the run.
for unit in "${UNITS[@]}"; do
	name="${unit#"$REPO_ROOT"/}"
	printf -- '--- %s ... ' "$name"
	log="$TOOLS_DIR/last-proof.log"
	# -i: verify exactly this file's package; -I: where to resolve imports.
	if "$GOBRA" -i "$unit" \
		-I "$REPO_ROOT/proof" \
		--backend "$PROOF_BACKEND" \
		--packageTimeout "$PROOF_TIMEOUT" \
		--assertTimeout "$PROOF_ASSERT_TIMEOUT" >"$log" 2>&1; then
		echo "OK"
	else
		echo "FAILED"
		sed "s/^/    /" "$log"
		status=1
	fi
done

if [[ $status -eq 0 ]]; then
	echo "== all proof units verified"
else
	echo "== proof failures (see above)"
fi
exit $status

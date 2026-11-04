#!/usr/bin/env bash
#
# setup-gobra.sh -- install the toolchain needed by `make proof`.
#
# The proof pipeline is Gobra (https://github.com/viperproject/gobra), a
# deductive verifier for Go programs. Gobra publishes no prebuilt binaries, so
# this script builds it from a pinned tag with sbt. Everything lands in a
# single tools directory (default: $REPO/.proof-tools) which is gitignored, so
# the repository stays clean and CI can cache the whole directory.
#
# What gets installed:
#   * a JDK in the 17..21 range (Gobra/Viper are built and tested there; a very
#     new JDK can break the Viper backends, so we do not just use whatever
#     `java` happens to be on PATH)
#   * sbt, at the version pinned in proof/gobra.version's tool section
#   * Z3 (the SMT solver used by Silicon, Gobra's default backend)
#   * Gobra itself, assembled into a fat jar, plus a small `gobra` wrapper
#
# Usage:
#   ./scripts/setup-gobra.sh              # install (idempotent)
#   ./scripts/setup-gobra.sh --version    # print the pins and exit
#
# Environment overrides:
#   SSHOQ_TOOLS_DIR   where to install (default <repo>/.proof-tools)
#   GOBRA_REF         Gobra git ref to build (default: contents of proof/gobra.version)
#   SKIP_APT=1        do not try to install system packages (assume they exist)
#   APT=...           package manager command (default: apt-get)
#
set -euo pipefail

log() { printf '[setup-gobra] %s\n' "$*"; }
die() { printf '[setup-gobra] ERROR: %s\n' "$*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="${SSHOQ_TOOLS_DIR:-$REPO_ROOT/.proof-tools}"
VERSION_FILE="$REPO_ROOT/proof/gobra.version"
APT="${APT:-apt-get}"
SKIP_APT="${SKIP_APT:-0}"

# Pinned toolchain. The Gobra tag is the source of truth for what the proofs in
# proof/ mean: Gobra's annotation language evolves, so a proof that checks today
# is only meaningful against the same version.
DEFAULT_GOBRA_REF="v26.09"
SBT_VERSION="1.13.0"
Z3_VERSION="4.16.0"
JAVA_PACKAGE="openjdk-21-jdk-headless"

# Note the guards below: under `set -o pipefail`, a `cat` of a missing version file
# inside a command substitution in an assignment makes the assignment fail, which
# aborts the whole script before anything is installed.
if [[ -z "${GOBRA_REF:-}" && -f "$VERSION_FILE" ]]; then
	GOBRA_REF="$(tr -d '[:space:]' < "$VERSION_FILE")"
fi
GOBRA_REF="${GOBRA_REF:-$DEFAULT_GOBRA_REF}"
GOBRA_REF="${GOBRA_REF:-$DEFAULT_GOBRA_REF}"

if [[ "${1:-}" == "--version" ]]; then
	echo "gobra=$GOBRA_REF sbt=$SBT_VERSION z3=$Z3_VERSION java-package=$JAVA_PACKAGE"
	exit 0
fi

mkdir -p "$TOOLS_DIR"/{bin,src,share}

# ---------------------------------------------------------------- JDK ---------
# Prefer an existing JDK 17..21; install one through apt when nothing fits.
find_jdk() {
	local home ver major
	for home in "${JAVA_HOME_DIR:-}" /usr/lib/jvm/*-openjdk-amd64 /usr/lib/jvm/*; do
		[[ -n "$home" && -x "$home/bin/java" ]] || continue
		ver="$("$home/bin/java" -version 2>&1 | sed -n '1s/.*version "\([0-9]*\).*/\1/p')"
		[[ -n "$ver" ]] || continue
		major="$ver"
		if (( major >= 17 && major <= 21 )); then
			echo "$home"
			return 0
		fi
	done
	return 1
}

JAVA_HOME_DIR="$(find_jdk || true)"
if [[ -z "$JAVA_HOME_DIR" ]]; then
	if [[ "$SKIP_APT" == "1" ]]; then
		die "no JDK 17..21 found and SKIP_APT=1"
	fi
	log "installing $JAVA_PACKAGE"
	"$APT" update -qq >/dev/null
	DEBIAN_FRONTEND=noninteractive "$APT" install -y -qq "$JAVA_PACKAGE" >/dev/null
	JAVA_HOME_DIR="$(find_jdk || true)"
	[[ -n "$JAVA_HOME_DIR" ]] || die "still no usable JDK after installing $JAVA_PACKAGE"
fi
export JAVA_HOME="$JAVA_HOME_DIR"
export PATH="$JAVA_HOME/bin:$PATH"
log "using JDK $JAVA_HOME ($("$JAVA_HOME/bin/java" -version 2>&1 | head -1 | tr -d '\n'))"

# ----------------------------------------------------------------- sbt --------
SBT_BIN="$TOOLS_DIR/share/sbt/bin/sbt"
if [[ ! -x "$SBT_BIN" ]]; then
	log "downloading sbt $SBT_VERSION"
	curl -fsSL -o "$TOOLS_DIR/sbt.tgz" \
		"https://github.com/sbt/sbt/releases/download/v$SBT_VERSION/sbt-$SBT_VERSION.tgz"
	tar -xzf "$TOOLS_DIR/sbt.tgz" -C "$TOOLS_DIR/share"
	rm -f "$TOOLS_DIR/sbt.tgz"
fi
log "using sbt at $SBT_BIN"

# ----------------------------------------------------------------- z3 ---------
Z3_BIN="$TOOLS_DIR/bin/z3"
if [[ ! -x "$Z3_BIN" ]]; then
	log "downloading z3 $Z3_VERSION"
	# glibc 2.39 builds: needs a glibc >= 2.38 distro (Ubuntu 24.04 / Debian 13).
	curl -fsSL -o "$TOOLS_DIR/z3.zip" \
		"https://github.com/Z3Prover/z3/releases/download/z3-$Z3_VERSION/z3-$Z3_VERSION-x64-glibc-2.39.zip"
	mkdir -p "$TOOLS_DIR/share/z3"
	unzip -qo "$TOOLS_DIR/z3.zip" -d "$TOOLS_DIR/share/z3"
	rm -f "$TOOLS_DIR/z3.zip"
	Z3_BIN="$(find "$TOOLS_DIR/share/z3" -name z3 -type f | head -1)"
	[[ -n "$Z3_BIN" ]] || die "z3 binary not found in the downloaded archive"
	chmod +x "$Z3_BIN"
	ln -sf "$Z3_BIN" "$TOOLS_DIR/bin/z3"
fi
"$Z3_BIN" --version | sed 's/^/[setup-gobra] /'
Z3_EXE="$Z3_BIN"
export Z3_EXE

# -------------------------------------------------------------- gobra --------
GOBRA_SRC="$TOOLS_DIR/src/gobra"
if [[ ! -d "$GOBRA_SRC/.git" ]]; then
	log "cloning gobra $GOBRA_REF (this is the slow part)"
	git clone --depth 1 --branch "$GOBRA_REF" --recurse-submodules \
		https://github.com/viperproject/gobra.git "$GOBRA_SRC"
else
	( cd "$GOBRA_SRC" && git fetch --depth 1 origin tag "$GOBRA_REF" 2>/dev/null || true
	  git checkout -q "$GOBRA_REF" 2>/dev/null || true )
fi
( cd "$GOBRA_SRC" && git submodule sync --recursive >/dev/null && \
	git submodule update --init --recursive --depth 1 )

ASSEMBLY_DIR="$GOBRA_SRC/target/scala-2.13"
GOBRA_JAR="$(ls "$ASSEMBLY_DIR"/gobra-assembly-*.jar 2>/dev/null | head -1 || true)"
if [[ -z "$GOBRA_JAR" ]]; then
	log "building gobra ($GOBRA_REF) with sbt assembly -- several minutes on a cold cache"
	# SBT_OPTS: silver/silicon are large Scala projects; the default heap OOMs.
	( cd "$GOBRA_SRC" && SBT_OPTS="-Xmx6G -Xss16m" \
		"$SBT_BIN" -batch -Dsbt.color=false -Dsbt.supershell=false assembly )
	GOBRA_JAR="$(ls "$ASSEMBLY_DIR"/gobra-assembly-*.jar 2>/dev/null | head -1 || true)"
	[[ -n "$GOBRA_JAR" ]] || die "sbt assembly produced no jar"
fi

ln -sf "$GOBRA_JAR" "$TOOLS_DIR/share/gobra.jar"
GOBRA_JAR="$TOOLS_DIR/share/gobra.jar"

cat > "$TOOLS_DIR/bin/gobra" <<EOF
#!/usr/bin/env bash
# Generated by scripts/setup-gobra.sh -- runs the pinned Gobra build.
export JAVA_HOME="\${JAVA_HOME:-$JAVA_HOME}"
export Z3_EXE="\${Z3_EXE:-$Z3_EXE}"
exec "\$JAVA_HOME/bin/java" -Xss128m -jar "$GOBRA_JAR" "\$@"
EOF
chmod +x "$TOOLS_DIR/bin/gobra"

cat > "$TOOLS_DIR/env.sh" <<EOF
# Generated by scripts/setup-gobra.sh. Source this to run gobra by hand.
export JAVA_HOME="$JAVA_HOME"
export Z3_EXE="$Z3_EXE"
export GOBRA_JAR="$GOBRA_JAR"
export GOBRA_REF="$GOBRA_REF"
export PATH="$TOOLS_DIR/bin:\$PATH"
EOF

"$TOOLS_DIR/bin/gobra" --version | sed 's/^/[setup-gobra] /' || true
log "gobra is ready: $TOOLS_DIR/bin/gobra"
log "source it with:  source $TOOLS_DIR/env.sh"
log "GOBRA SETUP COMPLETE"

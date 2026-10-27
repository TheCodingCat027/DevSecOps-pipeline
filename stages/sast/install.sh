#!/usr/bin/env bash
# stages/sast/install.sh — ensure the PINNED Semgrep CLI is available.
#
# Prints the absolute path of the `semgrep` executable on STDOUT (nothing else);
# diagnostics go to STDERR.  Idempotent.
#
# Semgrep is a Python package, so it is installed into its OWN virtual environment
# (never the project's or the system's interpreter):
#   ${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/semgrep-<version>/venv/bin/semgrep
#
# Environment knobs (all optional):
#   SEMGREP_BIN       Use this executable instead of installing (tests / air-gapped use).
#   SEMGREP_PYTHON    Interpreter used to create the venv (default: python3, needs >= 3.9).
#   PIP_INDEX_URL / PIP_EXTRA_INDEX_URL / PIP_CERT   honoured by pip as usual (internal mirror).
#   XDG_CACHE_HOME    Relocates the cache.
#
# Exit: 0 ok, 1 install failed.

set -euo pipefail

SEMGREP_VERSION="1.182.1"

log() { echo "[sast:install] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

if [[ -n "${SEMGREP_BIN:-}" ]]; then
    [[ -x "$SEMGREP_BIN" ]] || die "SEMGREP_BIN is set but not executable: $SEMGREP_BIN"
    echo "$SEMGREP_BIN"
    exit 0
fi

CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/devsecops"
INSTALL_DIR="$CACHE_ROOT/semgrep-$SEMGREP_VERSION"
VENV="$INSTALL_DIR/venv"
BIN="$VENV/bin/semgrep"
OK_MARKER="$INSTALL_DIR/.install-ok"

installed_version() {
    # --disable-version-check + metrics off: the version query must not phone home.
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 "$BIN" --version 2>/dev/null | head -n1 | tr -d '[:space:]'
}

if [[ -x "$BIN" && -f "$OK_MARKER" && "$(installed_version || true)" == "$SEMGREP_VERSION" ]]; then
    echo "$BIN"
    exit 0
fi

PY="${SEMGREP_PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || die "python interpreter not found: $PY"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
    || die "semgrep needs Python >= 3.9 ($PY is older)"

log "installing semgrep==$SEMGREP_VERSION into $VENV"
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cleanup_on_error() { rm -rf "$INSTALL_DIR"; }
trap cleanup_on_error ERR

"$PY" -m venv "$VENV" || die "could not create the virtual environment"

attempt=1
until "$VENV/bin/python" -m pip install --quiet --no-input --disable-pip-version-check \
        --only-binary=:all: "semgrep==$SEMGREP_VERSION" >&2; do
    if (( attempt >= 3 )); then
        rm -rf "$INSTALL_DIR"
        die "pip could not install semgrep==$SEMGREP_VERSION after $attempt attempts"
    fi
    attempt=$((attempt + 1))
    log "pip install failed; retry $attempt/3"
    sleep 3
done
trap - ERR

[[ "$(installed_version || true)" == "$SEMGREP_VERSION" ]] \
    || { rm -rf "$INSTALL_DIR"; die "installed semgrep does not report version $SEMGREP_VERSION"; }

echo "$SEMGREP_VERSION" > "$OK_MARKER"
log "installed $BIN"
echo "$BIN"

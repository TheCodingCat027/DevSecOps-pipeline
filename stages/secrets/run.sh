#!/usr/bin/env bash
# stages/secrets/run.sh — secrets stage (Gitleaks, pinned; see install.sh)
#
# Usage: run.sh <target_path> <output_dir>
#   -> <output_dir>/secrets.sarif   (written only when the scan completed)
#   exit 0  scan completed (findings are data, not errors)
#   exit 1  the scanner itself failed (no SARIF is left behind: fail closed)
#   exit 2  usage error
#
# Interface: contracts/stage-interface.md
# Environment knobs: see README.md ("Environment variables").

set -euo pipefail

log() { echo "[secrets] $*" >&2; }

# ---------------------------------------------------------------------------
# Usage checks (exit 2)
# ---------------------------------------------------------------------------
if [[ $# -ne 2 ]]; then
    log "ERROR: expected 2 arguments: <target_path> <output_dir>"
    log "Usage: $0 <target_path> <output_dir>"
    exit 2
fi
TARGET_PATH="$1"
OUTPUT_DIR="$2"
if [[ ! -e "$TARGET_PATH" ]]; then
    log "ERROR: target path does not exist: $TARGET_PATH"
    exit 2
fi

# ---------------------------------------------------------------------------
# Locations (never derived from the current working directory)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHON="${PYTHON:-python3}"
CONFIG="${SECRETS_CONFIG:-$SCRIPT_DIR/gitleaks.toml}"
STAGE_TIMEOUT="${STAGE_TIMEOUT:-600}"
SECRETS_SCAN_HISTORY="${SECRETS_SCAN_HISTORY:-1}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
SARIF_OUT="$OUTPUT_DIR/secrets.sarif"

if [[ -d "$TARGET_PATH" ]]; then
    TARGET_ABS="$(cd "$TARGET_PATH" && pwd -P)"
else
    TARGET_ABS="$(cd "$(dirname "$TARGET_PATH")" && pwd -P)/$(basename "$TARGET_PATH")"
fi

# ---------------------------------------------------------------------------
# Fail-closed plumbing: a stale or partial report must never look like success
# ---------------------------------------------------------------------------
rm -f "$SARIF_OUT"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/secrets-stage.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
fail() {
    log "ERROR: $*"
    rm -f "$SARIF_OUT"
    exit 1
}

# Run a command with a wall-clock limit (coreutils `timeout`, else a python fallback).
run_limited() {
    if command -v timeout >/dev/null 2>&1; then
        timeout --kill-after=10 "$STAGE_TIMEOUT" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout --kill-after=10 "$STAGE_TIMEOUT" "$@"
    else
        "$PYTHON" -c '
import subprocess, sys
try:
    sys.exit(subprocess.run(sys.argv[2:], timeout=float(sys.argv[1])).returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
' "$STAGE_TIMEOUT" "$@"
    fi
}

# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------
GITLEAKS="$(bash "$SCRIPT_DIR/install.sh")" || fail "could not provision the pinned gitleaks binary"
[[ -f "$CONFIG" ]] || fail "gitleaks config not found: $CONFIG"
GITLEAKS_VERSION="$("$GITLEAKS" version 2>/dev/null | tr -d '[:space:]')" \
    || fail "gitleaks does not run: $GITLEAKS"
[[ -n "$GITLEAKS_VERSION" ]] || fail "could not determine the gitleaks version"
log "using gitleaks $GITLEAKS_VERSION ($GITLEAKS)"

# Settings shared by both scans.
#  --exit-code 0            findings never change the exit code; real errors still do
#  --redact                 secret values are masked in the raw report too
#  --ignore-gitleaks-allow  inline `gitleaks:allow` comments must not suppress findings
#                           (suppression is the gate's job: waivers in security-policy.yaml)
#  -i <empty dir>           a .gitleaksignore inside the target is not honoured, for the same reason
mkdir -p "$TMP/empty-ignore"
COMMON=(--no-banner --no-color -l warn --exit-code 0 --redact
        --ignore-gitleaks-allow -i "$TMP/empty-ignore" -c "$CONFIG"
        --max-decode-depth 5 -f json)

# ---------------------------------------------------------------------------
# Scan A: working tree (no git needed)
# ---------------------------------------------------------------------------
log "scanning working tree: $TARGET_ABS"
run_limited "$GITLEAKS" dir "$TARGET_ABS" "${COMMON[@]}" -r "$TMP/tree.json" >&2 \
    || fail "gitleaks working-tree scan failed or timed out (exit $?)"
[[ -s "$TMP/tree.json" ]] || fail "gitleaks produced no working-tree report"

# ---------------------------------------------------------------------------
# Scan B: git history, restricted to the target's path.
# Without a pathspec, `gitleaks git <repo>` scans every path in every ref even
# when the target is a sub-directory (verified empirically on gitleaks 8.30.1),
# which would report secrets outside the target.  We pass a pathspec, and
# to_sarif.py additionally drops anything outside the target.
# ---------------------------------------------------------------------------
GIT_TOP=""
HISTORY_ARGS=()
if [[ "$SECRETS_SCAN_HISTORY" == "1" ]] && command -v git >/dev/null 2>&1; then
    probe_dir="$TARGET_ABS"; [[ -d "$probe_dir" ]] || probe_dir="$(dirname "$probe_dir")"
    if GIT_TOP="$(git -C "$probe_dir" rev-parse --show-toplevel 2>/dev/null)" \
        && git -C "$GIT_TOP" rev-parse --verify -q HEAD >/dev/null 2>&1; then
        GIT_TOP="$(cd "$GIT_TOP" && pwd -P)"
        REL="${TARGET_ABS#"$GIT_TOP"}"; REL="${REL#/}"
        LOG_OPTS="--all"
        if [[ -n "$REL" ]]; then
            if [[ "$REL" =~ [[:space:]] ]]; then
                log "WARNING: target path contains whitespace; scanning all history and filtering afterwards"
            else
                LOG_OPTS="--all -- $REL"
            fi
        fi
        log "scanning git history of $GIT_TOP (log options: $LOG_OPTS)"
        run_limited "$GITLEAKS" git "$GIT_TOP" "${COMMON[@]}" --log-opts="$LOG_OPTS" \
            -r "$TMP/history.json" >&2 \
            || fail "gitleaks history scan failed or timed out (exit $?)"
        [[ -s "$TMP/history.json" ]] || fail "gitleaks produced no history report"
        HISTORY_ARGS=(--history-report "$TMP/history.json" --git-top "$GIT_TOP")
    else
        GIT_TOP=""
        log "target is not inside a git repository with commits; history scan skipped"
    fi
else
    log "history scan disabled or git unavailable; working tree only"
fi

# ---------------------------------------------------------------------------
# Convert to SARIF (atomic write inside the output directory)
# ---------------------------------------------------------------------------
"$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
    --tree-report "$TMP/tree.json" \
    ${HISTORY_ARGS[@]+"${HISTORY_ARGS[@]}"} \
    --target "$TARGET_ABS" \
    --repo-root "$REPO_ROOT" \
    --tool-version "$GITLEAKS_VERSION" \
    --out "$SARIF_OUT" >&2 \
    || fail "conversion to SARIF failed"

[[ -s "$SARIF_OUT" ]] || fail "SARIF was not written"
log "Done. Output: $SARIF_OUT"
exit 0

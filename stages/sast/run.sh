#!/usr/bin/env bash
# stages/sast/run.sh — SAST stage (Semgrep, pinned; see install.sh)
#
# Usage: run.sh <target_path> <output_dir>
#   -> <output_dir>/sast.sarif   (written only when the scan completed)
#   exit 0  scan completed (findings are data, not errors)
#   exit 1  scanner failed / timed out / rules or registry unavailable (no SARIF left behind)
#   exit 2  usage error
#
# Interface: contracts/stage-interface.md
# Environment knobs: see README.md ("Environment variables").

set -euo pipefail

log() { echo "[sast] $*" >&2; }

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
# Locations and knobs (never derived from the current working directory)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHON="${PYTHON:-python3}"
STAGE_TIMEOUT="${STAGE_TIMEOUT:-600}"
SAST_CUSTOM_RULES="${SAST_CUSTOM_RULES:-1}"
# NOTE: ${VAR-default} (no colon): an EMPTY value means "no registry packs".
SAST_REGISTRY_PACKS="${SAST_REGISTRY_PACKS-p/python p/flask p/owasp-top-ten}"
SAST_ALLOW_OFFLINE="${SAST_ALLOW_OFFLINE:-0}"
RULES_DIR="${SAST_RULES_DIR:-$SCRIPT_DIR/rules}"

if [[ "$SAST_CUSTOM_RULES" != "0" && "$SAST_CUSTOM_RULES" != "1" ]]; then
    log "ERROR: SAST_CUSTOM_RULES must be 0 or 1 (got '$SAST_CUSTOM_RULES')"; exit 2
fi
read -r -a PACKS <<< "$SAST_REGISTRY_PACKS"
if [[ "$SAST_CUSTOM_RULES" == "0" && ${#PACKS[@]} -eq 0 ]]; then
    log "ERROR: no rules selected (SAST_CUSTOM_RULES=0 and SAST_REGISTRY_PACKS is empty)"; exit 2
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
SARIF_OUT="$OUTPUT_DIR/sast.sarif"

if [[ -d "$TARGET_PATH" ]]; then
    TARGET_ABS="$(cd "$TARGET_PATH" && pwd -P)"
else
    TARGET_ABS="$(cd "$(dirname "$TARGET_PATH")" && pwd -P)/$(basename "$TARGET_PATH")"
fi

# ---------------------------------------------------------------------------
# Fail-closed plumbing: a stale or partial report must never look like success
# ---------------------------------------------------------------------------
rm -f "$SARIF_OUT"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/sast-stage.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
fail() {
    log "ERROR: $*"
    rm -f "$SARIF_OUT"
    exit 1
}

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
SEMGREP="$(bash "$SCRIPT_DIR/install.sh")" || fail "could not provision the pinned semgrep"
[[ "$SAST_CUSTOM_RULES" == "0" || -d "$RULES_DIR" ]] || fail "custom rules directory not found: $RULES_DIR"

# Semgrep must not write anything under $HOME or the target, and must not phone home.
export SEMGREP_SETTINGS_FILE="$TMP/settings.yml"
export SEMGREP_VERSION_CACHE_PATH="$TMP/version-cache"
export SEMGREP_LOG_FILE="$TMP/semgrep.log"
export SEMGREP_SEND_METRICS=off
export SEMGREP_ENABLE_VERSION_CHECK=0
export SEMGREP_FORCE_COLOR=0
export NO_COLOR=1

# Not source: test code, vendored/virtual-env/VCS directories, bytecode, build output, minified bundles.
EXCLUDES=(tests test __tests__ node_modules .git venv .venv __pycache__ site-packages dist build
          'test_*.py' '*_test.py' conftest.py '*.min.js')
EXCLUDE_ARGS=()
for e in "${EXCLUDES[@]}"; do EXCLUDE_ARGS+=(--exclude "$e"); done

# --no-git-ignore      scan what is on disk, not only what git tracks
# --disable-nosem      inline `# nosem` comments must not suppress findings (the gate owns waivers)
# --no-rewrite-rule-ids  custom rule ids are reported exactly as written in rules/*.yaml
COMMON=(--metrics=off --disable-version-check --no-git-ignore --disable-nosem
        --no-rewrite-rule-ids "${EXCLUDE_ARGS[@]}"
        --json --output "$TMP/semgrep.json")

if [[ -f "$TARGET_ABS/.semgrepignore" ]]; then
    log "WARNING: $TARGET_ABS/.semgrepignore exists; Semgrep honours it and it can hide files from this scan"
fi

run_semgrep() { # run_semgrep <use_custom 0|1> <use_registry 0|1>
    local cfg=()
    [[ "$1" == "1" ]] && cfg+=(--config "$RULES_DIR")
    if [[ "$2" == "1" ]]; then for p in "${PACKS[@]}"; do cfg+=(--config "$p"); done; fi
    rm -f "$TMP/semgrep.json"
    local rc=0
    run_limited "$SEMGREP" scan "${COMMON[@]}" "${cfg[@]}" "$TARGET_ABS" >"$TMP/semgrep.out" 2>"$TMP/semgrep.err" || rc=$?
    if [[ $rc -ne 0 ]]; then
        log "semgrep exited with $rc; last lines of its error output:"
        tail -n 6 "$TMP/semgrep.err" | sed 's/^/[sast]   | /' >&2
    fi
    return $rc
}

# Fast pre-flight for the rule registry: an unreachable registry otherwise costs ~100 s of
# internal retries before Semgrep gives up.  The probe only short-circuits; a reachable
# registry is still fetched (and failures still handled) by Semgrep itself.
registry_reachable() {
    command -v curl >/dev/null 2>&1 || return 0
    curl -sS -m 10 -o /dev/null -I "${SAST_REGISTRY_URL:-https://semgrep.dev}/" >/dev/null 2>&1
}

USE_CUSTOM="$SAST_CUSTOM_RULES"
USE_REGISTRY=0; [[ ${#PACKS[@]} -gt 0 ]] && USE_REGISTRY=1
REGISTRY_APPLIED="false"; [[ $USE_REGISTRY -eq 1 ]] && REGISTRY_APPLIED="true"

log "scanning $TARGET_ABS (custom rules: $USE_CUSTOM, registry packs: ${SAST_REGISTRY_PACKS:-none})"
RC=0
REGISTRY_DOWN=0
if [[ $USE_REGISTRY -eq 1 ]] && ! registry_reachable; then
    log "rule registry ${SAST_REGISTRY_URL:-https://semgrep.dev} is not reachable"
    REGISTRY_DOWN=1
    RC=2
else
    set +e
    run_semgrep "$USE_CUSTOM" "$USE_REGISTRY"
    RC=$?
    set -e
fi

if [[ $RC -ne 0 ]]; then
    if [[ $USE_REGISTRY -eq 1 && "$SAST_ALLOW_OFFLINE" == "1" && "$USE_CUSTOM" == "1" ]]; then
        log "WARNING: semgrep failed (exit $RC) with registry packs [${SAST_REGISTRY_PACKS}]."
        log "WARNING: SAST_ALLOW_OFFLINE=1 -> continuing with the LOCAL RULES ONLY. Registry coverage is NOT applied."
        USE_REGISTRY=0; REGISTRY_APPLIED="false"
        set +e
        run_semgrep 1 0
        RC=$?
        set -e
    fi
fi
if [[ $RC -ne 0 ]]; then
    if [[ $RC -eq 124 || $RC -eq 137 ]]; then fail "semgrep timed out after ${STAGE_TIMEOUT}s"; fi
    if [[ $USE_REGISTRY -eq 1 ]]; then
        why=""; [[ $REGISTRY_DOWN -eq 1 ]] && why=", registry unreachable"
        fail "semgrep failed (exit ${RC}${why}). Set SAST_ALLOW_OFFLINE=1 to accept a local-rules-only scan, or SAST_REGISTRY_PACKS= to disable the registry"
    fi
    fail "semgrep failed (exit $RC)"
fi
[[ -s "$TMP/semgrep.json" ]] || fail "semgrep produced no JSON report"

# ---------------------------------------------------------------------------
# Convert to SARIF (atomic write inside the output directory)
# ---------------------------------------------------------------------------
"$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
    --report "$TMP/semgrep.json" \
    --target "$TARGET_ABS" \
    --repo-root "$REPO_ROOT" \
    --custom-rules-dir "$RULES_DIR" \
    --custom-rules "$USE_CUSTOM" \
    --registry-packs "${SAST_REGISTRY_PACKS}" \
    --registry-applied "$REGISTRY_APPLIED" \
    --out "$SARIF_OUT" >&2 \
    || fail "conversion to SARIF failed"

[[ -s "$SARIF_OUT" ]] || fail "SARIF was not written"
log "Done. Output: $SARIF_OUT"
exit 0

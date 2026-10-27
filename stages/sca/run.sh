#!/usr/bin/env bash
# stages/sca/run.sh — SCA stage (Trivy filesystem mode, vulnerability scanner only; see install.sh)
#
# Usage: run.sh <target_path> <output_dir>
#   -> <output_dir>/sca.sarif   (written only when the scan completed)
#   exit 0  scan completed (findings are data, not errors; "no manifests" is a valid empty scan)
#   exit 1  the scanner failed / timed out / no usable vulnerability DB (no SARIF is left behind)
#   exit 2  usage error
#
# Interface: contracts/stage-interface.md
# Environment knobs: see README.md ("Environment variables").

set -euo pipefail

log() { echo "[sca] $*" >&2; }

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
SCA_DB_RETRIES="${SCA_DB_RETRIES:-3}"
SCA_DB_RETRY_DELAY="${SCA_DB_RETRY_DELAY:-10}"
SCA_DB_MAX_AGE_DAYS="${SCA_DB_MAX_AGE_DAYS:-7}"
SCA_DB_REPOSITORY="${SCA_DB_REPOSITORY:-}"      # comma-separated OCI repositories (mirror), default: Trivy's own
CACHE_DIR="${SCA_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-db}"

for v in STAGE_TIMEOUT SCA_DB_RETRIES SCA_DB_RETRY_DELAY SCA_DB_MAX_AGE_DAYS; do
    if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then log "ERROR: $v must be a non-negative integer (got '${!v}')"; exit 2; fi
done
[[ "$SCA_DB_RETRIES" -ge 1 ]] || { log "ERROR: SCA_DB_RETRIES must be >= 1"; exit 2; }

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
SARIF_OUT="$OUTPUT_DIR/sca.sarif"

if [[ -d "$TARGET_PATH" ]]; then
    TARGET_ABS="$(cd "$TARGET_PATH" && pwd -P)"
else
    TARGET_ABS="$(cd "$(dirname "$TARGET_PATH")" && pwd -P)/$(basename "$TARGET_PATH")"
fi

# ---------------------------------------------------------------------------
# Fail-closed plumbing: a stale or partial report must never look like success
# ---------------------------------------------------------------------------
rm -f "$SARIF_OUT"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/sca-stage.XXXXXX")"
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
TRIVY="$(bash "$SCRIPT_DIR/install.sh")" || fail "could not provision the pinned trivy binary"
TRIVY_VERSION="$("$TRIVY" --version 2>/dev/null | awk '/^Version:/ {print $2; exit}')" \
    || fail "trivy does not run: $TRIVY"
[[ -n "$TRIVY_VERSION" ]] || fail "could not determine the trivy version"
log "using trivy $TRIVY_VERSION ($TRIVY)"

# The cache (DB, analysis cache) lives OUTSIDE the target; nothing is written into the target.
mkdir -p "$CACHE_DIR" || fail "cannot create the cache directory: $CACHE_DIR"
case "$CACHE_DIR/" in
    "$TARGET_ABS"/*) fail "cache directory must not be inside the scan target ($CACHE_DIR)" ;;
esac

# Trivy picks up .trivyignore / trivy.yaml from the CURRENT directory; run from an empty private
# directory so no file of the scanned project can suppress findings (suppression is the gate's job).
WORKDIR="$TMP/work"; mkdir -p "$WORKDIR"
: > "$TMP/empty.trivyignore"
: > "$TMP/empty.yaml"
export TRIVY_DISABLE_TELEMETRY=true

DB_REPO_ARGS=()
if [[ -n "$SCA_DB_REPOSITORY" ]]; then
    IFS=',' read -r -a _repos <<< "$SCA_DB_REPOSITORY"
    for r in "${_repos[@]}"; do [[ -n "$r" ]] && DB_REPO_ARGS+=(--db-repository "$r"); done
fi

COMMON=(--config "$TMP/empty.yaml" --cache-dir "$CACHE_DIR" --no-progress --skip-version-check --disable-telemetry)

# ---------------------------------------------------------------------------
# Vulnerability database: reuse the cache, retry downloads (bounded), else fail closed
# ---------------------------------------------------------------------------
DB_META="$CACHE_DIR/db/metadata.json"
db_age_days() { # age of the cached DB (UpdatedAt) in whole days, or empty when unknown
    [[ -f "$DB_META" && -f "$CACHE_DIR/db/trivy.db" ]] || return 0
    "$PYTHON" -I - "$DB_META" <<'PY' 2>/dev/null || true
import json, sys, datetime
m = json.load(open(sys.argv[1]))
t = m.get("UpdatedAt") or m.get("DownloadedAt")
d = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
print((datetime.datetime.now(datetime.timezone.utc) - d).days)
PY
}

# Trivy itself skips the download when the cached DB is still within its update window,
# so a warm run needs no network.
download_db() {
    local attempt=1
    while [[ $attempt -le $SCA_DB_RETRIES ]]; do
        log "vulnerability DB: update attempt $attempt/$SCA_DB_RETRIES"
        if (cd "$WORKDIR" && run_limited "$TRIVY" fs --download-db-only "${COMMON[@]}" \
                ${DB_REPO_ARGS[@]+"${DB_REPO_ARGS[@]}"} "$TARGET_ABS" >&2); then
            return 0
        fi
        attempt=$((attempt + 1))
        [[ $attempt -le $SCA_DB_RETRIES ]] && sleep "$SCA_DB_RETRY_DELAY"
    done
    return 1
}

DB_SOURCE="downloaded"
if ! download_db; then
    age="$(db_age_days)"
    if [[ -n "$age" && "$age" -le "$SCA_DB_MAX_AGE_DAYS" ]]; then
        log "WARNING: DB update failed; using the cached vulnerability DB (${age} day(s) old, limit ${SCA_DB_MAX_AGE_DAYS})"
        DB_SOURCE="cached-stale"
    elif [[ -n "$age" ]]; then
        fail "DB update failed and the cached DB is ${age} day(s) old (limit ${SCA_DB_MAX_AGE_DAYS}; raise SCA_DB_MAX_AGE_DAYS to accept it)"
    else
        fail "could not obtain the Trivy vulnerability DB (network blocked? set SCA_DB_REPOSITORY to a reachable mirror)"
    fi
fi
[[ -s "$CACHE_DIR/db/trivy.db" && -s "$DB_META" ]] || fail "vulnerability DB is missing after the update step"

# ---------------------------------------------------------------------------
# Scan: vulnerabilities only (secrets belong to the secrets stage, misconfiguration to P3's iac stage)
# ---------------------------------------------------------------------------
SKIP_ARGS=()
for d in '**/node_modules' '**/.git' '**/venv' '**/.venv' '**/__pycache__' '**/site-packages'; do
    SKIP_ARGS+=(--skip-dirs "$d")
done

log "scanning $TARGET_ABS (vulnerability scanner only)"
set +e
(cd "$WORKDIR" && run_limited "$TRIVY" fs --scanners vuln --format json --output "$TMP/trivy.json" \
    --exit-code 0 --skip-db-update --ignorefile "$TMP/empty.trivyignore" \
    --timeout "${STAGE_TIMEOUT}s" "${SKIP_ARGS[@]}" "${COMMON[@]}" "$TARGET_ABS" >&2)
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
    if [[ $RC -eq 124 || $RC -eq 137 ]]; then fail "trivy timed out after ${STAGE_TIMEOUT}s"; fi
    fail "trivy failed (exit $RC)"
fi
[[ -s "$TMP/trivy.json" ]] || fail "trivy produced no JSON report"

# ---------------------------------------------------------------------------
# Convert to SARIF (atomic write inside the output directory)
# ---------------------------------------------------------------------------
"$PYTHON" "$SCRIPT_DIR/to_sarif.py" \
    --report "$TMP/trivy.json" \
    --target "$TARGET_ABS" \
    --repo-root "$REPO_ROOT" \
    --tool-version "$TRIVY_VERSION" \
    --db-metadata "$DB_META" \
    --out "$SARIF_OUT" >&2 \
    || fail "conversion to SARIF failed"

[[ -s "$SARIF_OUT" ]] || fail "SARIF was not written"
log "Done (DB: $DB_SOURCE). Output: $SARIF_OUT"
exit 0

#!/usr/bin/env bash
# Test double for the trivy binary (used through TRIVY_BIN).  NOT a scanner: it only replays a
# canned JSON report so that run.sh can be exercised without a vulnerability database.
#   FAKE_TRIVY_REPORT       JSON file to write for a scan
#   FAKE_TRIVY_DB_FAIL=1    the DB download step fails
#   FAKE_TRIVY_DB_COUNT     file that receives one line per DB download attempt
#   FAKE_TRIVY_MODE         ok (default) | crash | hang | garbage
set -u
if [[ "${1:-}" == "--version" ]]; then echo "Version: 0.76.1"; exit 0; fi
args=("$@"); cache=""; out=""; dbonly=0
for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[$i]}" in
        --cache-dir) cache="${args[$((i + 1))]}" ;;
        --output) out="${args[$((i + 1))]}" ;;
        --download-db-only) dbonly=1 ;;
    esac
done
if [[ $dbonly -eq 1 ]]; then
    [[ -n "${FAKE_TRIVY_DB_COUNT:-}" ]] && echo attempt >> "$FAKE_TRIVY_DB_COUNT"
    [[ "${FAKE_TRIVY_DB_FAIL:-0}" == "1" ]] && { echo "fake-trivy: download failed" >&2; exit 1; }
    mkdir -p "$cache/db"; echo fake > "$cache/db/trivy.db"
    printf '{"Version":2,"UpdatedAt":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$cache/db/metadata.json"
    exit 0
fi
case "${FAKE_TRIVY_MODE:-ok}" in
    crash)   echo "fake-trivy: boom" >&2; exit 3 ;;
    hang)    sleep 30; exit 0 ;;
    garbage) printf 'not json {' > "$out"; exit 0 ;;
esac
cp "$FAKE_TRIVY_REPORT" "$out"
exit 0

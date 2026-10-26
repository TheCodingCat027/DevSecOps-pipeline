#!/usr/bin/env bash
# stages/dast/run.sh — STUB for the DAST scanning stage
#
# Owner: P3  |  Real tool: OWASP ZAP v2.15.0
# Interface: contracts/stage-interface.md
# Note: DAST is disabled by default (enabled: false in stages/stages.json)
#       Enable it in stages.json once P3 has implemented the real scanner.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "[dast] ERROR: expected 2 arguments: <target_path> <output_dir>" >&2
    exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

[[ -e "$TARGET_PATH" ]] || { echo "[dast] ERROR: target does not exist: $TARGET_PATH" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

mkdir -p "$OUTPUT_DIR"

echo "[stub] dast: replace this stub with the real scanner (owner: P3)" >&2

cp "$REPO_ROOT/contracts/samples/dast.sarif" "$OUTPUT_DIR/dast.sarif"

echo "[dast] Done. Output: $OUTPUT_DIR/dast.sarif" >&2
exit 0

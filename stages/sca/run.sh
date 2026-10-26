#!/usr/bin/env bash
# stages/sca/run.sh — STUB for the SCA (dependency) scanning stage
#
# Owner: P2  |  Real tool: Trivy fs v0.51.4
# Interface: contracts/stage-interface.md

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "[sca] ERROR: expected 2 arguments: <target_path> <output_dir>" >&2
    exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

[[ -e "$TARGET_PATH" ]] || { echo "[sca] ERROR: target does not exist: $TARGET_PATH" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

mkdir -p "$OUTPUT_DIR"

echo "[stub] sca: replace this stub with the real scanner (owner: P2)" >&2

cp "$REPO_ROOT/contracts/samples/sca.sarif" "$OUTPUT_DIR/sca.sarif"

echo "[sca] Done. Output: $OUTPUT_DIR/sca.sarif" >&2
exit 0

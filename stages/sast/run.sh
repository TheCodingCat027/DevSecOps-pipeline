#!/usr/bin/env bash
# stages/sast/run.sh — STUB for the SAST scanning stage
#
# Owner: P2  |  Real tool: Semgrep v1.78.0
# Interface: contracts/stage-interface.md

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "[sast] ERROR: expected 2 arguments: <target_path> <output_dir>" >&2
    exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

if [[ ! -e "$TARGET_PATH" ]]; then
    echo "[sast] ERROR: target path does not exist: $TARGET_PATH" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SAMPLE_SARIF="$REPO_ROOT/contracts/samples/sast.sarif"

mkdir -p "$OUTPUT_DIR"

echo "[stub] sast: replace this stub with the real scanner (owner: P2)" >&2

cp "$SAMPLE_SARIF" "$OUTPUT_DIR/sast.sarif"

echo "[sast] Done. Output: $OUTPUT_DIR/sast.sarif" >&2
exit 0

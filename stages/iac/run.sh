#!/usr/bin/env bash
# stages/iac/run.sh — STUB for the IaC scanning stage
#
# Owner: P3  |  Real tools: Hadolint v2.12.0 + Checkov 3.x
# Interface: contracts/stage-interface.md

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "[iac] ERROR: expected 2 arguments: <target_path> <output_dir>" >&2
    exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

[[ -e "$TARGET_PATH" ]] || { echo "[iac] ERROR: target does not exist: $TARGET_PATH" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

mkdir -p "$OUTPUT_DIR"

echo "[stub] iac: replace this stub with the real scanner (owner: P3)" >&2

cp "$REPO_ROOT/contracts/samples/iac.sarif" "$OUTPUT_DIR/iac.sarif"

echo "[iac] Done. Output: $OUTPUT_DIR/iac.sarif" >&2
exit 0

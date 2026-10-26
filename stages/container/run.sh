#!/usr/bin/env bash
# stages/container/run.sh — STUB for the container image scanning stage
#
# Owner: P3  |  Real tool: Trivy image v0.51.4
# Interface: contracts/stage-interface.md
# Requires: IMAGE_REF environment variable (set by CI; see contracts/stage-interface.md §7)

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "[container] ERROR: expected 2 arguments: <target_path> <output_dir>" >&2
    exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

[[ -e "$TARGET_PATH" ]] || { echo "[container] ERROR: target does not exist: $TARGET_PATH" >&2; exit 2; }

# IMAGE_REF is optional for the stub but required for the real scanner
if [[ -z "${IMAGE_REF:-}" ]]; then
    echo "[container] WARNING: IMAGE_REF not set; stub will proceed without it" >&2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

mkdir -p "$OUTPUT_DIR"

echo "[stub] container: replace this stub with the real scanner (owner: P3)" >&2

cp "$REPO_ROOT/contracts/samples/container.sarif" "$OUTPUT_DIR/container.sarif"

echo "[container] Done. Output: $OUTPUT_DIR/container.sarif" >&2
exit 0

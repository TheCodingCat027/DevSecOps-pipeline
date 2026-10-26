#!/usr/bin/env bash
# stages/secrets/run.sh — STUB for the secrets scanning stage
#
# Owner: P2
# Real tool: Gitleaks (v8.18.4 planned)
# This stub copies the sample SARIF from contracts/samples/secrets.sarif.
# P2 replaces the body of this script with the real Gitleaks invocation.
# See contracts/stage-interface.md for the full interface specification.
#
# Usage: run.sh <target_path> <output_dir>

set -euo pipefail

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

if [[ $# -ne 2 ]]; then
    echo "[secrets] ERROR: expected 2 arguments: <target_path> <output_dir>" >&2
    echo "[secrets] Usage: $0 <target_path> <output_dir>" >&2
    exit 2
fi

TARGET_PATH="$1"
OUTPUT_DIR="$2"

if [[ ! -e "$TARGET_PATH" ]]; then
    echo "[secrets] ERROR: target path does not exist: $TARGET_PATH" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Locate repo root relative to this script (do not depend on CWD)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SAMPLE_SARIF="$REPO_ROOT/contracts/samples/secrets.sarif"

# ---------------------------------------------------------------------------
# Create output directory
# ---------------------------------------------------------------------------

mkdir -p "$OUTPUT_DIR"

# ---------------------------------------------------------------------------
# Stub: copy sample SARIF
# ---------------------------------------------------------------------------

echo "[stub] secrets: replace this stub with the real scanner (owner: P2)" >&2

cp "$SAMPLE_SARIF" "$OUTPUT_DIR/secrets.sarif"

echo "[secrets] Done. Output: $OUTPUT_DIR/secrets.sarif" >&2
exit 0

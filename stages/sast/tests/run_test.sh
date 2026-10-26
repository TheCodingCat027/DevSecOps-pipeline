#!/usr/bin/env bash
# stages/sast/tests/run_test.sh — Integration test for the SAST stage stub
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
STAGE_SCRIPT="$REPO_ROOT/stages/sast/run.sh"
VALIDATE_PY="$REPO_ROOT/contracts/validate.py"
PYTHON="${PYTHON:-python3}"

TMPDIR_OUT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_OUT"' EXIT

echo "[test:sast] Running stage stub..."
bash "$STAGE_SCRIPT" "$REPO_ROOT/demo-app/vulnerable" "$TMPDIR_OUT"

[[ -f "$TMPDIR_OUT/sast.sarif" ]] || { echo "[test:sast] FAIL: sast.sarif not found" >&2; exit 1; }

"$PYTHON" "$VALIDATE_PY" "$TMPDIR_OUT/sast.sarif" --stage sast || \
    { echo "[test:sast] FAIL: sast.sarif failed validate.py" >&2; exit 1; }

echo "[test:sast] PASS"
exit 0

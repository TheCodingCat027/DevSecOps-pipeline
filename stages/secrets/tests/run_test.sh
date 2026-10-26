#!/usr/bin/env bash
# stages/secrets/tests/run_test.sh — Integration test for the secrets stage stub
#
# Runs the stage against a temp directory and asserts the SARIF exists and passes validate.py.
# P2 extends this with a known-bad input test when replacing the stub.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
STAGE_SCRIPT="$REPO_ROOT/stages/secrets/run.sh"
VALIDATE_PY="$REPO_ROOT/contracts/validate.py"
PYTHON="${PYTHON:-python3}"

# Create temp output directory
TMPDIR_OUT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_OUT"' EXIT

echo "[test:secrets] Running stage stub against demo-app/vulnerable..."
bash "$STAGE_SCRIPT" "$REPO_ROOT/demo-app/vulnerable" "$TMPDIR_OUT"

# Assert SARIF was written
if [[ ! -f "$TMPDIR_OUT/secrets.sarif" ]]; then
    echo "[test:secrets] FAIL: secrets.sarif not found in output directory" >&2
    exit 1
fi

# Assert SARIF passes validation with the --stage flag
if ! "$PYTHON" "$VALIDATE_PY" "$TMPDIR_OUT/secrets.sarif" --stage secrets; then
    echo "[test:secrets] FAIL: secrets.sarif failed validate.py --stage secrets" >&2
    exit 1
fi

echo "[test:secrets] PASS: stub stage output is valid"
exit 0

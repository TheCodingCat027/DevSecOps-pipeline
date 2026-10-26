#!/usr/bin/env bash
# stages/sca/tests/run_test.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON="${PYTHON:-python3}"
TMPDIR_OUT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_OUT"' EXIT
bash "$REPO_ROOT/stages/sca/run.sh" "$REPO_ROOT/demo-app/vulnerable" "$TMPDIR_OUT"
[[ -f "$TMPDIR_OUT/sca.sarif" ]] || { echo "[test:sca] FAIL: sca.sarif not found" >&2; exit 1; }
"$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMPDIR_OUT/sca.sarif" --stage sca || { echo "[test:sca] FAIL" >&2; exit 1; }
echo "[test:sca] PASS"

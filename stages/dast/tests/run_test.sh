#!/usr/bin/env bash
# stages/dast/tests/run_test.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON="${PYTHON:-python3}"
TMPDIR_OUT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_OUT"' EXIT
bash "$REPO_ROOT/stages/dast/run.sh" "$REPO_ROOT/demo-app/vulnerable" "$TMPDIR_OUT"
[[ -f "$TMPDIR_OUT/dast.sarif" ]] || { echo "[test:dast] FAIL: dast.sarif not found" >&2; exit 1; }
"$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMPDIR_OUT/dast.sarif" --stage dast || { echo "[test:dast] FAIL" >&2; exit 1; }
echo "[test:dast] PASS"

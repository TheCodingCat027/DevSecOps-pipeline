#!/usr/bin/env bash
# stages/iac/tests/run_test.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON="${PYTHON:-python3}"
TMPDIR_OUT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_OUT"' EXIT
bash "$REPO_ROOT/stages/iac/run.sh" "$REPO_ROOT/demo-app/vulnerable" "$TMPDIR_OUT"
[[ -f "$TMPDIR_OUT/iac.sarif" ]] || { echo "[test:iac] FAIL: iac.sarif not found" >&2; exit 1; }
"$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMPDIR_OUT/iac.sarif" --stage iac || { echo "[test:iac] FAIL" >&2; exit 1; }
echo "[test:iac] PASS"

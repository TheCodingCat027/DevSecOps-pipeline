#!/usr/bin/env bash
# stages/container/tests/run_test.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON="${PYTHON:-python3}"
TMPDIR_OUT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_OUT"' EXIT
# IMAGE_REF is not required for the stub
bash "$REPO_ROOT/stages/container/run.sh" "$REPO_ROOT/demo-app/vulnerable" "$TMPDIR_OUT"
[[ -f "$TMPDIR_OUT/container.sarif" ]] || { echo "[test:container] FAIL: container.sarif not found" >&2; exit 1; }
"$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMPDIR_OUT/container.sarif" --stage container || { echo "[test:container] FAIL" >&2; exit 1; }
echo "[test:container] PASS"

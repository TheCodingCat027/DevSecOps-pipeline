#!/usr/bin/env bash
# stages/sbom/tests/run_test.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON="${PYTHON:-python3}"
TMPDIR_OUT="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_OUT"' EXIT
bash "$REPO_ROOT/stages/sbom/run.sh" "$REPO_ROOT/demo-app/vulnerable" "$TMPDIR_OUT"
[[ -f "$TMPDIR_OUT/sbom.sarif" ]] || { echo "[test:sbom] FAIL: sbom.sarif not found" >&2; exit 1; }
[[ -f "$TMPDIR_OUT/artifacts/sbom/sbom.cdx.json" ]] || { echo "[test:sbom] FAIL: sbom.cdx.json not found" >&2; exit 1; }
"$PYTHON" "$REPO_ROOT/contracts/validate.py" "$TMPDIR_OUT/sbom.sarif" --stage sbom || { echo "[test:sbom] FAIL" >&2; exit 1; }
echo "[test:sbom] PASS"

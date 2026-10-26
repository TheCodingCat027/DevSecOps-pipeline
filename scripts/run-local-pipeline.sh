#!/usr/bin/env bash
# scripts/run-local-pipeline.sh — mirrors the CI pipeline locally
#
# Runs every ENABLED stage from stages/stages.json against the target,
# validates each output, runs the stub gate, then prints WOULD DEPLOY or DEPLOY BLOCKED.
#
# Usage:
#   bash scripts/run-local-pipeline.sh [target_path]
#   GATE_FORCE_FAIL=1 bash scripts/run-local-pipeline.sh  # always block
#
# Environment variables:
#   TARGET        — override default scan target (default: demo-app/vulnerable)
#   GATE_FORCE_FAIL=1  — force the gate to exit 1 (demo blocked-deploy path)
#   PYTHON        — python executable to use (default: python3)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STAGES_JSON="$REPO_ROOT/stages/stages.json"
VALIDATE_PY="$REPO_ROOT/contracts/validate.py"
GATE_PY="$REPO_ROOT/gate/run_gate.py"
POLICY_FILE="$REPO_ROOT/security-policy.yaml"
PYTHON="${PYTHON:-python3}"
TARGET="${1:-${TARGET:-$REPO_ROOT/demo-app/vulnerable}}"

REPORTS_DIR="$REPO_ROOT/reports"
GATE_OUT_DIR="$REPO_ROOT/gate-out"

echo "========================================================"
echo " DevSecOps Local Pipeline"
echo " Target : $TARGET"
echo " Repo   : $REPO_ROOT"
echo " Python : $PYTHON"
if [[ "${GATE_FORCE_FAIL:-}" == "1" ]]; then
    echo " Mode   : GATE_FORCE_FAIL=1 (will block deploy)"
fi
echo "========================================================"
echo ""

# Clean previous run
rm -rf "$REPORTS_DIR" "$GATE_OUT_DIR"
mkdir -p "$REPORTS_DIR"

# ── Read enabled stages from stages.json ──────────────────────────────────
ENABLED_STAGES=$("$PYTHON" -c "
import json
with open('$STAGES_JSON') as f:
    data = json.load(f)
enabled = [s['name'] for s in data['stages'] if s.get('enabled', True)]
print(' '.join(enabled))
")

echo "[pipeline] Enabled stages: $ENABLED_STAGES"
echo ""

STAGE_FAILURES=0

# ── Run each stage ────────────────────────────────────────────────────────
for STAGE in $ENABLED_STAGES; do
    STAGE_SCRIPT="$REPO_ROOT/stages/$STAGE/run.sh"

    echo "────────────────────────────────────────"
    echo " Stage: $STAGE"
    echo "────────────────────────────────────────"

    STAGE_START=$(date +%s)

    if [[ ! -f "$STAGE_SCRIPT" ]]; then
        echo "[pipeline] ERROR: $STAGE_SCRIPT not found" >&2
        STAGE_FAILURES=$((STAGE_FAILURES + 1))
        continue
    fi

    # Run the stage (exit 1 = scanner crashed, exit 2 = usage error)
    if ! bash "$STAGE_SCRIPT" "$TARGET" "$REPORTS_DIR" 2>&1; then
        echo "[pipeline] ERROR: Stage '$STAGE' exited with error" >&2
        STAGE_FAILURES=$((STAGE_FAILURES + 1))
        continue
    fi

    # Validate SARIF output
    SARIF_FILE="$REPORTS_DIR/$STAGE.sarif"
    if [[ ! -f "$SARIF_FILE" ]]; then
        echo "[pipeline] ERROR: $STAGE.sarif not written by stage" >&2
        STAGE_FAILURES=$((STAGE_FAILURES + 1))
        continue
    fi

    if ! "$PYTHON" "$VALIDATE_PY" "$SARIF_FILE" --stage "$STAGE"; then
        echo "[pipeline] ERROR: $STAGE.sarif failed validation" >&2
        STAGE_FAILURES=$((STAGE_FAILURES + 1))
        continue
    fi

    STAGE_END=$(date +%s)
    STAGE_DURATION=$((STAGE_END - STAGE_START))
    echo "[pipeline] ✓ Stage '$STAGE' completed in ${STAGE_DURATION}s"
    echo ""
done

# ── Gate ──────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════"
echo " Gate"
echo "════════════════════════════════════════"

if [[ $STAGE_FAILURES -gt 0 ]]; then
    echo "[pipeline] WARNING: $STAGE_FAILURES stage(s) failed — gate will still run on available reports"
fi

GATE_START=$(date +%s)

GATE_EXIT=0
"$PYTHON" "$GATE_PY" \
    --reports "$REPORTS_DIR" \
    --policy  "$POLICY_FILE" \
    --out     "$GATE_OUT_DIR" \
    || GATE_EXIT=$?

GATE_END=$(date +%s)
GATE_DURATION=$((GATE_END - GATE_START))

echo ""
echo "[pipeline] Gate completed in ${GATE_DURATION}s (exit code: $GATE_EXIT)"
echo ""

# ── Final verdict ─────────────────────────────────────────────────────────
echo "========================================================"
if [[ $GATE_EXIT -eq 0 && $STAGE_FAILURES -eq 0 ]]; then
    echo " ✅  WOULD DEPLOY"
    echo " Gate: PASSED | Stage failures: 0"
    exit 0
elif [[ $GATE_EXIT -eq 1 ]]; then
    echo " 🚫  DEPLOY BLOCKED"
    echo " Gate: POLICY VIOLATED"
    exit 1
elif [[ $GATE_EXIT -eq 2 ]]; then
    echo " 🚫  DEPLOY BLOCKED"
    echo " Gate: INTERNAL ERROR (invalid SARIF or policy)"
    exit 2
else
    echo " 🚫  DEPLOY BLOCKED"
    echo " Stage failures: $STAGE_FAILURES | Gate exit: $GATE_EXIT"
    exit 1
fi
echo "========================================================"

#!/usr/bin/env bash
# eval/p2-code/run_eval.sh — run the Phase 2 evaluation (see evaluate.py for what it does).
#
# Usage: eval/p2-code/run_eval.sh [evaluate.py options]
#   --warm-runs N      repetitions for the warm-cache timing (default 3, or EVAL_WARM_RUNS)
#   --cache-dir DIR    reuse an existing cache (then cold timings are not measured)
#   --no-figures       skip PNG charts
#
# Needs network access for a COLD run (it installs gitleaks, semgrep, trivy into a fresh temporary
# cache) and for Semgrep registry packs / the Trivy DB; whatever cannot run is recorded as "not run".
# Validator interpreter: $EVAL_PYTHON, else the repo's .venv (it has jsonschema), else python3.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
if [[ -z "${EVAL_PYTHON:-}" ]]; then
    if [[ -x "$REPO/.venv/bin/python" ]]; then EVAL_PYTHON="$REPO/.venv/bin/python"; else EVAL_PYTHON="python3"; fi
fi
export EVAL_PYTHON
# evaluate.py itself runs under the plain interpreter (standard library; matplotlib is used for charts if
# importable there); $EVAL_PYTHON is only used to run contracts/validate.py (needs jsonschema).
exec "${EVAL_RUNNER:-python3}" "$HERE/evaluate.py" "$@"

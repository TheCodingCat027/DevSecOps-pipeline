# DevSecOps Pipeline — Makefile
# Owner: P1
# All targets must work on Linux, macOS, and Windows (via Git Bash or WSL).
# Run 'make help' to see available targets.

.DEFAULT_GOAL := help
VENV          ?= .venv
PYTHON        ?= $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)
PYTHON_ABS    := $(shell command -v $(PYTHON))
PIP           ?= $(VENV)/bin/pip
PYTEST        ?= $(VENV)/bin/pytest

.PHONY: help setup validate test pipeline-local pipeline-local-fail lint clean

## help: Show this help message
help:
	@echo ""
	@echo "DevSecOps Pipeline — Available Make Targets"
	@echo "────────────────────────────────────────────"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""

## setup: Create a virtual environment and install contract dependencies
setup:
	@echo "[setup] Creating virtual environment..."
	$(PYTHON) -m venv $(VENV)
	@echo "[setup] Installing contract dependencies..."
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r contracts/requirements.txt
	$(VENV)/bin/pip install Flask==3.1.0  # needed for demo-app tests
	@echo "[setup] Done. Activate with: source $(VENV)/bin/activate"

## validate: Validate all SARIF samples and the baseline security policy
validate:
	@echo "[validate] Validating SARIF samples..."
	$(PYTHON) contracts/validate.py contracts/samples/
	@echo "[validate] Validating security policy..."
	$(PYTHON) contracts/validate.py security-policy.yaml --policy security-policy.yaml
	@echo "[validate] All checks passed ✓"

## test: Run all tests (contracts, demo-app, stage stub tests)
test: _test-pytest _test-stage-stubs

_test-pytest:
	@echo "[test] Running pytest (contracts + demo-app)..."
	$(PYTHON) -m pytest contracts/tests/ demo-app/tests/ gate/tests/ -v --tb=short
	cd demo-app/vulnerable && "$(PYTHON_ABS)" -m pytest tests -q
	cd demo-app/fixed && "$(PYTHON_ABS)" -m pytest tests -q

_test-stage-stubs:
	@echo "[test] Running stage stub tests..."
	@PYTHON="$(PYTHON)" bash stages/secrets/tests/run_test.sh
	@PYTHON="$(PYTHON)" bash stages/sast/tests/run_test.sh
	@PYTHON="$(PYTHON)" bash stages/sca/tests/run_test.sh
	@PYTHON="$(PYTHON)" bash stages/iac/tests/run_test.sh
	@PYTHON="$(PYTHON)" bash stages/container/tests/run_test.sh
	@PYTHON="$(PYTHON)" bash stages/sbom/tests/run_test.sh
	@PYTHON="$(PYTHON)" bash stages/dast/tests/run_test.sh
	@echo "[test] All stage stub tests passed ✓"

## pipeline-local: Run the full local pipeline (should end with WOULD DEPLOY)
pipeline-local:
	@echo "[pipeline-local] Running local pipeline against demo-app/vulnerable..."
	PYTHON="$(PYTHON)" bash scripts/run-local-pipeline.sh demo-app/vulnerable

## pipeline-local-fail: Run with GATE_FORCE_FAIL=1 (should end with DEPLOY BLOCKED)
pipeline-local-fail:
	@echo "[pipeline-local-fail] Running with GATE_FORCE_FAIL=1..."
	GATE_FORCE_FAIL=1 PYTHON="$(PYTHON)" bash scripts/run-local-pipeline.sh demo-app/vulnerable

## lint: Run shellcheck (if available) and Python syntax check
lint:
	@echo "[lint] Checking Python syntax..."
	$(PYTHON) -m compileall contracts/ gate/ -q
	@echo "[lint] Running shellcheck on bash scripts (if available)..."
	@if command -v shellcheck >/dev/null 2>&1; then \
	    shellcheck stages/*/run.sh stages/*/tests/run_test.sh scripts/run-local-pipeline.sh; \
	    echo "[lint] shellcheck passed ✓"; \
	else \
	    echo "[lint] shellcheck not installed — skipping (install from https://github.com/koalaman/shellcheck)"; \
	fi

## clean: Remove generated reports and venv
clean:
	@echo "[clean] Removing reports, gate-out, venv..."
	rm -rf reports/ gate-out/ $(VENV) .pytest_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "[clean] Done"

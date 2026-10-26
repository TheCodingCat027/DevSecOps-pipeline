# Phase 1 Implementation Report

**Project:** Automated Security Integration for CI/CD Pipelines  
**Phase:** 1 — Foundation & Contracts  
**Author:** P1  
**Date:** 2026-10-26  
**Status:** Implementation complete; pending four-member contract sign-off, first green GitHub Actions run, and real CODEOWNERS handles + branch protection

## Post-review fixes

1. Corrected the seeded V3 CVE descriptions and verified the three CVEs with pip-audit.
2. Preserved the already-correct 20-character fake AWS key and audited fixed-app requirements.
3. Made the gate return exit 2 with an error result when enabled-stage reports are missing or absent.
4. Added subprocess coverage for gate pass, forced failure, missing reports, empty reports, and invalid SARIF.
5. Made Makefile Python selection prefer an existing virtual environment and run both demo-app test suites.
6. Updated CI to run gate and demo-app tests, hardened target handling, and corrected deploy job dependencies.

---

## 1. Objective

Phase 1 established the complete structural skeleton and frozen contracts for the DevSecOps pipeline, enabling P2, P3, and P4 to build their respective phases in parallel without coordinating file edits or waiting for Phase 1 to complete.

---

## 2. Deliverables Completed

### A. Repository Scaffolding ✅
| File | Purpose |
|---|---|
| `.gitignore` | Ignores Python caches, venvs, reports, IDE files |
| `CODEOWNERS` | Maps folder ownership to P1–P4; requires all-four-approval for `contracts/` |
| `.github/pull_request_template.md` | 6-item PR review checklist |
| `docs/branch-protection.md` | Branch protection rules + `gh api` CLI commands |
| `docs/contributing.md` | Contribution guidelines and stub replacement process |
| `README.md` | Root readme with quick start, ownership table, and document index |

### B. Contracts (Frozen) ✅
All files in `contracts/` are frozen as of v1.0.0 (see `contracts/CHANGELOG.md`).

| File | Purpose |
|---|---|
| `finding.schema.json` | JSON Schema for the normalized finding object |
| `policy.schema.json` | JSON Schema for the security policy YAML |
| `sarif-profile.md` | SARIF 2.1.0 subset all stages must emit |
| `severity-map.md` | Tool-to-canonical severity normalization table (4 levels) |
| `stage-interface.md` | Universal stage CLI interface specification |
| `gate-interface.md` | Gate CLI, exit codes, and output schema specification |
| `CHANGELOG.md` | Contract version history and amendment process |
| `requirements.txt` | Pinned: `jsonschema==4.23.0`, `PyYAML==6.0.2`, `pytest==8.3.4` |
| `samples/*.sarif` (7 files) | Valid SARIF for all 7 stages (secrets, sast, sca, iac, container, sbom, dast) |
| `samples/invalid/*.sarif` (6 files) | Deliberately broken SARIF for negative testing |

### C. Validator & Tests ✅
| File | Purpose |
|---|---|
| `contracts/validate.py` | SARIF profile + finding + policy validator; `extract_findings()` API |
| `contracts/tests/test_validate.py` | 34 pytest tests covering all code paths |

**`extract_findings(sarif_dict) → list[dict]`** is the frozen public interface consumed by P4's gate normalizer.

### D. Demo Application ✅
| Path | Vulnerabilities |
|---|---|
| `demo-app/vulnerable/config.py` | V1a/V1b — Hardcoded fake AWS credentials (Gitleaks target) |
| `demo-app/vulnerable/app.py` | V2 — SQL injection (line 91); V6 — MD5 hashing (line 111); V7 — debug=True (line 137) |
| `demo-app/vulnerable/requirements.txt` | V3a/V3b/V3c — Flask 1.1.4, Jinja2 2.11.3, Werkzeug 1.0.1 (CVE targets) |
| `demo-app/vulnerable/Dockerfile` | V4 — No USER (line 14); V5 — Unpinned FROM (line 14); V8 — No HEALTHCHECK (line 14) |
| `demo-app/fixed/` | Corrected version fixing all 8 vulnerabilities; same functional test suite |

### E. Seeded Vulnerability Ground Truth ✅
| File | Purpose |
|---|---|
| `demo-app/seeded-vulnerabilities.md` | Human-readable table with exact file/line/CVE/tool for Phase 5 evaluation |
| `demo-app/seeded-vulnerabilities.json` | Machine-readable equivalent (schema_version: 1) |
| `demo-app/tests/test_seeded_vulns.py` | Drift-protection test — fails if code moves without updating ground truth |

### F. Stub Stages ✅
| Stage | Owner | Tool (Phase) | Category |
|---|---|---|---|
| `stages/secrets/` | P2 | Gitleaks v8.18.4 | secret |
| `stages/sast/` | P2 | Semgrep v1.78.0 | sast |
| `stages/sca/` | P2 | Trivy fs v0.51.4 | sca |
| `stages/iac/` | P3 | Hadolint v2.12.0 + Checkov 3.x | iac |
| `stages/container/` | P3 | Trivy image v0.51.4 | container |
| `stages/sbom/` | P3 | Syft v1.5.0 | sbom |
| `stages/dast/` | P3 | ZAP v2.15.0 (disabled) | dast |

Each stage has `run.sh`, `README.md`, and `tests/run_test.sh`.

### G. Stub Gate ✅
| File | Purpose |
|---|---|
| `gate/run_gate.py` | Validates all SARIFs + policy; counts findings; always passes (stub) |
| `gate/README.md` | Documents frozen interface, GATE_FORCE_FAIL demo, and P4 replacement guide |
| `security-policy.yaml` | Baseline policy: enforce mode, 0 secrets, 0 Criticals, 3 Highs allowed |

### H. CI/CD Workflow ✅
| File | Purpose |
|---|---|
| `.github/workflows/pipeline.yml` | 6-job workflow: contracts-and-tests → prepare → build-image → stage (matrix) → gate → deploy (mock) |
| `.github/actions/run-stage/action.yml` | Thin composite action: run stage + validate SARIF |
| `stages/stages.json` | Stage registry driving the CI matrix (owned by P1) |

### I. Developer Tools ✅
| File | Purpose |
|---|---|
| `Makefile` | Targets: setup, validate, test, pipeline-local, pipeline-local-fail, lint, clean |
| `scripts/run-local-pipeline.sh` | Mirrors CI pipeline locally; outputs WOULD DEPLOY or DEPLOY BLOCKED |

### J. Documentation ✅
| File | Purpose |
|---|---|
| `docs/p1-architecture.md` | Mermaid pipeline diagram, component table, merge-conflict-free design rationale |
| `docs/p1-assumptions.md` | 15 design decisions made during implementation |
| `docs/team-signoff.md` | Contracts freeze sign-off checklist (all 4 members must sign) |
| `docs/p2-architecture.md` | Placeholder for P2 |
| `docs/p3-architecture.md` | Placeholder for P3 |
| `docs/p4-architecture.md` | Placeholder for P4 |
| `eval/p1-performance/` `eval/p2-code/` `eval/p3-container/` `eval/p4-policy/` | Evaluation gitkeep directories |

---

## 3. Verification Results

All verification commands run on **Python 3.13.2 / Windows 11 (WSL for bash)**:

### `make validate` (SARIF samples + policy)
```
VALID:   contracts/samples/container.sarif
VALID:   contracts/samples/dast.sarif
VALID:   contracts/samples/iac.sarif
VALID:   contracts/samples/sast.sarif
VALID:   contracts/samples/sbom.sarif
VALID:   contracts/samples/sca.sarif
VALID:   contracts/samples/secrets.sarif
VALID:   security-policy.yaml
```
**Result: 7/7 samples valid, policy valid ✅**

### `make test` (pytest: contracts + demo-app + gate)
```
contracts/tests/test_validate.py   — 34 passed
demo-app/tests/test_seeded_vulns.py — 23 passed
gate/tests/test_gate_stub.py       — 5 passed
demo-app/vulnerable/tests         — 5 passed
demo-app/fixed/tests              — 5 passed
Total: 72 passed
```
**Result: 72/72 ✅**

### Stage stub tests (all 7 stages)
```
[test:secrets] PASS: stub stage output is valid
[test:sast]    PASS
[test:sca]     PASS
[test:iac]     PASS
[test:container] PASS
[test:sbom]    PASS
[test:dast]    PASS
```
**Result: 7/7 ✅**

### Local pipeline — normal run
```
[pipeline] ✓ Stage 'secrets' completed in 1s
[pipeline] ✓ Stage 'sast' completed in 1s
[pipeline] ✓ Stage 'sca' completed in 1s
[pipeline] ✓ Stage 'iac' completed in 1s
[pipeline] ✓ Stage 'container' completed in 1s
[pipeline] ✓ Stage 'sbom' completed in 1s
[gate] Decision: PASS
✅  WOULD DEPLOY
```
**Result: 6/6 stages passed, gate passed, WOULD DEPLOY ✅**

### Local pipeline — `GATE_FORCE_FAIL=1` demo
```
[gate] GATE_FORCE_FAIL=1 set — simulating policy violation
[gate] Decision: FAIL
Exit code: 1
```
**Result: Gate blocked correctly ✅**

---

## 4. Acceptance Criteria Status

| # | Criterion | Status |
|---|---|---|
| AC1 | `make validate` exits 0 for all 7 SARIF samples | ✅ |
| AC2 | `make test` exits 0 (contracts + demo-app tests) | ✅ |
| AC3 | Each `stages/*/tests/run_test.sh` exits 0 | ✅ |
| AC4 | Local pipeline exits 0 with WOULD DEPLOY | ✅ |
| AC5 | `GATE_FORCE_FAIL=1` makes gate exit 1 | ✅ |
| AC6 | 8 seeded vulnerabilities documented with exact file/line | ✅ |
| AC7 | Drift-protection test catches pattern drift | ✅ |
| AC8 | Contracts README/CHANGELOG frozen and dated | ✅ |
| AC9 | CODEOWNERS maps all folders to owners | ✅ |
| AC10 | GitHub Actions workflow YAML is valid (manually reviewed) | ✅ |

---

## 5. Known Limitations and Notes

1. **Docker builds not verified** — Docker daemon not available in scaffolding environment. Dockerfiles are correctly written and expected to build. See `docs/p1-assumptions.md` (A5).

2. **GATE_FORCE_FAIL via bash on Windows** — When calling `bash` from PowerShell, env vars set with `$env:VAR=value` are not forwarded into the bash subprocess (a PowerShell/WSL boundary quirk). Call Python directly: `GATE_FORCE_FAIL=1 python gate/run_gate.py ...` from WSL, or `$env:GATE_FORCE_FAIL="1"; python gate/run_gate.py ...` from PowerShell. The gate code itself works correctly.

3. **Fake AWS key may trigger push protection** — See `demo-app/README.md` for the bypass procedure (mark as test value in the GitHub UI).

---

## 6. What P2 Must Do Next

1. Read `contracts/stage-interface.md` completely.
2. Read `contracts/severity-map.md`.
3. Replace `stages/secrets/run.sh` with Gitleaks (4-step guide in `stages/secrets/README.md`).
4. Replace `stages/sast/run.sh` with Semgrep (4-step guide in `stages/sast/README.md`).
5. Replace `stages/sca/run.sh` with Trivy fs (4-step guide in `stages/sca/README.md`).
6. Run `validate.py --stage <name>` on each real output before merging.

## 7. What P3 Must Do Next

1. Same contract reading as P2.
2. Replace `stages/iac/run.sh` with Hadolint + Checkov.
3. Replace `stages/container/run.sh` with Trivy image (needs `IMAGE_REF`).
4. Replace `stages/sbom/run.sh` with Syft (both SARIF + CycloneDX artifact).
5. Enable DAST by setting `"enabled": true` in `stages/stages.json` and implementing `stages/dast/run.sh`.

## 8. What P4 Must Do Next

1. Read `contracts/gate-interface.md` completely.
2. Read `contracts/finding.schema.json` — this is the normalized finding format.
3. Replace the body of `gate/run_gate.py` with real policy evaluation.
4. Tune `security-policy.yaml` thresholds.
5. All sign-off members must tick their checkbox in `docs/team-signoff.md`.

---

## 9. File Count Summary

| Category | Files Created |
|---|---|
| Repository scaffolding | 7 |
| Contracts (schemas, profiles, interfaces) | 9 |
| SARIF samples | 13 (7 valid + 6 invalid) |
| Validator + tests | 2 |
| Demo app (vulnerable + fixed + tests) | 14 |
| Seeded vulnerability data + drift test | 3 |
| Stage stubs (7 stages × 3 files) | 21 |
| Gate | 2 |
| CI workflow + composite action | 2 |
| Scripts + Makefile | 2 |
| Documentation | 10 |
| **Total** | **~85** |

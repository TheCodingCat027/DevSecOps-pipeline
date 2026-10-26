# P1 Assumptions

This file records every decision made during Phase 1 that the prompt did not explicitly dictate.

---

## A1. Vulnerable App Line Numbers

**Decision:** Line numbers in `seeded-vulnerabilities.json` were verified against the actual committed files after writing them, not pre-planned.

**Reason:** Python docstrings and blank lines pushed vulnerability lines further down than the comment placeholders (e.g., V2=91 not 36). The drift-protection test `demo-app/tests/test_seeded_vulns.py` catches any future drift.

---

## A2. Flask Version for Tests

**Decision:** The demo-app tests install Flask from the fixed app's `requirements.txt` (Flask 3.1.0), not the vulnerable version (Flask 1.1.4).

**Reason:** Running tests with the vulnerable Flask 1.1.4 can conflict with modern pytest infrastructure. The tests are functional tests only — they test app behavior, not security properties. Using the secure version for tests is consistent with CI practice.

---

## A3. Category Field Used for Both `stage` and `category`

**Decision:** In `extract_findings()`, both `stage` and `category` are initially set to `properties.category` from the SARIF. The caller (gate) overrides `stage` with the actual stage name (the SARIF filename stem).

**Reason:** SARIF has no "stage" field; the stage is known from which file was generated. The gate has this context; the validator does not.

---

## A4. SBOM Stage SARIF Contains Zero Results

**Decision:** The SBOM stage's `sbom.sarif` always has zero results. The real deliverable is `artifacts/sbom/sbom.cdx.json`.

**Reason:** Syft is an inventory tool, not a vulnerability scanner. The SARIF file exists only to satisfy the pipeline interface. The validator allows zero-result SARIFs.

---

## A5. Docker Build Not Verified in Phase 1

**Decision:** The `demo-app/vulnerable/Dockerfile` and `demo-app/fixed/Dockerfile` were not Docker-built during Phase 1 scaffolding.

**Reason:** The Docker daemon was not available in the scaffolding environment. Both Dockerfiles follow documented best practices and are expected to build correctly. This is noted in `demo-app/README.md`.

---

## A6. CVE Selection for V3 (SCA Vulnerabilities)

**Decision:** Three CVEs were chosen for the SCA demonstration: CVE-2023-30861 (Flask), CVE-2024-34064 (Jinja2), CVE-2023-25577 (Werkzeug). These were verified with pip-audit (2026-10-27).

**Reason:** These are widely known, well-documented CVEs in common Flask stack packages. The specific versions (Flask 1.1.4, Jinja2 2.11.3, Werkzeug 1.0.1) are old enough to contain multiple CVEs, making them realistic SCA targets.

**Update:** The CVEs were verified with pip-audit (2026-10-27).

---

## A7. CODEOWNERS Single File (Not Duplicated in `.github/`)

**Decision:** `CODEOWNERS` is placed only at the repo root, not also at `.github/CODEOWNERS`.

**Reason:** GitHub accepts CODEOWNERS in either location, but the prompt says "keep one source of truth." The repo root location is used, which GitHub supports for all repo types.

---

## A8. Fake AWS Key Value

**Decision:** Used `AKIAIOSFODNN7FAKEKEY` (from AWS documentation examples) and a similarly fake secret key. Added extensive comments marking them as fake.

**Reason:** Using the AWS documentation example key is a well-established practice for test/demo credentials. It is immediately recognizable as fake by any developer familiar with AWS.

---

## A9. Python Package `contracts/__init__.py`

**Decision:** Added `contracts/__init__.py` to make `contracts/` a Python package.

**Reason:** The gate imports `from contracts.validate import extract_findings`. Without `__init__.py`, this import fails. The `__init__.py` is not mentioned in the prompt but is necessary for the frozen module API to work.

---

## A10. Stage Test for SBOM Validates CycloneDX Artifact

**Decision:** `stages/sbom/tests/run_test.sh` asserts both `sbom.sarif` and `artifacts/sbom/sbom.cdx.json` exist.

**Reason:** The SBOM stage's primary value is the CycloneDX JSON. Validating only the SARIF would miss the actual deliverable.

---

## A11. Demo App Tests Use In-Memory / Tmp SQLite

**Decision:** App tests create a temporary SQLite database per test run and seed it manually, rather than using a shared database.

**Reason:** Test isolation — each test starts with a clean database state. This is standard practice and avoids test order dependencies.

---

## A12. Makefile Uses System Python (`python3`) by Default

**Decision:** The Makefile defaults to `python3` (overridable with `PYTHON=python`), not a venv path.

**Reason:** `make test` may be run outside a venv (e.g. in CI where Python is already installed). The `PYTHON` variable allows the venv python to be injected: `PYTHON=.venv/bin/python make test`.

---

## A13. No Additional Top-Level Folders

**Decision:** No top-level folders beyond those in section 3 of the prompt were created.

**Reason:** The prompt explicitly prohibits this without recording it here. All generated files fit within the specified structure.

---

## A14. Stage Tests Run Dast Stub Even Though It's Disabled

**Decision:** `make test` runs `stages/dast/tests/run_test.sh` even though `dast` is `enabled: false` in `stages.json`.

**Reason:** The test is for the stub's correctness, not the CI enablement. Keeping it always-run ensures the stub stays valid even while disabled.

---

## A15. `conftest.py` Not Added

**Decision:** No `conftest.py` was added to the test directories.

**Reason:** All pytest tests work without a conftest (they use `sys.path.insert` for imports). Adding conftest would require additional explanation and is not necessary for Phase 1.

# P2 → P1: requests for changes outside P2's folders

P2 may not edit `.github/`, `Makefile`, `demo-app/`, `contracts/` or `scripts/`. Each item below is a concrete request.
Status of every item: **open (needs a P1 decision)**.

## R1. Seed list is missing the hard-coded `SECRET_KEY` (demo-app)

* **What:** `demo-app/vulnerable/app.py:22` and `demo-app/vulnerable/config.py:24` contain a literal Flask `SECRET_KEY`.
  `demo-app/fixed/config.py:19-21` replaces it with `os.environ['SECRET_KEY']`, so Phase 1 treats it as a flaw, but
  `seeded-vulnerabilities.json` does not list it.
* **Effect:** the `secrets` stage (custom rule `flask-hardcoded-secret-key`) reports both occurrences. They are counted as
  "findings matching no seeded flaw" in `eval/p2-code/triage.md` (PROPOSED verdict: true positive not in seed list).
* **Proposed:** add a seeded entry (class `secret`, files `app.py` and `config.py`, expected rule id
  `flask-hardcoded-secret-key`), or state in `seeded-vulnerabilities.md` that it is intentionally out of scope.

## R2. V3 CVE ids are unverified against Trivy (demo-app, evidence needed)

* **What:** `seeded-vulnerabilities.json` lists CVE-2023-30861 (Flask 1.1.4), CVE-2024-34064 (Jinja2 2.11.3) and
  CVE-2023-25577 (Werkzeug 1.0.1), verified with `pip-audit`. P2 could **not** check that Trivy reports the same ids:
  `ghcr.io` / `mirror.gcr.io` (Trivy DB hosts) are unreachable from the build sandbox.
* **Proposed:** someone with network access runs `bash eval/p2-code/run_eval.sh` (or `SCA_DB_REPOSITORY=<mirror>`)
  and records any mismatch here. Trivy and pip-audit can legitimately differ (different advisory sources and ids, e.g.
  GHSA vs CVE). `demo-app/` stays untouched until then.

## R3. `make test` fails when `PYTHON` is a relative path (Makefile)

* **What:** `_test-pytest` runs `cd demo-app/vulnerable && "$(VENV)/bin/python" ...`; with the default relative
  `VENV=.venv` the path no longer exists after the `cd` (`.venv/bin/python: not found`, exit 127).
* **Workaround used by P2:** `make test PYTHON="$PWD/.venv/bin/python"` (also for `pipeline-local*`).
* **Proposed diff:** use the already-defined `$(PYTHON_ABS)` in that recipe instead of `$(VENV)/bin/python`.

## R4. CI: cache the tools and fetch full history (`.github/`)

* Cache `~/.cache/devsecops/gitleaks-8.30.1`, `~/.cache/devsecops/semgrep-1.182.1` (venv) and
  `~/.cache/devsecops/trivy-0.76.1` (binary) and `~/.cache/devsecops/trivy-db` (vulnerability DB), keyed on the versions.
* Use `fetch-depth: 0` for the `secrets` job; with the default shallow clone the history scan sees one commit.
* Give the `sast` and `sca` jobs outbound access to `semgrep.dev` and to the Trivy DB registries
  (`mirror.gcr.io`, `ghcr.io`), or provide a mirror through `SCA_DB_REPOSITORY`. Without them both stages exit 1 by design (fail closed).

## R5. CI: run the stage tests

* `stages/*/tests/run_test.sh` are only run by `make test`; add them to the workflow (with `STAGE_TEST_STRICT=1` so
  `SKIPPED (tool unavailable)` becomes a failure rather than a silent pass).

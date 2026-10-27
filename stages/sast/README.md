# SAST Stage

**Owner:** P2  
**Status:** Real scanner (Phase 2)
**Tool:** **semgrep 1.182.1** (pinned, open-source CLI) — <https://semgrep.dev>
**Interface:** [`contracts/stage-interface.md`](../../contracts/stage-interface.md)
**Seeded flaws covered:** V2 (SQL injection), V6 (MD5 password hashing), V7 (`debug=True`) in `demo-app/vulnerable/app.py`

## Purpose

Static Application Security Testing: finds insecure code patterns in source files and reports them as contract-valid SARIF (`category: sast`).

```
stages/sast/run.sh <target_path> <output_dir>
  -> <output_dir>/sast.sarif   (only when the scan completed; zero findings = valid empty report)
  -> exit 0  scan completed (findings are data, not errors)
  -> exit 1  scanner failed / timed out / bad rules / rule registry unavailable (no SARIF is left behind)
  -> exit 2  usage error (wrong argument count, missing target, invalid knob value)
```

## Files

| File | Role |
|---|---|
| `run.sh` | Orchestrates: install → Semgrep scan → convert → atomic write. Fail-closed. |
| `install.sh` | Creates a private virtual environment in the cache and installs the pinned Semgrep. Idempotent. |
| `to_sarif.py` | Semgrep JSON → SARIF (severity mapping, CWE extraction, path normalisation, dedup, ordering). Standard library only. |
| `rules/*.yaml` | Three custom rules (always applied unless `SAST_CUSTOM_RULES=0`). |
| `rules/tests/*.py` | Semgrep rule tests (`# ruleid:` / `# ok:` annotations). |
| `tests/run_test.sh` | Integration tests (run by `make test`). |

## Rule sources

1. **Custom local rules** (`rules/*.yaml`) — every rule carries `metadata.cwe`, `owasp`, `confidence` and a human-readable `remediation` (mapped to `properties.fix`).

   | Rule id | Flaw | Severity (Semgrep → pipeline) | CWE | Notes |
   |---|---|---|---|---|
   | `devsecops-python-sql-injection-string-built-query` | V2 | ERROR → High | CWE-89 | Taint-mode: a query built by `+`, f-string, `.format()` or `%` reaches `.execute/.executemany/.executescript` (sqlite3 and generic DB-API). Parameterized queries (`?` / `%s` + tuple) are never sources, so the fixed app is not flagged. |
   | `devsecops-python-weak-hash-for-password` | V6 | ERROR → High | CWE-327 | `hashlib.md5/sha1` (and `hashlib.new("md5"|"sha1")`) applied to an expression whose text contains `passw`, `passwd`, `pwd` or `passphrase`. Non-password uses (ETags, checksums) are tested negatives. |
   | `devsecops-flask-debug-enabled` | V7 | WARNING → Medium | CWE-94 | `app.run(..., debug=True)` or `app.debug = True` with the literal `True` (CWE-94 matches the seeded ground truth). Reading the flag from the environment is a tested negative. |

2. **Registry packs** — default `p/python p/flask p/owasp-top-ten`, overridable with `SAST_REGISTRY_PACKS` (an **empty** value disables them).
   - They need to download rules from `https://semgrep.dev`.
   - **Fail closed:** if the registry is unreachable (or Semgrep fails while loading it) the stage **exits 1** and leaves no SARIF. Silently dropping 100s of community rules would look like "fewer findings".
   - **Opt-in offline mode:** `SAST_ALLOW_OFFLINE=1` continues with the **local rules only**, prints a loud `WARNING … LOCAL RULES ONLY` to stderr, and records `registry_packs_applied: false` in the SARIF `runs[0].properties` so the degraded coverage is visible downstream. Trade-off: availability vs. coverage — use it only where a degraded scan is acceptable (air-gapped development); CI should run the strict default.
3. `SAST_CUSTOM_RULES=0|1` (default `1`) switches the custom rules off, for the registry-only vs tuned comparison in `eval/p2-code/`.

## Severity, CWE, other fields

* Severity follows `contracts/severity-map.md`: `ERROR → High`, `WARNING → Medium`, `INFO → Low`, anything else → `Low`. The original label is kept in `properties.raw_severity`.
* `properties.cwe`: first `CWE-<n>` found in `metadata.cwe`, else in `metadata.tags`.
* `properties.fix` ← `metadata.remediation` (or Semgrep's autofix text); `properties.confidence` ← `metadata.confidence` (lower-cased); `properties.help_uri` ← first http(s) reference.
* `uri` is **repo-relative** (relative to the target when the target is outside the repository); `region.startLine` is set.
* Results are de-duplicated on (rule, file, line) and sorted by (file, line, rule) → byte-identical output for identical input.
* `runs[0].properties` records `custom_rules_enabled`, `registry_packs_requested`, `registry_packs_applied`, `scan_errors`.

## Noise control

Excluded from the scan: `tests`, `test`, `__tests__`, `test_*.py`, `*_test.py`, `conftest.py`, `node_modules`, `.git`, `venv`, `.venv`, `__pycache__`, `site-packages`, `dist`, `build`, `*.min.js`. Inline `# nosem` suppression comments are **ignored** (`--disable-nosem`) — suppression belongs to the gate (waivers in `security-policy.yaml`). Semgrep scans files on disk, not only git-tracked ones (`--no-git-ignore`).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `STAGE_TIMEOUT` | `600` | Wall-clock limit (seconds) for one Semgrep run; exceeding it → exit 1. |
| `SAST_CUSTOM_RULES` | `1` | `0` disables the local rules. Anything but `0`/`1` → exit 2. |
| `SAST_REGISTRY_PACKS` | `p/python p/flask p/owasp-top-ten` | Space-separated registry configs; empty = none. With `SAST_CUSTOM_RULES=0` and no packs → exit 2. |
| `SAST_ALLOW_OFFLINE` | `0` | `1` = fall back to local rules only when the registry fails (warns, recorded in SARIF). |
| `SAST_REGISTRY_URL` | `https://semgrep.dev` | Host used only for the fast reachability probe (tests point it at a closed port). |
| `SAST_RULES_DIR` | `<stage>/rules` | Alternative custom-rule directory (tests). |
| `SEMGREP_BIN` | – | Use this executable instead of installing (tests / air-gapped). |
| `SEMGREP_PYTHON` | `python3` | Interpreter used to create the venv (≥ 3.9). |
| `PYTHON` | `python3` | Interpreter for `to_sarif.py` (3.11+, stdlib only). |
| `PIP_INDEX_URL`, `PIP_CERT`, … | – | Honoured by pip during install (internal mirror). |
| `XDG_CACHE_HOME` | `$HOME/.cache` | Relocates the cache. |

Semgrep's own state is redirected into the run's private temp directory (`SEMGREP_SETTINGS_FILE`, `SEMGREP_VERSION_CACHE_PATH`, `SEMGREP_LOG_FILE`); metrics and version checks are disabled; no login is needed. Nothing is written into the target.

## Install and cache

`install.sh` creates a virtual environment and installs `semgrep==1.182.1` with pip:

```
${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/semgrep-1.182.1/        <- cache this directory in CI
    venv/bin/semgrep
    .install-ok                                                    (marker written after a verified install)
```

Cold install ≈ 20 s on a fast link; warm start is a version check. Semgrep is installed from PyPI (pip verifies package hashes via the index, but there is no separate hash pin); pin the whole venv by caching on the version-keyed directory name.

## How to run

```bash
bash stages/sast/run.sh demo-app/vulnerable /tmp/out        # strict (needs semgrep.dev)
SAST_ALLOW_OFFLINE=1 bash stages/sast/run.sh demo-app/vulnerable /tmp/out   # local rules only if registry is down
SAST_REGISTRY_PACKS= bash stages/sast/run.sh demo-app/vulnerable /tmp/out    # local rules only, deliberately
python contracts/validate.py /tmp/out/sast.sarif --stage sast
```

## How to test

```bash
bash stages/sast/tests/run_test.sh          # also run by `make test`
semgrep --test --config stages/sast/rules stages/sast/rules/tests   # rule tests only
```

The integration test is hermetic (never contacts the registry). It covers: rule tests with ≥ 2 positive and ≥ 2 negative cases per rule; usage errors (exit 2); a generated known-bad fixture (exactly 3 findings, expected rule ids/severities/CWEs, test directory excluded); a clean fixture (0 findings); fail-closed cases (invalid rules, crash, timeout, unparsable output, missing binary, unreachable registry — all exit 1 with no SARIF, stale SARIF removed); the offline fallback; byte-identical repeat runs; target tree unmodified; V2/V6/V7 detected on `demo-app/vulnerable` (±2 lines); zero findings on `demo-app/fixed`. If Semgrep cannot be installed it prints `SKIPPED (tool unavailable): <reason>` (exit 0; exit 77 with `STAGE_TEST_STRICT=1`).

## Known limitations

* **Registry packs were not exercised during development** (semgrep.dev is blocked in the build sandbox). Only the local rules have been measured; the combined local + registry numbers must be produced by re-running `eval/p2-code/run_eval.sh` in an environment with access.
* Pattern-based: no cross-file data flow; a query built in one function and executed in another is missed. The SQL rule tracks taint within a function.
* The weak-hash rule is a heuristic on the argument expression text (`passw…`, `pwd`, `passphrase`); a password passed through an oddly named variable is missed.
* Only Python is covered by the custom rules.
* Findings in excluded directories (tests, vendored code) are never reported.

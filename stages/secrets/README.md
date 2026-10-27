# Secrets Stage

**Owner:** P2  
**Status:** Real scanner (Phase 2)
**Tool:** **gitleaks 8.30.1** (pinned) — <https://github.com/gitleaks/gitleaks>
**Interface:** [`contracts/stage-interface.md`](../../contracts/stage-interface.md)
**Seeded flaw covered:** V1 (hard-coded fake AWS credentials, `demo-app/vulnerable/config.py`)

## Purpose

Detects hard-coded credentials in (a) the **working tree** of the target and (b) its **git history**, and reports them as contract-valid SARIF (`category: secret`). Secret values are never written to the report.

```
stages/secrets/run.sh <target_path> <output_dir>
  -> <output_dir>/secrets.sarif   (only when the scan completed; zero findings = valid empty report)
  -> exit 0  scan completed (findings are data, not errors)
  -> exit 1  scanner failed / timed out / bad config / tool unavailable (no SARIF is left behind)
  -> exit 2  usage error (wrong argument count, missing target)
```

## Files

| File | Role |
|---|---|
| `run.sh` | Orchestrates: install → working-tree scan → history scan → convert → atomic write. Fail-closed. |
| `install.sh` | Installs the pinned, checksum-verified binary into the cache; prints its path. Idempotent. |
| `gitleaks.toml` | Default ruleset + 2 custom rules + justified allowlist. |
| `to_sarif.py` | Raw Gitleaks JSON → SARIF (severity mapping, redaction, path normalisation, dedup). Standard library only. |
| `tests/run_test.sh` | Integration tests (run by `make test`). |

## How it works

1. `install.sh` provides gitleaks **8.30.1** (see *Install and cache*).
2. **Working-tree scan:** `gitleaks dir <target>` — does not need git, so it also works on an exported/unpacked source tree.
3. **History scan** (only if the target is inside a git repository with commits): `gitleaks git <repo-top> --log-opts="--all -- <target-relative-path>"`.
   *Observed behaviour of gitleaks 8.30.1:* without a pathspec, `gitleaks git <subdir>` scans **every path of every ref of the enclosing repository** (running it on `demo-app/vulnerable` also reported findings in `docs/` and `demo-app/tests/`). The stage therefore passes a pathspec so only history *under the target* is scanned, and `to_sarif.py` additionally drops any finding outside the target (defence in depth). `--all` is deliberate: secrets on any branch/tag count.
4. Both reports stay in a private temp directory (removed by `trap`). `to_sarif.py` merges them, **deduplicates by (rule, file, line)** (a working-tree hit wins), and marks history-only hits: *"… found in commit history only at file:line (first commit abc12345, N commit(s)) …"*.
5. The SARIF is written atomically (temp file in the output directory, then `os.replace`).

### Redaction — secrets never reach a report
* gitleaks runs with `--redact` (values masked even in the raw JSON).
* `to_sarif.py` copies **only** rule id, file, line and an 8-char commit id. `Secret`, `Match`, `Line`, author, e-mail and commit message are never read into the output.
* `--ignore-gitleaks-allow` and an empty `.gitleaksignore` directory (`-i`) are used so a scanned repository cannot silence findings itself; suppression is the gate's job (waivers in `security-policy.yaml`).
* The test suite searches every generated SARIF, stdout and stderr for the fake key material.

## Severity and confidence

Gitleaks has no severity field, so per `contracts/severity-map.md`:

| Rule id | Severity |
|---|---|
| `aws-access-token`, `aws-secret-access-key` (custom), `aws-amazon-bedrock-api-key-long-lived`, `aws-amazon-bedrock-api-key-short-lived`, `gcp-api-key`, `azure-ad-client-secret` | **Critical** (cloud-provider credential — explicit list `CLOUD_PROVIDER_RULES` in `to_sarif.py`) |
| every other rule (incl. `flask-hardcoded-secret-key`, `generic-api-key`, …) | **High** |

* `properties.raw_severity` = the rule id (Gitleaks has no native severity; this matches `contracts/samples/secrets.sarif`).
* `properties.confidence`: `medium` for `generic-*` rules and `flask-hardcoded-secret-key` (heuristic / low-entropy patterns), `high` otherwise. *This is a heuristic chosen by P2, not a Gitleaks value.*
* `properties.fix` is always set (rotate, purge from history, load from a secrets manager); `region.startLine` is set.
* Other cloud providers (e.g. Alibaba, DigitalOcean) are deliberately **High**: the contract names AWS/GCP/Azure. Extend `CLOUD_PROVIDER_RULES` through a normal PR if the team wants more.

## Configuration: `gitleaks.toml`

`useDefault = true` keeps the full upstream default ruleset (222 rule ids in 8.30.1, counted from the config embedded in the binary). The file is passed with `-c`, so a `.gitleaks.toml` inside the scanned repo can never replace it (the repo-root `.gitleaks.toml` of this project allowlists the demo secrets for *repository hygiene*; it must not influence the pipeline scan).

### Custom rules (each fills a gap found by testing the defaults on `demo-app/vulnerable`)

Result of the **default** ruleset on `demo-app/vulnerable` (working tree): 1 finding — `aws-access-token` at `config.py:17` (V1a). V1b and the hard-coded `SECRET_KEY` values were **not** detected.

| Custom rule | Gap it fills | False-positive risk |
|---|---|---|
| `aws-secret-access-key` | Gitleaks 8.30.1 has no rule for the AWS *secret* access key, and `generic-api-key` does not fire on the seeded value (V1b). | Low: anchored on the variable name (`aws_secret_access_key`, `AWS-SECRET`, …), value ≥ 40 base64 chars, entropy ≥ 3.5. The seeded fake value has 42 characters, so a strict `{40}` match would have missed it. Placeholders such as `your-aws-secret-access-key` do not match (hyphens, length). |
| `flask-hardcoded-secret-key` | A hard-coded `SECRET_KEY = "…"` (config.py:24, app.py:22) is a real secret (session forgery) but has low entropy, so no default rule fires. | Medium: any quoted literal ≥ 8 chars assigned to `SECRET_KEY` matches, including dev placeholders. Mitigated by the rule-scoped test-code allowlist; `os.environ[...]` lookups never match. These two hits are *true positives that are not in the seeded list* (see `eval/p2-code/triage.md`). |

### Allowlist (every entry justified; none can touch V1)

| Entry | Why it is safe |
|---|---|
| `\.env.(example\|sample\|template)` | Committed placeholder templates that exist so that real values are **not** committed (e.g. `demo-app/fixed/.env.example`). |
| `fixtures?/` directories | Conventional location of deliberately fake data. |
| `.git/`, `node_modules/`, `.venv/`, `venv/`, `__pycache__/`, `*.pyc`/`*.pyo` | Not source: VCS internals, vendored packages, bytecode. (Without this, a working-tree scan of the repo root reported a hit inside a `.pyc` file.) |
| *rule-scoped to `flask-hardcoded-secret-key` only:* `tests?/`, `test_*.py`, `*_test.py`, `conftest.py` | Test code sets throw-away session keys. **Before** this entry the custom rule produced 3 false positives on `demo-app/fixed/tests/test_app.py`; **after**, 0. It does not apply to any other rule, so AWS keys in tests are still found. |

`demo-app/vulnerable/config.py` and `app.py` are **not** allowlisted. `tests/run_test.sh` proves it: every seeded secret in `seeded-vulnerabilities.json` must still be detected (±2 lines).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `STAGE_TIMEOUT` | `600` | Seconds allowed **per gitleaks invocation**; on expiry the stage exits 1 and leaves no SARIF. |
| `SECRETS_SCAN_HISTORY` | `1` | `0` = working tree only. |
| `SECRETS_CONFIG` | `stages/secrets/gitleaks.toml` | Alternative config (used by the evaluation for the "default config" run, and by tests). |
| `GITLEAKS_BIN` | *(unset)* | Use this binary instead of the pinned install (tests / air-gapped). |
| `GITLEAKS_DOWNLOAD_BASE` | official GitHub release URL | Mirror for the release assets. |
| `GITLEAKS_VERIFY_OFFICIAL` | `1` | Also cross-check the archive against the release's official checksums file (the pinned SHA-256 in `install.sh` is always enforced). |
| `PYTHON` | `python3` | Interpreter for `to_sarif.py` (3.11+, standard library only). |
| `XDG_CACHE_HOME` | `$HOME/.cache` | Cache location. |

## Install and cache

`install.sh` downloads `gitleaks_8.30.1_<os>_<arch>.tar.gz` (linux/darwin, x64/arm64), verifies its **SHA-256** against the value pinned in the script (copied from the project's official `gitleaks_8.30.1_checksums.txt`) and against the official checksums file, then installs atomically into:

```
${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/gitleaks-8.30.1/gitleaks
```

For CI caching (request for P1, see `docs/p2-requests-to-p1.md`): cache `~/.cache/devsecops/gitleaks-8.30.1` keyed on `8.30.1`.

## Running and testing

```bash
bash stages/secrets/run.sh demo-app/vulnerable /tmp/out
python contracts/validate.py /tmp/out/secrets.sarif --stage secrets

bash stages/secrets/tests/run_test.sh        # also run by `make test`
```

The test builds its known-bad fixture in a temp directory at run time from fragments (no complete secret-looking string is committed). It covers: usage errors (exit 2), known-bad fixture (exact count + rule ids + severities), clean fixture, history-only finding, SARIF validity, redaction, determinism, fail-closed (invalid config, crashing binary, timeout, missing binary → exit 1 and **no** SARIF, stale SARIF removed), target tree unmodified, V1 still detected on the demo app, relative/absolute/repo-root paths, fixed app clean.
If gitleaks cannot be installed the test prints `SKIPPED (tool unavailable): <reason>` and exits 0 (so offline `make test` still works); `STAGE_TEST_STRICT=1` turns that into exit 77.

## Known limitations

* Regex + entropy detection: it cannot find secrets that look like ordinary text, and entropy thresholds can miss short or structured secrets. Gitleaks has no notion of whether a credential is still valid.
* **History depth:** CI's default `actions/checkout` is a shallow clone (depth 1), so in CI the history scan sees one commit. A full-history scan needs `fetch-depth: 0` (request for P1).
* The working-tree scan also reads untracked/ignored files (e.g. a local `.env`) — intended, but it means a developer machine can report more than CI.
* Files above gitleaks' default decode limits, binary files and archives are not unpacked (`--max-archive-depth` left at 0).
* Findings are keyed by (rule, file, line); the same secret re-appearing at a different line in history is reported separately.
* `raw_severity` is the rule id because Gitleaks has no severity concept.
* Target paths containing whitespace fall back to a full-history scan that is filtered afterwards.

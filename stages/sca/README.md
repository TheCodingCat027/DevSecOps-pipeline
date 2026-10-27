# SCA Stage

**Owner:** P2  
**Status:** Real scanner (Phase 2). **Detection against the live vulnerability database has not been verified yet** — see *Verification status*.
**Tool:** **trivy 0.76.1** (pinned, filesystem mode, vulnerability scanner only) — <https://trivy.dev>
**Interface:** [`contracts/stage-interface.md`](../../contracts/stage-interface.md)
**Seeded flaw covered:** V3a–c (Flask 1.1.4, Jinja2 2.11.3, Werkzeug 1.0.1 in `demo-app/vulnerable/requirements.txt`)

## Purpose

Software Composition Analysis: finds known-vulnerable third-party packages declared in dependency manifests (`requirements.txt`, lock files, …) and reports them as contract-valid SARIF (`category: sca`).

```
stages/sca/run.sh <target_path> <output_dir>
  -> <output_dir>/sca.sarif   (only when the scan completed; zero findings = valid empty report)
  -> exit 0  scan completed (findings are data, not errors; a tree with no manifests is a valid empty scan)
  -> exit 1  scanner failed / timed out / no usable vulnerability DB / unparsable output (no SARIF is left behind)
  -> exit 2  usage error (wrong argument count, missing target, invalid knob value)
```

## Files

| File | Role |
|---|---|
| `run.sh` | Orchestrates: install → DB update (retries) → `trivy fs` → convert → atomic write. Fail-closed. |
| `install.sh` | Installs the pinned, checksum-verified binary into the cache; prints its path. Idempotent. |
| `to_sarif.py` | Trivy JSON → SARIF (severity mapping, optional properties, line lookup, dedup, ordering). Standard library only. |
| `tests/run_test.sh` | Integration tests (run by `make test`). |
| `tests/fake-trivy.sh` | Test double that replays canned JSON (never used by the pipeline). |
| `tests/fixtures/` | Canned Trivy reports (one real upstream golden file, the rest synthetic) — provenance in `tests/fixtures/README.md`. |

## How it works

1. `install.sh` provides trivy **0.76.1** (see *Install and cache*).
2. **Vulnerability DB.** Trivy downloads its database from an OCI registry (`mirror.gcr.io/aquasec/trivy-db:2`, then `ghcr.io/…`). `run.sh` runs `trivy fs --download-db-only` first:
   * a DB already in the cache and still inside its update window is reused without network access (Trivy decides);
   * a failed download is retried `SCA_DB_RETRIES` times (default 3, `SCA_DB_RETRY_DELAY` seconds apart);
   * if every attempt fails, a cached DB no older than `SCA_DB_MAX_AGE_DAYS` (default 7) is used with a warning on stderr; **otherwise the stage exits 1** (fail closed). An empty cache and no network never produces an "empty but valid" report;
   * rate limits or blocked registries: point `SCA_DB_REPOSITORY` at a mirror (comma-separated list of OCI repositories, e.g. an internal registry holding a copy of `trivy-db`).
3. **Scan:** `trivy fs --scanners vuln --format json --skip-db-update --exit-code 0 <target>` from an empty private working directory, with `--config` and `--ignorefile` pointing at empty files, so no `trivy.yaml`/`.trivyignore` of the scanned project can suppress findings (suppression is the gate's job). Secret and misconfiguration scanners are **off** (they belong to the `secrets` stage and P3's `iac` stage). Skipped directories: `**/node_modules`, `**/.git`, `**/venv`, `**/.venv`, `**/__pycache__`, `**/site-packages`.
4. `to_sarif.py` converts Trivy's **JSON** (not Trivy's built-in SARIF) because the JSON carries the structured fields the contract needs.
5. The SARIF is written atomically (temp file in the output directory, then `os.replace`).

## Mapping (Trivy JSON → SARIF)

| SARIF | Source |
|---|---|
| `ruleId` | `VulnerabilityID` (CVE-… or GHSA-…) |
| `properties.severity` | per `contracts/severity-map.md`: `CRITICAL/HIGH/MEDIUM/LOW → Critical/High/Medium/Low`, `UNKNOWN` and any unrecognised label → `Low` |
| `properties.raw_severity` | `Severity` as reported |
| `level` | Critical/High → `error`, Medium → `warning`, Low → `note` |
| `properties.cve_id` | the id if it matches `CVE-YYYY-NNNN+`, else a CVE found in `VendorIDs`, else omitted (e.g. GHSA-only advisories) |
| `properties.package`, `installed_version` | `PkgName`, `InstalledVersion` |
| `properties.fixed_version`, `fix_available` | `FixedVersion` (several versions stay as `"2.2.5, 2.3.2"`); `fix_available` is true when any fixed version exists |
| `properties.fix` | `Upgrade <pkg> from <installed> to <fixed> or later.` (one fixed version), `… to a fixed release (a, b).` (several), or `No fixed version available yet (status: <Status>).` |
| `properties.cwe` | first `CweIDs` entry matching `CWE-<n>` |
| `properties.help_uri` | `PrimaryURL` (else first http(s) reference) |
| `uri` | manifest path (`Target`) made **repo-relative** (relative to the target when the target is outside the repository) |
| `region.startLine` | Trivy's `Packages[].Locations[0].StartLine` when present; else the first non-comment line of the manifest naming the package (case/`-_.`-insensitive; a line that also contains the installed version wins); else the result has no region (file level, `line` = 0 after normalisation) |
| `message.text` | `<pkg> <installed> is affected by <id>: <Title>` |
| `runs[0].properties` | `scanned_manifests`, `db_updated_at`, `db_schema_version` (provenance of the DB used) |

De-duplication key: (manifest file, package, installed version, vulnerability id). The same CVE in two different manifests is two findings (the fix has to be applied in both). Results are sorted by (file, line, package, rule).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `STAGE_TIMEOUT` | `600` | Wall-clock limit (seconds) for each Trivy invocation (each DB attempt and the scan); exceeding it → exit 1. |
| `SCA_DB_RETRIES` | `3` | DB download attempts (≥ 1). |
| `SCA_DB_RETRY_DELAY` | `10` | Seconds between DB attempts. |
| `SCA_DB_MAX_AGE_DAYS` | `7` | Oldest cached DB accepted when the update fails. |
| `SCA_DB_REPOSITORY` | – | Comma-separated OCI repositories for the DB (mirror). Default: Trivy's own list. |
| `SCA_CACHE_DIR` | `${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-db` | Trivy cache (DB + analysis cache). Must not be inside the target. |
| `TRIVY_BIN` | – | Use this executable instead of installing (tests / air-gapped). |
| `TRIVY_DOWNLOAD_BASE` | official GitHub release | Mirror for the binary archive. |
| `TRIVY_VERIFY_OFFICIAL` | `1` | Also cross-check the archive against the official checksums file (the pinned checksum is always enforced). |
| `PYTHON` | `python3` | Interpreter for `to_sarif.py` (3.11+, stdlib only). |
| `XDG_CACHE_HOME` | `$HOME/.cache` | Relocates the caches. |

Telemetry is disabled (`--disable-telemetry`, `TRIVY_DISABLE_TELEMETRY`), the version-update notice is suppressed, and nothing is written into the target.

## Install and cache

```
${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-0.76.1/trivy      <- binary (cache key: version)
${XDG_CACHE_HOME:-$HOME/.cache}/devsecops/trivy-db/               <- vulnerability DB + analysis cache (cache key: date; refreshed by Trivy)
```

Both directories can be cached in CI. The binary archive's SHA-256 is pinned in `install.sh` (copied from the project's official `trivy_0.76.1_checksums.txt`) **and** cross-checked against that file when reachable. Cold install ≈ 6 s; the first DB download is a one-off of tens of MB.

## How to run

```bash
bash stages/sca/run.sh demo-app/vulnerable /tmp/out
SCA_DB_REPOSITORY=registry.example.org/mirror/trivy-db:2 bash stages/sca/run.sh demo-app/vulnerable /tmp/out
python contracts/validate.py /tmp/out/sca.sarif --stage sca
```

## How to test

```bash
bash stages/sca/tests/run_test.sh      # also run by `make test`
```

Layer A (always): usage errors; the **real** binary with no reachable DB exits 1 and leaves no SARIF; DB retries are bounded. Layer B (test double + canned reports): mapping, optional properties, line lookup, de-duplication, ordering, determinism, clean tree, no-manifest tree, every fail-closed case (crash, timeout, garbage output, foreign JSON, missing binary, DB failure, stale cache), cache inside the target refused, target tree unmodified. Layer C (real scanner, real DB): asserts V3a–c on `demo-app/vulnerable`; when the DB is unreachable it prints `NOT RUN (vulnerability DB unavailable): …` and the script ends with `PASS (layers A+B) — layer C NOT RUN` (exit 77 under `STAGE_TEST_STRICT=1`, which CI should set).

## Verification status

* Verified in the build sandbox: binary install and checksum, real-binary failure without DB (fail closed), converter on **real upstream Trivy output** (`tests/fixtures/upstream-pip.json`), all stage logic through the test double.
* **Not verified:** detection of the V3 CVEs by a real Trivy against the live DB. The sandbox cannot reach `mirror.gcr.io` / `ghcr.io`. Before relying on V3 detection, run `bash stages/sca/tests/run_test.sh` and `eval/p2-code/run_eval.sh` somewhere with access. Open question for that run: whether the three CVE ids in `demo-app/seeded-vulnerabilities.json` are the ones Trivy reports for these exact versions (record any mismatch in `docs/p2-requests-to-p1.md`; do not edit `demo-app/`).

## Known limitations

* Needs network access to an OCI registry for the vulnerability DB (first run, and whenever the cached DB expires).
* Only dependencies **declared with a resolvable version** in a supported manifest are seen. Unpinned requirements (`flask>=1`) and dependencies fetched at build time are invisible; vendored copies and transitive dependencies are only seen through lock files.
* No reachability analysis: a vulnerable package is reported even if the vulnerable function is never called.
* Java archives (`.jar`) make Trivy download its Java index DB lazily; that DB comes from the same registry and is subject to the same fail-closed behaviour.
* The reported severity is Trivy's selected source (usually GitHub Advisory/NVD); it can differ from other tools' scores.

# Phase 2 evaluation results (code-level stages)

Generated 2026-10-27T05:21:43Z from commit `4c065d0` by `eval/p2-code/evaluate.py`. Every number below is read from `results.json`; nothing is estimated. A configuration marked **not run** exited non-zero in this environment; the reason is quoted from the stage's own stderr.

## Matching rules

* Evaluated flaws: every entry of `seeded-vulnerabilities.json` whose class is secret, sast or sca (8 flaws).
* secret / sast: same file, same category, |finding line - seeded line| <= 2.
* sca: same file and the CVE id (ruleId / cve_id) is one of the seeded CVE ids; the line delta is reported.
* One-to-one: a finding satisfies at most one flaw (greedy by rule-id agreement, then line distance).

## Headline detection rate (primary configuration per stage)

| Stage | Primary configuration | Seeded | Detected | Detection rate | Strict CI default ran? |
|---|---|---|---|---|---|
| secrets | tuned | 2 | 2 | 100.0% | yes |
| sast | custom-only | 3 | 3 | 100.0% | **no** (fallback config) |
| sca | **not run** | 3 | n/a | n/a | no |
| **Overall (evaluated stages only)** | | 5 | 5 | 100.0% | |
| **Overall (not-run stages counted as missed)** | | 8 | 5 | 62.5% | |

## Per-flaw results (primary configuration)

| Flaw | Stage | Detected | By rule | Line delta | Severity | Rule id = seed's expected id |
|---|---|---|---|---|---|---|
| V1a | secrets | yes | `aws-access-token` | 0 | Critical | yes |
| V1b | secrets | yes | `aws-secret-access-key` | 0 | Critical | yes |
| V2 | sast | yes | `devsecops-python-sql-injection-string-built-query` | 1 | High | no |
| V6 | sast | yes | `devsecops-python-weak-hash-for-password` | 0 | High | no |
| V7 | sast | yes | `devsecops-flask-debug-enabled` | 0 | Medium | no |
| V3a | sca | **not evaluated** (stage did not run) | - | - | - | - |
| V3b | sca | **not evaluated** (stage did not run) | - | - | - | - |
| V3c | sca | **not evaluated** (stage did not run) | - | - | - | - |

## False negatives and not-evaluated flaws

| Flaw | Configuration | Outcome | Evidence |
|---|---|---|---|
| V3a | sca | not evaluated | stage exited non-zero: [sca] ERROR: could not obtain the Trivy vulnerability DB (network blocked? set SCA_DB_REPOSITORY to a reachable mirror) |
| V3b | sca | not evaluated | stage exited non-zero: [sca] ERROR: could not obtain the Trivy vulnerability DB (network blocked? set SCA_DB_REPOSITORY to a reachable mirror) |
| V3c | sca | not evaluated | stage exited non-zero: [sca] ERROR: could not obtain the Trivy vulnerability DB (network blocked? set SCA_DB_REPOSITORY to a reachable mirror) |

## Findings on the vulnerable app that match no seeded flaw

2 finding(s) in the primary configurations; each is listed with a PROPOSED verdict in `triage.md` (needs human confirmation).

## False positives on the fixed app

| Configuration | Status | Findings |
|---|---|---|
| secrets/tuned | ran | 0  |
| secrets/gitleaks-default | ran | 0  |
| sast/custom+registry | **not run** | [sast] ERROR: semgrep failed (exit 2, registry unreachable). Set SAST_ALLOW_OFFLINE=1 to accept a local-rules-only scan, or SAST_REGISTRY_PACKS= to disable the registry |
| sast/custom-only | ran | 0  |
| sast/registry-only | **not run** | [sast] ERROR: semgrep failed (exit 2, registry unreachable). Set SAST_ALLOW_OFFLINE=1 to accept a local-rules-only scan, or SAST_REGISTRY_PACKS= to disable the registry |
| sca/default | **not run** | [sca] ERROR: could not obtain the Trivy vulnerability DB (network blocked? set SCA_DB_REPOSITORY to a reachable mirror) |

## Findings by severity (vulnerable app)

| Configuration | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| secrets/tuned | 2 | 2 | 0 | 0 | 4 |
| secrets/gitleaks-default | 1 | 0 | 0 | 0 | 1 |
| sast/custom+registry | **not run** | | | | |
| sast/custom-only | 0 | 2 | 1 | 0 | 3 |
| sast/registry-only | **not run** | | | | |
| sca/default | **not run** | | | | |

## Tuning comparison

| Configuration | Status | Detected / seeded | Findings (vulnerable) | Findings (fixed) | Missed flaws |
|---|---|---|---|---|---|
| secrets/tuned | ran | 2 / 2 | 4 | 0 | - |
| secrets/gitleaks-default | ran | 1 / 2 | 1 | 0 | V1b |
| sast/custom+registry | **not run** | n/a / 3 | n/a | n/a | n/a ([sast] ERROR: semgrep failed (exit 2, registry unreachable). Set SAST_ALLOW_OFFLINE=1 to accept a local-rules-only scan, or SAST_REGISTRY_PACKS= to disable the registry) |
| sast/custom-only | ran | 3 / 3 | 3 | 0 | - |
| sast/registry-only | **not run** | n/a / 3 | n/a | n/a | n/a ([sast] ERROR: semgrep failed (exit 2, registry unreachable). Set SAST_ALLOW_OFFLINE=1 to accept a local-rules-only scan, or SAST_REGISTRY_PACKS= to disable the registry) |
| sca/default | **not run** | n/a / 3 | n/a | n/a | n/a ([sca] ERROR: could not obtain the Trivy vulnerability DB (network blocked? set SCA_DB_REPOSITORY to a reachable mirror)) |

## Runtime (primary configuration, vulnerable app)

Cold = `install.sh` against an empty cache (tool provisioning on a fresh runner; the Trivy vulnerability-DB download is additional and is not included). Warm = the scan with the tool already cached.

| Stage | Configuration | Cold install (empty cache), s | Warm scan median, s | Warm runs, s | Byte-identical across warm runs |
|---|---|---|---|---|---|
| secrets | tuned | 0.81 | 1.27 | 1.26, 1.27, 1.27 | yes |
| sast | custom-only | 14.5 | 2.5 | 2.56, 2.5, 2.44 | yes |
| sca | not run | not measured | n/a | n/a | n/a |

## Tool versions and contract validation

| Configuration | Tool | `validate.py --stage` (vulnerable / fixed) |
|---|---|---|
| secrets/tuned | gitleaks 8.30.1 | valid / valid |
| secrets/gitleaks-default | gitleaks 8.30.1 | valid / valid |
| sast/custom+registry | n/a | n/a / n/a |
| sast/custom-only | semgrep 1.182.1 | valid / valid |
| sast/registry-only | n/a | n/a / n/a |
| sca/default | n/a | n/a / n/a |

# P2: Code-Level Security Scanning (Secrets, SAST, SCA)

> All figures in this document are read from `eval/p2-code/results.json` (generated 2026-10-27, commit `4c065d0`).
> Configurations that could not run in the build environment are marked **not run**; no number is estimated.

## 1. Introduction

A shift-left pipeline aims to find defects at the cheapest point of the lifecycle: when the code is committed, rather than after deployment. Three classes of code-level defect can be detected without running the application: credentials committed to the repository, insecure code patterns written by the team, and known vulnerabilities in third-party libraries. Phase 2 implements one scanner for each class as an interchangeable pipeline stage (`secrets`, `sast`, `sca`) that emits SARIF 2.1.0 conforming to the project contract, and evaluates the scanners against the flaws seeded in the demo application. The stages only report; the policy gate of Phase 4 decides whether a deployment is blocked.

## 2. Literature review

> **TODO(P2): to be written by the author. No sources have been cited here on purpose.**
>
> Suggested outline:
> 1. OWASP Top 10 and the relevant categories (injection, cryptographic failures, security misconfiguration, vulnerable and outdated components).
> 2. Shift-left security and DevSecOps: the rationale and the cost-of-fixing argument (find and cite a primary source before using it).
> 3. Differences between secret scanning, SAST and SCA: what each sees, what it cannot see.
> 4. Known limitations in the literature: false positives and alert fatigue, lack of reachability analysis, rule-set coverage, entropy-based detection limits.
> 5. Related tooling comparisons and benchmarks.

## 3. Methodology

### 3.1 Tools and versions

| Stage | Tool | Pinned version | Integrity |
|---|---|---|---|
| `secrets` | Gitleaks | 8.30.1 | SHA-256 pinned in `install.sh`, cross-checked with the official checksums file |
| `sast` | Semgrep (OSS CLI) | 1.182.1 | own virtual environment in the cache |
| `sca` | Trivy (filesystem mode, vulnerability scanner only) | 0.76.1 | SHA-256 pinned in `install.sh` |

### 3.2 Common design
* **Identical interface:** `run.sh <target> <output_dir>`; exit 0 when the scan completed (with or without findings), 1 only on scanner failure, 2 on usage error.
* **Fail closed:** crash, timeout, unloadable rules or database, or unparsable output give exit 1 and no SARIF file; an empty, valid SARIF means only "scan completed with zero findings".
* **Path normalisation:** every `uri` is repo-relative regardless of how the target was given.
* **Determinism:** results are sorted; consecutive runs on the same input produce byte-identical SARIF (checked for `secrets` and `sast`).
* **Self-contained stages:** each folder has its own installer and converter (Python standard library only).
* **Redaction:** the `secrets` stage runs Gitleaks with redaction and the converter never copies secret, match or line text; raw output stays in a private temporary directory.

### 3.3 Stage-specific configuration
* **secrets:** the default Gitleaks rules plus two custom rules found necessary by testing the defaults on the demo app: `aws-secret-access-key` (no default rule exists for the secret half of an AWS key pair) and `flask-hardcoded-secret-key` (low-entropy session key not matched by any default). A narrow allowlist covers placeholder templates, fixture directories and non-source directories; a test proves that it does not suppress the seeded secrets. Both the working tree and the git history under the target are scanned and de-duplicated.
* **sast:** three custom Semgrep rules (SQL injection through string-built queries, MD5/SHA-1 used for passwords, Flask `debug=True`), each with CWE, OWASP, confidence and remediation metadata and annotated rule tests, plus the registry packs `p/python`, `p/flask`, `p/owasp-top-ten`. If the registry is unreachable the stage fails unless `SAST_ALLOW_OFFLINE=1`.
* **sca:** Trivy JSON is converted by the stage itself so that package, installed and fixed versions, CVE id and fix availability reach the contract's optional properties. The vulnerability database is cached, retried a bounded number of times, and its absence is a failure.

### 3.4 Severity mapping
Following `contracts/severity-map.md`: Semgrep ERROR/WARNING/INFO map to High/Medium/Low; Trivy CRITICAL/HIGH/MEDIUM/LOW map to themselves and UNKNOWN to Low; Gitleaks findings are High, except an explicit list of cloud-provider credential rules, which are Critical. The tool's original label is kept in `raw_severity`.

### 3.5 Evaluation method
Ground truth is the set of seeded flaws of class secret, sast or sca in `demo-app/seeded-vulnerabilities.json` (8 flaws). A flaw counts as detected when a finding of the right category lies in the same file within ±2 lines (SCA: same file and a seeded CVE id); each finding satisfies at most one flaw. Both applications (`vulnerable`, `fixed`) are scanned; tuned and baseline configurations are compared.

## 4. Results

Source: `eval/p2-code/results.md`, `results.json`, figures `fig-p2-01.png` to `fig-p2-03.png`.

| Stage | Primary configuration | Seeded | Detected | Detection rate | Note |
|---|---|---|---|---|---|
| secrets | tuned | 2 | 2 | 100.0% | strict CI default ran |
| sast | custom rules only | 3 | 3 | 100.0% | registry packs **not run** (semgrep.dev unreachable) |
| sca | **not run** | 3 | n/a | n/a | Trivy DB hosts unreachable; stage failed closed |
| Overall, evaluated stages only | | 5 | 5 | 100.0% | |
| Overall, not-run stage counted as missed | | 8 | 5 | 62.5% | |

* **Tuning (secrets):** default Gitleaks configuration detected 1 of 2 seeded secrets (missed V1b, the AWS secret access key); the tuned configuration detected 2 of 2. Both reported 0 findings on the fixed app.
* **Tuning (sast):** registry-only and combined runs are **not run**; no comparison can be claimed.
* **Fixed app:** `secrets` 0 findings (tuned and default); `sast` (custom rules) 0 findings; `sca` not run.
* **Unmatched findings on the vulnerable app:** 2 (the hard-coded `SECRET_KEY` in `app.py` and `config.py`); proposed verdict *true positive not in seed list*, awaiting human confirmation (`eval/p2-code/triage.md`).
* **Runtime (vulnerable app):** `secrets` cold install 0.81 s, warm scan median 1.27 s; `sast` cold install 14.5 s, warm scan median 2.5 s; `sca` not measured. Warm repeats were byte-identical.

## 5. Discussion

**False negatives.** None among evaluated flaws. The three SCA flaws are *not evaluated*, not detected or missed: the stage could not obtain a vulnerability database and failed closed, which is the intended behaviour but leaves V3 unverified. Whether Trivy reports the same CVE ids as `pip-audit` (the source of the seed list) remains to be confirmed.

**False positives.** None on the fixed app for the configurations that ran. This is a small sample (one application); it says little about precision on other code bases.

**Effect of tuning.** The custom AWS secret rule changed the secrets result from 1/2 to 2/2. The custom SAST rules cover the three seeded patterns, but because their authoring was guided by the seeded flaws, the 100% rate is a *fit to the ground truth*, not an estimate of general recall. The registry packs would provide the independent check and were not run.

**Limitations.** Trivy sees only dependencies declared with a resolvable version in a manifest and does no reachability analysis. Semgrep rules are pattern-based and the SQL rule tracks data only within a function. Gitleaks relies on regular expressions and entropy and cannot judge whether a credential is live. In CI a shallow clone limits the history scan to one commit unless full history is fetched.

## 6. Conclusion

Three real scanners now replace the Phase 1 stubs behind an unchanged interface and produce contract-valid, deterministic, redacted, repo-relative SARIF. Evidence supports detection of V1 and V2/V6/V7 on the demo application with a very small false-positive record. The evidence does not yet cover V3 or the Semgrep registry packs; both depend on network access and are the first items to re-run (`bash eval/p2-code/run_eval.sh`) before the final project report.

# P2 assumptions and decisions not dictated by the master prompt

| # | Decision | Reason |
|---|---|---|
| A1 | `secrets` runs `gitleaks dir` for the working tree and `gitleaks git` with `--all -- <target path>` for history; findings outside the target are dropped in `to_sarif.py`. | Observed behaviour of gitleaks 8.30.1: without a pathspec it scans all paths of all refs of the enclosing repository. |
| A2 | Gitleaks has no severity, so `raw_severity` = rule id. Cloud-provider Critical list is explicit in `CLOUD_PROVIDER_RULES`: AWS (access token, secret key, Bedrock keys), GCP API key, Azure AD client secret. All other providers are High. | Matches `contracts/samples/secrets.sarif` and `severity-map.md`, which name AWS/GCP/Azure. |
| A3 | `properties.confidence` for secrets is `medium` for `generic-*` rules and the SECRET_KEY rule, otherwise `high`. | Heuristic by P2; Gitleaks provides none. Documented in the README. |
| A4 | Custom rule `flask-hardcoded-secret-key` is allow-listed for test directories (rule-scoped only). | It produced 3 false positives on `demo-app/fixed/tests/` before; all other rules still scan tests. |
| A5 | `secrets` test skip exits 0 with a visible message; `STAGE_TEST_STRICT=1` makes it exit 77. | Keeps offline `make test` usable while never passing silently. |
| A6 | `sast` fails closed when the Semgrep registry is unreachable unless `SAST_ALLOW_OFFLINE=1`. | Prompt section 7. A partially-applied ruleset must be an explicit choice. |
| A7 | The eval's *primary* SAST configuration is the first configuration that ran (`custom+registry`, else `custom-only`); the headline marks when it is a fallback to the non-strict config. | Honest reporting when the strict CI default cannot run. |
| A8 | The eval's Trivy DB download time is not part of "cold" runtime; cold = tool install into an empty cache. | The DB needs the network that is blocked here; stated in `results.md`. |
| A9 | The SCA test double (`tests/fake-trivy.sh`) and fixtures are used only for logic tests and a pipeline wiring check; they are never presented as V3 evidence. | No real DB available in the build sandbox. |
| A10 | `matplotlib==3.10.8` is optional (`eval/p2-code/requirements.txt`); `evaluate.py` produces tables without it. | Prompt 9.3. |
| A11 | The "secrets" work was merged into the baseline snapshot, so it has no branch of its own (it is on `main` already). | Branch layout of the uploaded progress archive. |
| A12 | The working tree for the `fixed` app is scanned from the repo root's `demo-app/fixed`; a leftover `P2-STATUS.txt` at the repo root (outside P2's folders) was removed and its content moved into `docs/p2-implementation-report.md`. | Ownership rule (prompt section 3). |

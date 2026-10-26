# Seeded Vulnerability Ground Truth

This file is the **authoritative ground truth** for Phase 5 detection-rate evaluation.  
Every vulnerability in `demo-app/vulnerable/` is documented here with exact file paths and line numbers.

> **Drift protection:** `demo-app/tests/test_seeded_vulns.py` automatically checks that every listed file exists and the listed line contains the expected pattern. If the code is refactored and lines shift, the test will fail, alerting the team to update this file before the data becomes stale.

---

## Vulnerability Table

| ID | File | Line | Class | Description | Expected Detecting Tool | Expected Rule ID | CVE IDs | Fixed In Version | Notes |
|---|---|---|---|---|---|---|---|---|---|
| V1a | `demo-app/vulnerable/config.py` | 17 | Secret | Hardcoded fake AWS Access Key ID (pattern: `AKIA` + 16 alphanums) | Gitleaks | `aws-access-token` | — | n/a — remove hardcoded value | Fake key; not a real credential |
| V1b | `demo-app/vulnerable/config.py` | 18 | Secret | Hardcoded fake AWS Secret Access Key | Gitleaks | `aws-secret-access-key` | — | n/a — read from env var | Fake key; not a real credential |
| V2 | `demo-app/vulnerable/app.py` | 91 | SAST | SQL injection via string concatenation in `/users` endpoint | Semgrep | `python.lang.security.audit.sqli.formatted-sql-query` | CWE-89 | Use parameterized query | High confidence |
| V3a | `demo-app/vulnerable/requirements.txt` | 15 | SCA | Flask 1.1.4 — response with session cookie may be cached by a shared proxy (missing Vary: Cookie) | Trivy (fs) | `CVE-2023-30861` | CVE-2023-30861 | Flask >= 2.3.2 | Status: verified with pip-audit (2026-10-27) |
| V3b | `demo-app/vulnerable/requirements.txt` | 16 | SCA | Jinja2 2.11.3 — xmlattr filter accepts keys with spaces, enabling attribute injection (XSS) | Trivy (fs) | `CVE-2024-34064` | CVE-2024-34064 | Jinja2 >= 3.1.4 | Status: verified with pip-audit (2026-10-27) |
| V3c | `demo-app/vulnerable/requirements.txt` | 17 | SCA | Werkzeug 1.0.1 — multipart data parsing DoS | Trivy (fs) | `CVE-2023-25577` | CVE-2023-25577 | Werkzeug >= 2.2.3 | Status: verified with pip-audit (2026-10-27) |
| V4 | `demo-app/vulnerable/Dockerfile` | 14 | IaC | No `USER` instruction — container runs as root (FROM line is the anchor) | Hadolint, Checkov | `DL3002` | — | Add `RUN useradd && USER appuser` | P3 hardens this in Phase 3 |
| V5 | `demo-app/vulnerable/Dockerfile` | 14 | IaC | Unpinned base image `python:3.9` (major tag only, no digest) | Hadolint, Trivy image | `DL3007` | — | Pin to `python:3.12.4-slim` with digest | Line 14 is the FROM instruction |
| V6 | `demo-app/vulnerable/app.py` | 111 | SAST | MD5 used for password hashing (cryptographically broken) | Semgrep | `python.lang.security.audit.md5-used-as-password` | CWE-327 | Use bcrypt / scrypt / argon2 | High confidence |
| V7 | `demo-app/vulnerable/app.py` | 137 | SAST | Flask debug mode enabled (`debug=True`) | Semgrep | `python.flask.security.audit.app-run-debug-enabled` | CWE-94 | Remove or read from env var | Medium confidence |
| V8 | `demo-app/vulnerable/Dockerfile` | 14 | IaC | No `HEALTHCHECK` instruction | Checkov | `CKV_DOCKER_2` | — | Add `HEALTHCHECK` instruction | FROM line (14) used as anchor for file-level findings |

---

## CVE Status Details (V3)

| CVE | Package | Installed | Fixed | Severity | Verified? | Source |
|---|---|---|---|---|---|---|
| CVE-2023-30861 | Flask | 1.1.4 | 2.3.2 | High | verified with pip-audit (2026-10-27) | pip-audit |
| CVE-2024-34064 | Jinja2 | 2.11.3 | 3.1.4 | Medium | verified with pip-audit (2026-10-27) | pip-audit |
| CVE-2023-25577 | Werkzeug | 1.0.1 | 2.2.3 | High | verified with pip-audit (2026-10-27) | pip-audit |

---

## Phase 5 Usage

In Phase 5, the team computes:

- **Detection rate** = (findings detected by real tools matching a V-ID) / (total V-IDs) × 100%
- **False negative rate** = V-IDs not detected by any tool
- **False positive rate** = tool findings not matching any V-ID

The `seeded-vulnerabilities.json` file (machine-readable) is the input for the automated evaluation script.

---

## How to Handle a Line-Number Drift

If `test_seeded_vulns.py` fails because a line number has shifted (e.g. after a code refactor):

1. Find the new line number for the planted pattern.
2. Update both `seeded-vulnerabilities.md` (this file) and `seeded-vulnerabilities.json`.
3. Run the test again to confirm it passes.
4. Open a PR. P1 reviews and approves.

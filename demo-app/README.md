# Demo Application README

This directory contains two versions of a small Flask user/notes service:

| Folder | Purpose |
|---|---|
| `vulnerable/` | Deliberately insecure — used as the scanner target |
| `fixed/` | Corrected — demonstrates non-breaking security fixes |

---

## ⚠️ Security Warning

**The `vulnerable/` folder is intentionally insecure and must NEVER be deployed or exposed to any network.**

Specifically:
- It contains a **fake AWS access key** (`config.py`) that matches the AWS pattern but is **not a real credential** and is not associated with any real account. It is planted solely to demonstrate secret detection.
- It contains SQL injection, weak password hashing, and Dockerfile security flaws — all deliberate.
- Dependabot and Renovate are **not** configured for `vulnerable/` to avoid noise from the intentionally outdated dependencies.

### Handling Secret Scanner Warnings

GitHub push protection or other tools may flag the fake AWS key in `vulnerable/config.py`. To bypass:

1. **GitHub push protection bypass (known-fake test value):**
   - When the push is blocked, click "Allow secret" in the GitHub UI.
   - Select "It's used in tests" or "False positive" as the reason.
   - Document the bypass in your team's security log.
2. **Alternative:** Ask your GitHub admin to add the fake key pattern to the allowed-secrets list for this repository.
3. **Do NOT** obfuscate or encode the key — the whole point is to make it detectable by scanners.

---

## Running the Vulnerable App Locally

> **Only run this in an isolated local environment. Never deploy.**

```bash
cd demo-app/vulnerable
pip install -r requirements.txt
python app.py
# Visits http://127.0.0.1:5000/health
```

---

## Running the Fixed App Locally

```bash
cd demo-app/fixed
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set SECRET_KEY to a random value
SECRET_KEY=your-random-secret python app.py
```

---

## Running Tests

```bash
# From repo root
pip install pytest Flask  # install test dependencies
pytest demo-app/vulnerable/tests/  -v   # functional tests (vulnerable app)
pytest demo-app/fixed/tests/ -v         # functional tests (fixed app)
pytest demo-app/tests/ -v               # drift-protection tests
```

---

## Building with Docker

```bash
# Vulnerable app (ISOLATED ENVIRONMENT ONLY)
docker build -t demo-vulnerable demo-app/vulnerable/
# NOTE: Docker build may or may not be available in your environment.

# Fixed app
docker build -t demo-fixed demo-app/fixed/
docker run -e SECRET_KEY=test -p 5000:5000 demo-fixed
```

Docker build was not verified in the Phase 1 environment (Docker daemon not available in the CI environment during scaffolding). The Dockerfiles follow best practices and are expected to build correctly.

---

## Seeded Vulnerability Ground Truth

See [`seeded-vulnerabilities.md`](seeded-vulnerabilities.md) and [`seeded-vulnerabilities.json`](seeded-vulnerabilities.json) for the complete list of planted flaws, including exact file paths, line numbers, CVE IDs, and expected detecting tools.

This data is used in Phase 5 to compute the detection rate of the real scanner pipeline.

**Drift protection:** `demo-app/tests/test_seeded_vulns.py` automatically checks that every listed file exists and the listed line contains the expected pattern. If the code is refactored, this test fails.

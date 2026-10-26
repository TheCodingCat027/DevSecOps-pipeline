# DevSecOps Pipeline — Automated Security Integration for CI/CD

A 4-person university project demonstrating how to integrate automatic security scanning into a CI/CD pipeline using a shift-left / DevSecOps approach.

**Quick start:**

```bash
pip install -r contracts/requirements.txt Flask==3.1.0
python contracts/validate.py contracts/samples/        # validate samples
python -m pytest contracts/tests/ demo-app/tests/ -v   # run all tests
bash scripts/run-local-pipeline.sh demo-app/vulnerable # run local pipeline
```

> **Note:** The Makefile uses `make setup` (requires bash/venv). On Windows without WSL, use the `pip install` and direct commands above.

See [`docs/p1-implementation-report.md`](docs/p1-implementation-report.md) for the full Phase 1 record.

---

## Project Summary

| Property | Value |
|---|---|
| **Problem** | Manual security review can't scale to continuous deployment |
| **Solution** | Automated security gates at each CI stage that block non-compliant deployments |
| **Approach** | Shift-left: scanners run on every commit; gate blocks promotion to production |
| **Phase 1** | Repo skeleton, frozen contracts, validator, seeded demo app, stub stages, CI pipeline |

---

## Repository Layout

```
.
├── contracts/           # FROZEN schemas, profiles, validator (all 4 owners)
├── stages/              # One folder per scanner stage (P2 owns secrets/sast/sca; P3 owns rest)
├── gate/                # Policy gate (P4)
├── demo-app/            # Vulnerable + fixed Flask app with 8 seeded vulnerabilities (P1)
├── security-policy.yaml # Security thresholds (P4 from Phase 4)
├── .github/workflows/   # CI pipeline (P1 only)
├── scripts/             # Local pipeline runner (P1)
├── eval/                # Evaluation data (one subfolder per phase)
└── docs/                # Architecture, contributing, branch protection (one file per phase)
```

---

## Ownership Table

| Path(s) | Owner | Phase |
|---|---|---|
| `contracts/` | All 4 (P4 leads) | Frozen after Phase 1 |
| `stages/secrets/`, `stages/sast/`, `stages/sca/` | P2 | Phase 2 |
| `stages/iac/`, `stages/container/`, `stages/sbom/`, `stages/dast/` | P3 | Phase 3 |
| `gate/`, `security-policy.yaml` | P4 | Phase 4 |
| Everything else | P1 | Phase 1 |

---

## Key Documents

| Document | Purpose |
|---|---|
| [`docs/p1-implementation-report.md`](docs/p1-implementation-report.md) | Full Phase 1 implementation record |
| [`docs/p1-architecture.md`](docs/p1-architecture.md) | Pipeline architecture with Mermaid diagram |
| [`contracts/stage-interface.md`](contracts/stage-interface.md) | Universal stage interface (frozen) |
| [`contracts/gate-interface.md`](contracts/gate-interface.md) | Gate interface (frozen) |
| [`contracts/sarif-profile.md`](contracts/sarif-profile.md) | SARIF subset all stages must emit |
| [`contracts/severity-map.md`](contracts/severity-map.md) | Tool severity → canonical 4-level mapping |
| [`docs/contributing.md`](docs/contributing.md) | Branch naming, reviewer rotation, stub replacement guide |
| [`docs/branch-protection.md`](docs/branch-protection.md) | GitHub branch protection settings + `gh api` commands |
| [`demo-app/seeded-vulnerabilities.md`](demo-app/seeded-vulnerabilities.md) | Ground truth for Phase 5 detection-rate evaluation |
| [`docs/team-signoff.md`](docs/team-signoff.md) | Sign-off checklist for freezing contracts v1.0.0 |

# IaC Stage

**Owner:** P3  
**Status:** Stub (Phase 1) — replace with Hadolint + Checkov in Phase 3  
**Interface:** See [`contracts/stage-interface.md`](../../contracts/stage-interface.md)

## Purpose

Infrastructure-as-Code scanning: checks Dockerfiles, Kubernetes manifests, Terraform, and other IaC files for misconfigurations and security violations.

## Real Tools (Phase 3)

- **Hadolint v2.12.0** — Dockerfile linter — [https://github.com/hadolint/hadolint](https://github.com/hadolint/hadolint)
- **Checkov 3.x** — Policy-as-code scanner — [https://www.checkov.io](https://www.checkov.io)

Pinned version placeholders: `hadolint 2.12.0`, `checkov 3.x.x`

## How to Replace This Stub (4 Steps)

1. Read `contracts/stage-interface.md`.
2. Run Hadolint and Checkov; merge their SARIF outputs into a single `iac.sarif`.
3. Apply severity mapping from `contracts/severity-map.md`.
4. Extend tests: scan `demo-app/vulnerable/Dockerfile`; assert DL3002 (no USER), DL3007 (unpinned), CKV_DOCKER_2 (no HEALTHCHECK) are present.

## Stage Interface

```
stages/iac/run.sh <target_path> <output_dir>
  -> writes  <output_dir>/iac.sarif
  -> exit 0  scan completed | exit 1  tool crashed | exit 2  bad args
```

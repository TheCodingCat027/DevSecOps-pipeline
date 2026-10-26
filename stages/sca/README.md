# SCA Stage

**Owner:** P2  
**Status:** Stub (Phase 1) — replace with Trivy fs in Phase 2  
**Interface:** See [`contracts/stage-interface.md`](../../contracts/stage-interface.md)

## Purpose

Software Composition Analysis: scans dependency manifests (`requirements.txt`, `package.json`, etc.) for known CVEs in third-party packages.

## Real Tool (Phase 2)

**Trivy v0.51.4 (fs mode)** — [https://trivy.dev](https://trivy.dev)  
Pinned version placeholder: `trivy 0.51.4`

## How to Replace This Stub (4 Steps)

1. Read `contracts/stage-interface.md`.
2. Replace stub body with: `trivy fs --format sarif --output "$OUTPUT_DIR/sca.sarif" "$TARGET_PATH" ; exit 0`
3. Apply severity mapping from `contracts/severity-map.md` (Trivy CRITICAL→Critical, etc.).
4. Extend tests: scan `demo-app/vulnerable` and assert CVE-2023-30861, CVE-2024-34064, CVE-2023-25577 are present.

## Stage Interface

```
stages/sca/run.sh <target_path> <output_dir>
  -> writes  <output_dir>/sca.sarif
  -> exit 0  scan completed | exit 1  tool crashed | exit 2  bad args
```

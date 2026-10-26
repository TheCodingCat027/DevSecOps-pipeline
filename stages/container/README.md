# Container Stage

**Owner:** P3  
**Status:** Stub (Phase 1) — replace with Trivy image in Phase 3  
**Interface:** See [`contracts/stage-interface.md`](../../contracts/stage-interface.md)  
**Requires:** `IMAGE_REF` environment variable (set by CI build-image job)

## Purpose

Container image scanning: scans a built Docker image for OS-level CVEs, package vulnerabilities, and misconfigurations.

## Real Tool (Phase 3)

**Trivy v0.51.4 (image mode)** — [https://trivy.dev](https://trivy.dev)  
Pinned version placeholder: `trivy 0.51.4`

## How to Replace This Stub (4 Steps)

1. Read `contracts/stage-interface.md` §7 (IMAGE_REF requirement).
2. Replace stub body with: `trivy image --format sarif --output "$OUTPUT_DIR/container.sarif" "$IMAGE_REF" ; exit 0`
3. Apply severity mapping from `contracts/severity-map.md`.
4. Extend tests: load a test image and assert CVEs are detected.

## Stage Interface

```
stages/container/run.sh <target_path> <output_dir>
  IMAGE_REF env var required (container reference or sha256 digest)
  -> writes  <output_dir>/container.sarif
  -> exit 0  scan completed | exit 1  tool crashed | exit 2  bad args/missing IMAGE_REF
```

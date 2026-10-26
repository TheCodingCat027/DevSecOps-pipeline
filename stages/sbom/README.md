# SBOM Stage

**Owner:** P3  
**Status:** Stub (Phase 1) — replace with Syft in Phase 3  
**Interface:** See [`contracts/stage-interface.md`](../../contracts/stage-interface.md)

## Purpose

Software Bill of Materials generation: produces a machine-readable inventory of all components, packages, and dependencies in the application or container image.

## Real Tool (Phase 3)

**Syft v1.5.0** — [https://github.com/anchore/syft](https://github.com/anchore/syft)  
Pinned version placeholder: `syft 1.5.0`

## Output Files

- `<output_dir>/sbom.sarif` — Always zero results (Syft is inventory-only, no security findings)
- `<output_dir>/artifacts/sbom/sbom.cdx.json` — CycloneDX 1.5 SBOM (the main deliverable)

## How to Replace This Stub (4 Steps)

1. Read `contracts/stage-interface.md` §6 (non-SARIF artifacts go in `artifacts/<stage>/`).
2. Replace stub body with: `syft "$IMAGE_REF" -o cyclonedx-json="$OUTPUT_DIR/artifacts/sbom/sbom.cdx.json"`
3. Write an empty `sbom.sarif` (Syft produces no findings; zero-results SARIF is valid).
4. Extend tests: assert `sbom.cdx.json` contains component entries.

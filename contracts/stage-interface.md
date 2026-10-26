# Stage Interface Contract

> **FROZEN** — Part of the v1.0.0 contract set. Amendments require the process in `contracts/CHANGELOG.md`.

This document defines the universal interface that every scanner stage must implement. Because all stages share this interface, the CI pipeline and the gate treat them identically — adding or upgrading a scanner never requires changes to `pipeline.yml` or `gate/run_gate.py`.

---

## 1. Invocation

```
stages/<name>/run.sh <target_path> <output_dir>
```

| Argument | Description |
|---|---|
| `<target_path>` | Absolute or repo-relative path to the codebase or artifact being scanned. Usually `demo-app/vulnerable` or the target passed from the workflow. Must not be modified by the stage. |
| `<output_dir>` | Directory where all stage outputs are written. Created by the stage if it does not exist. |

---

## 2. Outputs

| Output | Path | Required | Notes |
|---|---|---|---|
| SARIF report | `<output_dir>/<name>.sarif` | **Always** | Even when the scan finds zero issues. Must conform to `contracts/sarif-profile.md`. |
| Additional artifacts | `<output_dir>/artifacts/<name>/` | Optional | E.g. CycloneDX SBOM JSON for the `sbom` stage. Never validated against the SARIF profile. |

The SARIF file must be written **atomically** (write to a temp file then rename, or ensure the file is only opened for write once). This prevents the gate from reading a partially-written file.

---

## 3. Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed successfully. This includes the case where findings were found — findings are data, not errors. |
| `1` | The scanner itself crashed or returned an unexpected error (not a scan result). |
| `2` | Usage error: wrong number of arguments, missing required files, invalid arguments. |

> **Critical rule:** A stage must **never** exit non-zero because it found vulnerabilities. The gate decides whether findings constitute a failure, not the stage.

---

## 4. Logging

- **stderr**: All diagnostic messages, progress output, and the single required stub banner.
- **stdout**: Silent (no output). This keeps stdout clean for any pipeline orchestration that may capture it.

---

## 5. Idempotency

Running the stage twice with the same arguments must produce the same output. The stage must not:
- Modify `<target_path>` or any file within it.
- Leave partial state if interrupted (write atomically or clean up on failure).
- Depend on the current working directory (use paths relative to the script's own location via `$(dirname "$0")`).

---

## 6. Per-Stage Folder Requirements

Each `stages/<name>/` folder must contain:

| File | Contents |
|---|---|
| `run.sh` | The stage script. Must start with `set -euo pipefail`. Must be executable (`chmod +x`). |
| `README.md` | Stage purpose, owner, tool name with **pinned version** (e.g. `gitleaks v8.18.4`), install method, link to this document, and "how to replace this stub" in 4 steps (see `docs/contributing.md`). |
| `tests/run_test.sh` | Integration test. Runs the stage against a temp directory. Asserts SARIF exists and passes `python contracts/validate.py --stage <name>`. Must be executable. |

---

## 7. Stages Requiring a Built Container Image

The `container`, `sbom`, and `dast` stages scan a built container image, not source code. These stages receive the image reference through the environment variable:

```bash
export IMAGE_REF="<registry>/<image>:<tag>"
# or for locally loaded images:
export IMAGE_REF="sha256:<digest>"
```

If `IMAGE_REF` is not set, the stage should print an error to stderr and exit 2.

In CI, the `build-image` job builds and exports the image; the `stage` job for `needs_image: true` stages downloads, loads, and sets `IMAGE_REF` before calling `run.sh`. See `.github/workflows/pipeline.yml` and `.github/actions/run-stage/action.yml`.

---

## 8. The `extract_findings` Module Function

`contracts/validate.py` exposes a stable importable function:

```python
from contracts.validate import extract_findings

findings: list[dict] = extract_findings(sarif_dict)
```

Where `sarif_dict` is a parsed SARIF JSON object (as returned by `json.load()`). The function returns a list of finding dictionaries conforming to `finding.schema.json`.

**This function signature is part of the frozen contract.** P4's normalizer imports and calls it directly. Do not change its name, arguments, or return type without a contract amendment.

### What `extract_findings` does

1. Reads `runs[0].tool.driver.name` → `tool`.
2. For each result in `runs[0].results`:
   - Maps SARIF fields to finding fields per the table in `contracts/sarif-profile.md`.
   - Defaults `line` to `0` if `region.startLine` is absent.
   - Defaults `fix` to `null` if `properties.fix` is absent.
   - Copies all optional `properties.*` fields that are present.
3. Returns the list. Does **not** validate against the finding schema (call `jsonschema.validate()` separately if needed).

---

## 9. Compliance Checklist for P2 and P3

Before opening a PR that replaces a stub:

- [ ] `run.sh` accepts exactly 2 positional arguments and exits 2 otherwise.
- [ ] `run.sh` creates `<output_dir>` if absent.
- [ ] SARIF is always written, even on zero findings.
- [ ] Exit code is 0 for any completed scan (even with findings), 1 for tool crash, 2 for misuse.
- [ ] `properties.severity` and `properties.category` are set on every result.
- [ ] `properties.raw_severity` is set to the tool's original label.
- [ ] `tool.driver.version` is set and matches the pinned version in `README.md`.
- [ ] `python contracts/validate.py <output>.sarif --stage <name>` exits 0.
- [ ] `stages/<name>/tests/run_test.sh` passes.

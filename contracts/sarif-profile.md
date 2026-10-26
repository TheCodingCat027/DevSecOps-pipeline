# SARIF Profile for DevSecOps Pipeline Stages

> **FROZEN** — This profile is part of the v1.0.0 contract set. Any change requires a numbered amendment in `contracts/CHANGELOG.md` with acknowledgement from all four team members.

Every scanner stage in this pipeline must emit **SARIF 2.1.0** conforming to this profile. The `contracts/validate.py` tool enforces this profile automatically.

---

## 1. Top-Level Structure

```json
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "runs": [ /* exactly one run object */ ]
}
```

- `version` **must** be the string `"2.1.0"`. Any other value is rejected.
- `runs` **must** be an array containing **exactly one** run object.

---

## 2. Tool Driver

```json
"tool": {
  "driver": {
    "name": "<tool-name>",
    "version": "<pinned-version>",
    "rules": [ /* optional rule definitions */ ]
  }
}
```

- `runs[0].tool.driver.name` is **required** and must be a non-empty string.
- `runs[0].tool.driver.version` is **required** and must be a non-empty string.
  - This requirement enforces pinned tool versions: a stage that uses an unpinned tool cannot produce a valid SARIF.
- `rules` is optional but encouraged. If present, each rule must have `id` and `shortDescription.text`.

---

## 3. Results Array

`runs[0].results` is an array (may be empty — zero findings is valid and common, e.g. the SBOM stage).

Each result must include:

| Field | Type | Requirement | Notes |
|---|---|---|---|
| `ruleId` | string | **Required** | Tool-specific rule identifier |
| `level` | string | **Required** | One of `"error"`, `"warning"`, `"note"` |
| `message.text` | string | **Required** | Human-readable description |
| `locations[0].physicalLocation.artifactLocation.uri` | string | **Required** | Repo-relative file path |
| `properties.severity` | string | **Required** | One of `Critical`, `High`, `Medium`, `Low` |
| `properties.category` | string | **Required** | One of `secret`, `sast`, `sca`, `iac`, `container`, `dast` |

### Level ↔ Severity Mapping

The SARIF `level` field approximates severity but is not authoritative — `properties.severity` is the canonical value:

| `level` | Typical `properties.severity` |
|---|---|
| `error` | Critical or High |
| `warning` | Medium |
| `note` | Low |

---

## 4. Optional Result Fields

These mirror the optional fields in `finding.schema.json`. They are not required by the validator but will be extracted by `validate.py → extract_findings()` if present:

| SARIF Path | Finding Field | Used By |
|---|---|---|
| `locations[0].physicalLocation.region.startLine` | `line` | All phases |
| `properties.fix` | `fix` | P4 reports |
| `properties.cve_id` | `cve_id` | P4 policy gate |
| `properties.cwe` | `cwe` | P4 reports |
| `properties.package` | `package` | P4 SCA gate |
| `properties.installed_version` | `installed_version` | P4 SCA gate |
| `properties.fixed_version` | `fixed_version` | P4 SCA gate |
| `properties.fix_available` | `fix_available` | P4 prioritization |
| `properties.confidence` | `confidence` | P4 noise filtering |
| `properties.raw_severity` | `raw_severity` | Traceability |

---

## 5. Field Mapping Table: SARIF → Finding

The `extract_findings(sarif_dict)` function in `contracts/validate.py` performs this mapping for each result:

| SARIF Path | Finding Field | Transformation |
|---|---|---|
| `runs[0].tool.driver.name` | `tool` | Direct |
| `properties.category` | `stage` | Same value used for both `stage` and `category` initially; `stage` is the stage name |
| `properties.category` | `category` | Direct |
| `ruleId` | `rule_id` | Direct |
| `properties.severity` | `severity` | Direct (must be one of the four values) |
| `locations[0].physicalLocation.artifactLocation.uri` | `file` | Direct |
| `locations[0].physicalLocation.region.startLine` | `line` | Default: 0 if absent |
| `message.text` | `description` | Direct |
| `properties.fix` | `fix` | Default: null if absent |
| `properties.cve_id` | `cve_id` | Optional |
| `properties.cwe` | `cwe` | Optional |
| `properties.package` | `package` | Optional |
| `properties.installed_version` | `installed_version` | Optional |
| `properties.fixed_version` | `fixed_version` | Optional |
| `properties.fix_available` | `fix_available` | Optional |
| `properties.confidence` | `confidence` | Optional |
| `properties.raw_severity` | `raw_severity` | Optional |

---

## 6. Non-SARIF Artifacts

Some stages produce additional output files (e.g., a CycloneDX SBOM from the `sbom` stage). These are **never** validated against this SARIF profile:

- They are written to `<output_dir>/artifacts/<stage>/`.
- They must not be confused with the SARIF output.
- The SARIF file for such stages (`sbom.sarif`, `dast.sarif`) may have zero results but must still include valid driver metadata.

---

## 7. Example Minimal Valid SARIF

```json
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "my-scanner",
          "version": "1.2.3"
        }
      },
      "results": []
    }
  ]
}
```

---

## 8. Enforcement

Run `python contracts/validate.py <file.sarif> [--stage NAME]` to verify conformance. This is also run automatically in CI as part of the `contracts-and-tests` job and after each stage run.

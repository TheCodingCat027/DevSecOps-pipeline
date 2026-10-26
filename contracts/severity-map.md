# Severity Mapping

> **FROZEN** — Part of the v1.0.0 contract set. Amendments require the process in `contracts/CHANGELOG.md`.

This document defines how each scanner's native severity labels map to the four canonical levels used throughout this pipeline: **Critical**, **High**, **Medium**, **Low**.

The canonical levels are defined in `contracts/finding.schema.json` (`severity` enum). Every stage must translate to these four values before writing SARIF (via `properties.severity`). The original label is preserved in `properties.raw_severity` for traceability and audit.

---

## Default Fallback

> **Unknown, missing, or unrecognized severity labels always map to `Low`.**

This is a conservative default: an unlabeled finding is surfaced (not silently dropped) but at the lowest priority. P4's policy gate can be tuned to treat Low findings more aggressively if needed.

---

## Per-Tool Mapping Table

| Tool | Stage | Source Label | Maps To | Notes |
|---|---|---|---|---|
| **Gitleaks** | secrets | *(no severity field)* any secret | **High** | Cloud-provider credentials (AWS, GCP, Azure) → **Critical** |
| **Semgrep** | sast | `ERROR` | **High** | |
| **Semgrep** | sast | `WARNING` | **Medium** | |
| **Semgrep** | sast | `INFO` | **Low** | |
| **Trivy** (fs/image) | sca, container | `CRITICAL` | **Critical** | |
| **Trivy** (fs/image) | sca, container | `HIGH` | **High** | |
| **Trivy** (fs/image) | sca, container | `MEDIUM` | **Medium** | |
| **Trivy** (fs/image) | sca, container | `LOW` | **Low** | |
| **Trivy** (fs/image) | sca, container | `UNKNOWN` | **Low** | Fallback per default rule |
| **Hadolint** | iac | `error` | **High** | |
| **Hadolint** | iac | `warning` | **Medium** | |
| **Hadolint** | iac | `info` | **Low** | |
| **Hadolint** | iac | `style` | **Low** | |
| **Checkov** | iac | severity if present | *(direct map)* | If no severity, default → **Medium** |
| **Checkov** | iac | *(absent)* | **Medium** | Conservative default for policy-as-code checks |
| **ZAP** | dast | `High` | **High** | |
| **ZAP** | dast | `Medium` | **Medium** | |
| **ZAP** | dast | `Low` | **Low** | |
| **ZAP** | dast | `Informational` | **Low** | |
| **Syft** | sbom | n/a | n/a | Syft is an inventory tool; it emits no security findings |

---

## Notes on Specific Tools

### Gitleaks
Gitleaks detects secrets and does not assign a severity by itself. The mapping logic must inspect the matched rule to determine if it is a cloud-provider credential:
- Rules matching cloud providers (AWS `AKIA*`, GCP service accounts, Azure credentials) → **Critical**
- All other rules → **High**

### Checkov
Checkov results may or may not include a severity field depending on the check version and the registry used. The stage must check for `SEVERITY` in the check result. If present, map `CRITICAL→Critical`, `HIGH→High`, `MEDIUM→Medium`, `LOW→Low`. If absent, use **Medium**.

### Syft
Syft generates a Software Bill of Materials (SBOM) in CycloneDX format. It does not report vulnerabilities, so no severity mapping applies. Its SARIF output will have zero results and the `sbom.sarif` file is valid by the zero-results rule.

---

## Implementation Notes for P2 and P3

- Apply the mapping inside `run.sh` or a helper script before writing the SARIF.
- Always write the source label to `properties.raw_severity` so the gate and reports can show both values.
- The `--stage` flag in `contracts/validate.py` checks that the `properties.severity` value is one of the four canonical strings.

# Gate Interface Contract

> **FROZEN** — Part of the v1.0.0 contract set. Amendments require the process in `contracts/CHANGELOG.md`.

This document defines the interface for the security policy gate. The gate reads all stage SARIF reports, applies the security policy, and produces a deployment decision. The gate is the **only** component that decides whether a deployment is allowed — stages only report findings.

---

## 1. Invocation

```
python gate/run_gate.py \
  --reports <dir>   \
  --policy  <file>  \
  --out     <dir>
```

| Argument | Description |
|---|---|
| `--reports <dir>` | Directory containing all `*.sarif` files produced by the stage jobs. Typically `reports/` after downloading all `reports-*` artifacts. |
| `--policy <file>` | Path to the security policy YAML file (e.g. `security-policy.yaml`). Must validate against `contracts/policy.schema.json`. |
| `--out <dir>` | Directory where the gate writes its outputs. Created if absent. |

---

## 2. Exit Codes

| Code | Meaning | Effect on deployment |
|---|---|---|
| `0` | Policy satisfied, **or** `mode: audit` (audit never blocks). | Deploy job **may** proceed. |
| `1` | Policy violated — at least one threshold exceeded (after waivers applied). | Deploy job **must not** run. |
| `2` | Internal error — invalid SARIF, invalid policy, schema violation, unexpected exception. | Deploy job **must not** run (fail safe). |

> **Audit mode:** When `mode: audit`, the gate always exits 0 but still writes `gate-result.json` with `decision: "fail"` if thresholds would be exceeded. This allows the team to measure policy violations before enforcing them.

---

## 3. Outputs

### `<out>/gate-result.json`

The deployment decision document. Must contain **at minimum**:

```json
{
  "decision": "pass",
  "mode": "enforce",
  "counts": {
    "Critical": 0,
    "High": 2,
    "Medium": 5,
    "Low": 12,
    "total": 19
  },
  "violations": [],
  "waivers_applied": [],
  "generated_at": "2024-01-15T10:30:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `decision` | string | `"pass"`, `"fail"`, or `"error"` |
| `mode` | string | The mode from the policy (`enforce` or `audit`) |
| `counts` | object | Finding counts by canonical severity level plus `total` |
| `violations` | array | List of strings describing each policy threshold that was exceeded |
| `waivers_applied` | array | List of waiver IDs that were applied (P4 populates this) |
| `generated_at` | string | ISO 8601 UTC timestamp |

### `<out>/findings.json`

An array of all normalized findings across all stages, each conforming to `contracts/finding.schema.json`. This is the authoritative finding list for the dashboard and eval.

```json
[
  {
    "tool": "semgrep",
    "stage": "sast",
    "category": "sast",
    "rule_id": "python.lang.security.audit.sqli.formatted-sql-query",
    "severity": "High",
    "file": "demo-app/vulnerable/app.py",
    "line": 42,
    "description": "SQL injection via string concatenation",
    "fix": "Use parameterized queries"
  }
]
```

---

## 4. Validation Requirements (Gate Must Enforce)

Before evaluating policy thresholds, the gate must:

1. Validate every `*.sarif` in `--reports` using `contracts/validate.py` (import `extract_findings`). Exit 2 if any SARIF is invalid.
2. Validate the policy file against `contracts/policy.schema.json`. Exit 2 if invalid.
3. Check that the policy `version` is `1` (the only version defined). Exit 2 otherwise.

---

## 5. Policy Evaluation Logic (P4 implements in Phase 4)

The stub gate (Phase 1) always exits 0 (unless `GATE_FORCE_FAIL=1`). P4 replaces the stub body with:

1. Extract all findings from all SARIFs (via `extract_findings`).
2. Filter out waived findings (match by `id`, `cve_id`, `rule_id`, or `scope` glob).
3. Count findings by severity per category (secrets vs. vulnerabilities).
4. Compare counts against policy thresholds.
5. In `mode: enforce`, exit 1 if any threshold is exceeded. In `mode: audit`, always exit 0.
6. Write `findings.json` and `gate-result.json`.

---

## 6. Special Environment Variables

| Variable | Effect |
|---|---|
| `GATE_FORCE_FAIL=1` | Stub gate exits 1 (simulates a policy violation for demo/testing before Phase 4). Has no effect on the real gate (P4 removes this variable handling once real logic is in place). |

---

## 7. Stub Banner

The Phase 1 stub gate prints this line to stderr:

```
[stub gate] real policy evaluation arrives in Phase 4
```

P4 removes this line when implementing the real gate.

---

## 8. Interface Stability

The command-line arguments (`--reports`, `--policy`, `--out`), exit codes, and the schema of `gate-result.json` and `findings.json` are **frozen**. P4 replaces only the internal logic of `gate/run_gate.py`. The CI pipeline (`pipeline.yml`) calls the gate with these exact arguments and checks these exact exit codes — neither changes.

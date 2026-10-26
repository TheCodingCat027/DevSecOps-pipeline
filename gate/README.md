# Gate

**Owner:** P4  
**Status:** Stub (Phase 1) — P4 replaces the internal logic in Phase 4  
**Interface:** See [`contracts/gate-interface.md`](../contracts/gate-interface.md) (frozen)

## Purpose

The policy gate reads all stage SARIF reports, normalizes findings, applies the security policy (`security-policy.yaml`), and decides whether deployment is permitted.

## Phase 1 Stub Behavior

The stub gate:
1. Validates all `*.sarif` files in `--reports` against `contracts/validate.py` (exits 2 on any failure)
2. Validates the policy file against `contracts/policy.schema.json` (exits 2 on failure)
3. Counts findings by severity and writes `gate-result.json` + `findings.json`
4. **Always passes (exit 0)** — unless `GATE_FORCE_FAIL=1` is set (demo mode)

## Interface (Frozen)

```
python gate/run_gate.py --reports <dir> --policy <file> --out <dir>

Exit codes:
  0  policy satisfied (or mode: audit)    → deploy MAY proceed
  1  policy violated                      → deploy MUST NOT run
  2  internal error (bad SARIF/policy)    → deploy MUST NOT run

Outputs:
  <out>/gate-result.json   — decision, counts, violations[], waivers_applied[]
  <out>/findings.json      — normalized findings array (per finding.schema.json)
```

## What P4 Will Implement

P4 replaces only the **body** of `run_gate.py`. The CLI arguments, exit codes, and output file schemas remain frozen. The real gate will:

1. Extract and normalize findings via `contracts.validate.extract_findings()`
2. Apply waivers from `security-policy.yaml`
3. Evaluate severity thresholds per category
4. Emit structured violations in `gate-result.json`
5. Exit 1 if any threshold is exceeded (in `enforce` mode)

## Demo: Force a Policy Failure

```bash
GATE_FORCE_FAIL=1 python gate/run_gate.py --reports reports/ --policy security-policy.yaml --out gate-out/
echo "Exit code: $?"  # → 1 (DEPLOY BLOCKED)
```

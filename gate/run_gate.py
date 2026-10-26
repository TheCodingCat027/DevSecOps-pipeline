#!/usr/bin/env python3
"""
gate/run_gate.py — STUB policy gate for Phase 1.

Interface: see contracts/gate-interface.md (frozen).

This stub:
- Validates every *.sarif in --reports using contracts/validate.py
- Validates the policy file against contracts/policy.schema.json
- Counts findings by severity and writes gate-result.json + findings.json
- Always exits 0 (pass) UNLESS GATE_FORCE_FAIL=1 is set (for demo purposes)

P4 replaces the policy evaluation logic in Phase 4 without changing the
CLI interface, exit codes, or output schemas.

Usage:
    python gate/run_gate.py --reports <dir> --policy <file> --out <dir>

Exit codes:
    0  policy satisfied (or mode: audit) — deploy MAY proceed
    1  policy violated — deploy MUST NOT run
    2  internal error (invalid SARIF, invalid policy) — deploy MUST NOT run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Locate contracts module
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(_REPO_ROOT))

try:
    from contracts.validate import (
        extract_findings,
        validate_policy_file,
        validate_sarif_file,
    )
except ImportError as exc:
    print(f"[gate] ERROR: Could not import contracts.validate: {exc}", file=sys.stderr)
    sys.exit(2)


def _load_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        print("[gate] ERROR: PyYAML not installed. Run: pip install PyYAML==6.0.2", file=sys.stderr)
        sys.exit(2)


def _missing_stage_reports(reports_dir: Path) -> list[str]:
    stages_path = _REPO_ROOT / "stages" / "stages.json"
    if not stages_path.is_file():
        return []

    with open(stages_path, encoding="utf-8") as f:
        stages_data = json.load(f)

    return [
        stage["name"]
        for stage in stages_data.get("stages", [])
        if stage.get("enabled", True)
        and not (reports_dir / f'{stage["name"]}.sarif').is_file()
    ]


# ---------------------------------------------------------------------------
# Main gate logic
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_gate.py",
        description="DevSecOps Pipeline — stub security policy gate (Phase 1)",
    )
    parser.add_argument("--reports", required=True, metavar="DIR",
                        help="Directory containing *.sarif files from all stages")
    parser.add_argument("--policy", required=True, metavar="FILE",
                        help="Path to security-policy.yaml")
    parser.add_argument("--out", required=True, metavar="DIR",
                        help="Directory to write gate-result.json and findings.json")
    args = parser.parse_args(argv)

    reports_dir = Path(args.reports)
    policy_path = Path(args.policy)
    out_dir = Path(args.out)

    print("[stub gate] real policy evaluation arrives in Phase 4", file=sys.stderr)
    print(f"[gate] Reports dir: {reports_dir}", file=sys.stderr)
    print(f"[gate] Policy file: {policy_path}", file=sys.stderr)

    # --- Validate paths ---
    if not reports_dir.is_dir():
        print(f"[gate] ERROR: reports directory not found: {reports_dir}", file=sys.stderr)
        return 2
    if not policy_path.is_file():
        print(f"[gate] ERROR: policy file not found: {policy_path}", file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Step 1: Validate policy ---
    print("[gate] Validating policy...", file=sys.stderr)
    policy_errors = validate_policy_file(policy_path)
    if policy_errors:
        print("[gate] ERROR: policy file is invalid:", file=sys.stderr)
        for e in policy_errors:
            print(f"  - {e}", file=sys.stderr)
        _write_gate_result(out_dir, "error", "unknown", {}, ["Policy file failed validation"], [])
        return 2

    yaml = _load_yaml()
    with open(policy_path, encoding="utf-8") as f:
        policy = yaml.safe_load(f)
    mode = policy.get("mode", "enforce")

    # --- Step 2: Validate each SARIF and collect findings ---
    sarif_files = sorted(reports_dir.glob("*.sarif"))
    missing_stages = _missing_stage_reports(reports_dir)
    if missing_stages or not sarif_files:
        violations = []
        if missing_stages:
            violations.append(f"Missing stage reports: {', '.join(missing_stages)}")
        if not sarif_files:
            violations.append("No SARIF reports found in reports directory")
        print("[gate] ERROR: " + "; ".join(violations), file=sys.stderr)
        _write_gate_result(out_dir, "error", mode, {}, violations, [])
        return 2

    all_findings: list[dict] = []
    sarif_errors: list[str] = []

    for sarif_path in sarif_files:
        print(f"[gate] Validating {sarif_path.name}...", file=sys.stderr)
        errors = validate_sarif_file(sarif_path)
        if errors:
            sarif_errors.append(f"{sarif_path.name}: {'; '.join(errors)}")
        else:
            try:
                with open(sarif_path, encoding="utf-8") as f:
                    sarif_dict = json.load(f)
                stage_name = sarif_path.stem  # e.g. "secrets" from "secrets.sarif"
                findings = extract_findings(sarif_dict)
                # Override stage field with actual stage name
                for finding in findings:
                    finding["stage"] = stage_name
                all_findings.extend(findings)
            except Exception as exc:
                sarif_errors.append(f"{sarif_path.name}: {exc}")

    if sarif_errors:
        print("[gate] ERROR: SARIF validation failures:", file=sys.stderr)
        for e in sarif_errors:
            print(f"  - {e}", file=sys.stderr)
        _write_gate_result(
            out_dir,
            "error",
            mode,
            {},
            [f"SARIF validation failed: {e}" for e in sarif_errors],
            [],
        )
        return 2

    # --- Step 3: Count findings by severity ---
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "total": 0}
    for finding in all_findings:
        sev = finding.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
        counts["total"] += 1

    print(f"[gate] Finding counts: {counts}", file=sys.stderr)

    # --- Step 4: Write findings.json ---
    findings_path = out_dir / "findings.json"
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)
    print(f"[gate] Wrote {findings_path}", file=sys.stderr)

    # --- Step 5: Stub policy decision ---
    # GATE_FORCE_FAIL=1 simulates a policy violation for demo/testing
    force_fail = os.environ.get("GATE_FORCE_FAIL", "").strip() == "1"
    if force_fail:
        print("[gate] GATE_FORCE_FAIL=1 set — simulating policy violation", file=sys.stderr)
        decision = "fail"
        violations = ["[stub] GATE_FORCE_FAIL=1: simulated policy violation for demo purposes"]
        exit_code = 1
    else:
        decision = "pass"
        violations = []
        exit_code = 0

    _write_gate_result(out_dir, decision, mode, counts, violations, waivers_applied=[])

    print(f"[gate] Decision: {decision.upper()}", file=sys.stderr)
    return exit_code


def _write_gate_result(
    out_dir: Path,
    decision: str,
    mode: str,
    counts: dict,
    violations: list[str],
    waivers_applied: list,
    **kwargs,
) -> None:
    """Write gate-result.json to the output directory."""
    result = {
        "decision": decision,
        "mode": mode,
        "counts": counts or {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "total": 0},
        "violations": violations,
        "waivers_applied": waivers_applied,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **kwargs,
    }
    out_path = out_dir / "gate-result.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[gate] Wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())

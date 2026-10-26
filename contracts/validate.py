#!/usr/bin/env python3
"""
contracts/validate.py — SARIF and policy validator for the DevSecOps pipeline.

CLI:
    python contracts/validate.py <file-or-directory> [--stage NAME] [--json] [--policy FILE]

Exit codes:
    0  valid
    1  invalid (one or more errors found)
    2  usage error

Importable function (frozen contract — do not change signature):
    from contracts.validate import extract_findings
    findings: list[dict] = extract_findings(sarif_dict)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).parent.resolve()
_FINDING_SCHEMA_PATH = _THIS_DIR / "finding.schema.json"
_POLICY_SCHEMA_PATH = _THIS_DIR / "policy.schema.json"

# ---------------------------------------------------------------------------
# Lazy imports — keep top-level imports minimal so the module loads fast
# ---------------------------------------------------------------------------

def _load_jsonschema():
    try:
        import jsonschema
        from jsonschema import Draft202012Validator, ValidationError
        return jsonschema, Draft202012Validator, ValidationError
    except ImportError:
        print(
            "ERROR: jsonschema is not installed. Run: pip install jsonschema==4.23.0",
            file=sys.stderr,
        )
        sys.exit(2)


def _load_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        print(
            "ERROR: PyYAML is not installed. Run: pip install PyYAML==6.0.2",
            file=sys.stderr,
        )
        sys.exit(2)


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

def _load_schema(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# SARIF profile validation
# ---------------------------------------------------------------------------

VALID_SARIF_VERSION = "2.1.0"
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_CATEGORIES = {"secret", "sast", "sca", "iac", "container", "dast"}
VALID_LEVELS = {"error", "warning", "note"}

# Stages whose category property must be one of a specific set
STAGE_CATEGORY_MAP: dict[str, set[str]] = {
    "secrets":   {"secret"},
    "sast":      {"sast"},
    "sca":       {"sca"},
    "iac":       {"iac"},
    "container": {"container", "sca"},
    "sbom":      set(),  # SBOM results should be empty; no category check needed
    "dast":      {"dast"},
}


def validate_sarif(sarif_dict: dict, stage: str | None = None) -> list[str]:
    """
    Validate a parsed SARIF dict against the project's SARIF profile.

    Returns a list of error strings (empty list means valid).
    """
    errors: list[str] = []

    # --- top-level version ---
    version = sarif_dict.get("version")
    if version != VALID_SARIF_VERSION:
        errors.append(
            f"runs: SARIF version must be '2.1.0', got '{version}'"
        )

    # --- runs array ---
    runs = sarif_dict.get("runs")
    if not isinstance(runs, list):
        errors.append("runs: must be an array")
        return errors  # can't proceed without runs
    if len(runs) != 1:
        errors.append(f"runs: must contain exactly 1 run, got {len(runs)}")
        if not runs:
            return errors

    run = runs[0]

    # --- tool.driver ---
    tool = run.get("tool", {})
    driver = tool.get("driver", {})

    driver_name = driver.get("name")
    if not driver_name or not isinstance(driver_name, str) or not driver_name.strip():
        errors.append("runs[0].tool.driver.name: required and must be a non-empty string")

    driver_version = driver.get("version")
    if not driver_version or not isinstance(driver_version, str) or not driver_version.strip():
        errors.append("runs[0].tool.driver.version: required and must be a non-empty string")

    # --- results ---
    results = run.get("results", [])
    if not isinstance(results, list):
        errors.append("runs[0].results: must be an array")
        return errors

    for i, result in enumerate(results):
        prefix = f"runs[0].results[{i}]"

        # ruleId
        rule_id = result.get("ruleId")
        if not rule_id or not isinstance(rule_id, str):
            errors.append(f"{prefix}.ruleId: required and must be a non-empty string")

        # level
        level = result.get("level")
        if level not in VALID_LEVELS:
            errors.append(
                f"{prefix}.level: must be one of {sorted(VALID_LEVELS)}, got '{level}'"
            )

        # message.text
        msg = result.get("message", {})
        if not isinstance(msg, dict) or not msg.get("text"):
            errors.append(f"{prefix}.message.text: required and must be a non-empty string")

        # locations
        locations = result.get("locations")
        if not isinstance(locations, list) or len(locations) == 0:
            errors.append(f"{prefix}.locations: must be a non-empty array")
        else:
            loc0 = locations[0]
            phys = loc0.get("physicalLocation", {})
            art = phys.get("artifactLocation", {})
            uri = art.get("uri")
            if not uri or not isinstance(uri, str):
                errors.append(
                    f"{prefix}.locations[0].physicalLocation.artifactLocation.uri: "
                    "required and must be a non-empty string"
                )

        # properties.severity
        props = result.get("properties", {})
        severity = props.get("severity")
        if severity not in VALID_SEVERITIES:
            errors.append(
                f"{prefix}.properties.severity: must be one of "
                f"{sorted(VALID_SEVERITIES)}, got '{severity}'"
            )

        # properties.category
        category = props.get("category")
        if category not in VALID_CATEGORIES:
            errors.append(
                f"{prefix}.properties.category: must be one of "
                f"{sorted(VALID_CATEGORIES)}, got '{category}'"
            )
        elif stage is not None:
            allowed = STAGE_CATEGORY_MAP.get(stage)
            if allowed is None:
                errors.append(f"Unknown stage name: '{stage}'")
            elif allowed and category not in allowed:
                errors.append(
                    f"{prefix}.properties.category: for stage '{stage}', "
                    f"category must be one of {sorted(allowed)}, got '{category}'"
                )

    return errors


# ---------------------------------------------------------------------------
# Finding extraction (frozen public API)
# ---------------------------------------------------------------------------

def extract_findings(sarif_dict: dict) -> list[dict]:
    """
    Extract normalized findings from a parsed SARIF 2.1.0 dict.

    This function is part of the frozen contract (v1.0.0).
    P4's gate imports this function directly.

    Args:
        sarif_dict: A Python dict representing a parsed SARIF JSON object.

    Returns:
        A list of finding dicts. Each dict has all required finding.schema.json
        fields populated; optional fields are included only when present in the SARIF.
        Does NOT validate the findings against finding.schema.json.
    """
    runs = sarif_dict.get("runs", [])
    if not runs:
        return []

    run = runs[0]
    tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
    results = run.get("results", [])

    findings: list[dict] = []

    for result in results:
        props = result.get("properties", {})
        locations = result.get("locations", [])
        loc0 = locations[0] if locations else {}
        phys = loc0.get("physicalLocation", {})
        art = phys.get("artifactLocation", {})
        region = phys.get("region", {})

        category = props.get("category", "sast")

        # Map category → stage (category uses singular forms like 'secret',
        # stage uses plural/exact forms like 'secrets').
        # The gate overrides this with the actual stage name from the SARIF filename.
        _category_to_stage = {
            "secret": "secrets",
            "sast": "sast",
            "sca": "sca",
            "iac": "iac",
            "container": "container",
            "dast": "dast",
        }
        stage_name = _category_to_stage.get(category, category)

        finding: dict[str, Any] = {
            "tool": tool_name,
            "stage": stage_name,   # will be overridden by caller with the actual stage name
            "category": category,
            "rule_id": result.get("ruleId", ""),
            "severity": props.get("severity", "Low"),
            "file": art.get("uri", ""),
            "line": region.get("startLine", 0),
            "description": result.get("message", {}).get("text", ""),
            "fix": props.get("fix", None),
        }

        # Optional fields — only include if present
        for opt in (
            "cve_id", "cwe", "package", "installed_version", "fixed_version",
            "fix_available", "confidence", "help_uri", "raw_severity",
        ):
            if opt in props:
                finding[opt] = props[opt]

        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Policy validation
# ---------------------------------------------------------------------------

def validate_policy_file(policy_path: Path) -> list[str]:
    """Validate a security-policy.yaml against policy.schema.json."""
    yaml = _load_yaml()
    jsonschema, Draft202012Validator, ValidationError = _load_jsonschema()

    errors: list[str] = []

    try:
        with open(policy_path, encoding="utf-8") as f:
            policy = yaml.safe_load(f)
    except Exception as exc:
        return [f"Could not parse YAML: {exc}"]

    if not isinstance(policy, dict):
        return ["Policy file must be a YAML mapping (dict) at the top level"]

    schema = _load_schema(_POLICY_SCHEMA_PATH)
    validator = Draft202012Validator(schema)
    for ve in validator.iter_errors(policy):
        path = "/" + "/".join(str(p) for p in ve.absolute_path) if ve.absolute_path else "/"
        errors.append(f"{path}: {ve.message}")

    return errors


# ---------------------------------------------------------------------------
# Single SARIF file validation
# ---------------------------------------------------------------------------

def validate_sarif_file(
    sarif_path: Path,
    stage: str | None = None,
    validate_findings: bool = True,
) -> list[str]:
    """Validate a SARIF file at the given path."""
    errors: list[str] = []

    # Parse JSON
    try:
        with open(sarif_path, encoding="utf-8") as f:
            sarif_dict = json.load(f)
    except json.JSONDecodeError as exc:
        return [f"JSON parse error: {exc}"]
    except OSError as exc:
        return [f"Cannot open file: {exc}"]

    # Profile validation
    profile_errors = validate_sarif(sarif_dict, stage=stage)
    errors.extend(profile_errors)

    # Finding-level schema validation (only when profile passes)
    if not profile_errors and validate_findings:
        jsonschema, Draft202012Validator, ValidationError = _load_jsonschema()
        finding_schema = _load_schema(_FINDING_SCHEMA_PATH)
        validator = Draft202012Validator(finding_schema)

        findings = extract_findings(sarif_dict)
        for i, finding in enumerate(findings):
            for ve in validator.iter_errors(finding):
                path = "/" + "/".join(str(p) for p in ve.absolute_path) if ve.absolute_path else "/"
                errors.append(f"finding[{i}]{path}: {ve.message}")

    return errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_result(path: str, errors: list[str], valid: bool) -> dict:
    return {"path": path, "valid": valid, "errors": errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="validate.py",
        description="Validate SARIF files and security policy against DevSecOps pipeline contracts.",
    )
    parser.add_argument(
        "target",
        help="Path to a SARIF file, a directory of SARIF files, or (with --policy) a policy YAML.",
    )
    parser.add_argument(
        "--stage",
        metavar="NAME",
        help="Stage name (secrets|sast|sca|iac|container|sbom|dast). "
             "Enables stage-specific category checks and filename validation.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON result to stdout.",
    )
    parser.add_argument(
        "--policy",
        metavar="FILE",
        help="Validate the given security-policy.yaml instead of a SARIF file.",
    )
    args = parser.parse_args(argv)

    # --- Policy mode ---
    if args.policy:
        policy_path = Path(args.policy)
        if not policy_path.is_file():
            print(f"ERROR: policy file not found: {policy_path}", file=sys.stderr)
            return 2
        errors = validate_policy_file(policy_path)
        result = _build_result(str(policy_path), errors, valid=not errors)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if errors:
                print(f"INVALID: {policy_path}")
                for e in errors:
                    print(f"  - {e}")
            else:
                print(f"VALID: {policy_path}")
        return 1 if errors else 0

    target = Path(args.target)
    if not target.exists():
        print(f"ERROR: path not found: {target}", file=sys.stderr)
        return 2

    # --- Gather files ---
    if target.is_dir():
        sarif_files = sorted(target.glob("*.sarif"))
        if not sarif_files:
            print(f"WARNING: no *.sarif files found in {target}", file=sys.stderr)
            if args.json:
                print(json.dumps({"files": [], "all_valid": True}))
            return 0
    else:
        sarif_files = [target]

    # --- Validate each file ---
    results = []
    all_valid = True

    for sarif_path in sarif_files:
        # Stage-specific filename check
        stage = args.stage
        if stage and sarif_path.name != f"{stage}.sarif":
            file_errors = [
                f"Filename must be '{stage}.sarif' for stage '{stage}', got '{sarif_path.name}'"
            ]
        else:
            file_errors = validate_sarif_file(sarif_path, stage=stage)

        valid = not file_errors
        if not valid:
            all_valid = False

        results.append(_build_result(str(sarif_path), file_errors, valid))

    # --- Output ---
    if args.json:
        print(json.dumps({"files": results, "all_valid": all_valid}, indent=2))
    else:
        for r in results:
            if r["valid"]:
                print(f"VALID:   {r['path']}")
            else:
                print(f"INVALID: {r['path']}")
                for e in r["errors"]:
                    print(f"  - {e}")

    return 0 if all_valid else 1


if __name__ == "__main__":
    sys.exit(main())

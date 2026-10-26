"""
Pytest tests for contracts/validate.py

Coverage:
- Every valid sample in contracts/samples/ passes
- Every file in contracts/samples/invalid/ fails
- The baseline security-policy.yaml passes
- A broken policy fails
- The --stage category check works
- Exit codes are correct
- extract_findings returns the correct data
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent.resolve()
CONTRACTS_DIR = REPO_ROOT / "contracts"
SAMPLES_DIR = CONTRACTS_DIR / "samples"
INVALID_DIR = SAMPLES_DIR / "invalid"
VALIDATE_PY = CONTRACTS_DIR / "validate.py"
POLICY_FILE = REPO_ROOT / "security-policy.yaml"

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def run_validator(*args: str) -> subprocess.CompletedProcess:
    """Run validate.py with the given arguments and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(VALIDATE_PY), *args],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# Test: valid samples
# ---------------------------------------------------------------------------

VALID_STAGES = ["secrets", "sast", "sca", "iac", "container", "sbom", "dast"]


@pytest.mark.parametrize("stage", VALID_STAGES)
def test_valid_sample_passes(stage: str):
    """Every valid sample SARIF should pass validation."""
    sarif_file = SAMPLES_DIR / f"{stage}.sarif"
    assert sarif_file.exists(), f"Sample file missing: {sarif_file}"
    result = run_validator(str(sarif_file))
    assert result.returncode == 0, (
        f"Valid sample {stage}.sarif failed validation.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "VALID" in result.stdout


@pytest.mark.parametrize("stage", VALID_STAGES)
def test_valid_sample_with_stage_flag_passes(stage: str):
    """Valid samples should also pass with the --stage flag."""
    sarif_file = SAMPLES_DIR / f"{stage}.sarif"
    result = run_validator(str(sarif_file), "--stage", stage)
    assert result.returncode == 0, (
        f"Valid sample {stage}.sarif with --stage {stage} failed.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_validate_entire_samples_directory():
    """Running validate.py on the samples directory should pass all valid samples."""
    result = run_validator(str(SAMPLES_DIR))
    assert result.returncode == 0, (
        f"Samples directory validation failed.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Test: invalid samples
# ---------------------------------------------------------------------------

INVALID_SAMPLES = [
    ("missing-driver-version.sarif", "driver.version"),
    ("bad-severity.sarif", "severity"),
    ("missing-rule-id.sarif", "ruleId"),
    ("wrong-sarif-version.sarif", "version"),
    ("not-json.sarif", "JSON"),
    ("missing-location.sarif", "locations"),
]


@pytest.mark.parametrize("filename,expected_error_fragment", INVALID_SAMPLES)
def test_invalid_sample_fails(filename: str, expected_error_fragment: str):
    """Every file in samples/invalid/ should fail with a relevant error message."""
    sarif_file = INVALID_DIR / filename
    assert sarif_file.exists(), f"Invalid sample missing: {sarif_file}"
    result = run_validator(str(sarif_file))
    assert result.returncode == 1, (
        f"Invalid sample {filename} should exit 1, got {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    combined_output = result.stdout + result.stderr
    assert expected_error_fragment.lower() in combined_output.lower(), (
        f"Expected error fragment '{expected_error_fragment}' not found in output for {filename}.\n"
        f"stdout: {result.stdout}"
    )


# ---------------------------------------------------------------------------
# Test: policy validation
# ---------------------------------------------------------------------------

def test_baseline_policy_passes():
    """The baseline security-policy.yaml must validate successfully."""
    assert POLICY_FILE.exists(), f"Policy file missing: {POLICY_FILE}"
    result = run_validator(str(POLICY_FILE), "--policy", str(POLICY_FILE))
    assert result.returncode == 0, (
        f"Baseline policy failed validation.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "VALID" in result.stdout


def test_broken_policy_fails(tmp_path: Path):
    """A policy file with missing required fields should fail."""
    broken_policy = tmp_path / "broken-policy.yaml"
    broken_policy.write_text(
        "version: 2\nmode: enforce\n",  # version must be 1 (const), missing required fields
        encoding="utf-8",
    )
    result = run_validator(str(broken_policy), "--policy", str(broken_policy))
    assert result.returncode == 1, (
        f"Broken policy should exit 1, got {result.returncode}.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_policy_invalid_mode_fails(tmp_path: Path):
    """A policy file with an invalid mode value should fail."""
    bad_mode_policy = tmp_path / "bad-mode.yaml"
    bad_mode_policy.write_text(
        "version: 1\nmode: block\n"
        "secrets:\n  max_allowed: 0\n"
        "vulnerabilities:\n  critical: 0\n  high: 3\n  medium: null\n  low: null\n"
        "container:\n  must_run_as_non_root: true\n  banned_base_tags: []\n"
        "waivers: []\n",
        encoding="utf-8",
    )
    result = run_validator(str(bad_mode_policy), "--policy", str(bad_mode_policy))
    assert result.returncode == 1


# ---------------------------------------------------------------------------
# Test: --stage category check
# ---------------------------------------------------------------------------

def test_wrong_stage_category_fails(tmp_path: Path):
    """A SARIF with category 'sast' validated with --stage secrets should fail."""
    # Build a valid SARIF but with wrong category for the stage
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "version": "1.0.0"}},
            "results": [{
                "ruleId": "rule1",
                "level": "error",
                "message": {"text": "issue"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}],
                "properties": {"severity": "High", "category": "sast"},
            }],
        }],
    }
    sarif_file = tmp_path / "secrets.sarif"
    sarif_file.write_text(json.dumps(sarif), encoding="utf-8")
    result = run_validator(str(sarif_file), "--stage", "secrets")
    assert result.returncode == 1, "Expected failure for wrong category in --stage check"
    assert "category" in result.stdout.lower()


def test_correct_stage_category_passes(tmp_path: Path):
    """A SARIF with category 'secret' validated with --stage secrets should pass."""
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks", "version": "8.18.4"}},
            "results": [{
                "ruleId": "aws-access-token",
                "level": "error",
                "message": {"text": "AWS key found"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "config.py"}}}],
                "properties": {"severity": "Critical", "category": "secret"},
            }],
        }],
    }
    sarif_file = tmp_path / "secrets.sarif"
    sarif_file.write_text(json.dumps(sarif), encoding="utf-8")
    result = run_validator(str(sarif_file), "--stage", "secrets")
    assert result.returncode == 0


# ---------------------------------------------------------------------------
# Test: JSON output mode
# ---------------------------------------------------------------------------

def test_json_output_valid():
    """--json flag should produce parseable JSON output for a valid file."""
    sarif_file = SAMPLES_DIR / "secrets.sarif"
    result = run_validator(str(sarif_file), "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "all_valid" in data or "valid" in data


def test_json_output_invalid():
    """--json flag should produce parseable JSON output for an invalid file."""
    sarif_file = INVALID_DIR / "bad-severity.sarif"
    result = run_validator(str(sarif_file), "--json")
    assert result.returncode == 1
    data = json.loads(result.stdout)
    # Either a single result or a files list
    if "files" in data:
        assert not data["all_valid"]
    else:
        assert not data.get("valid", True)


# ---------------------------------------------------------------------------
# Test: exit codes
# ---------------------------------------------------------------------------

def test_exit_code_valid():
    result = run_validator(str(SAMPLES_DIR / "sast.sarif"))
    assert result.returncode == 0


def test_exit_code_invalid():
    result = run_validator(str(INVALID_DIR / "wrong-sarif-version.sarif"))
    assert result.returncode == 1


def test_exit_code_nonexistent_file():
    result = run_validator("nonexistent_file_xyz.sarif")
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# Test: extract_findings
# ---------------------------------------------------------------------------

def test_extract_findings_returns_list():
    """extract_findings should return a list of dicts for a non-empty SARIF."""
    from contracts.validate import extract_findings  # noqa: PLC0415

    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks", "version": "8.18.4"}},
            "results": [{
                "ruleId": "aws-access-token",
                "level": "error",
                "message": {"text": "AWS key found"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "config.py"},
                        "region": {"startLine": 5},
                    }
                }],
                "properties": {
                    "severity": "Critical",
                    "category": "secret",
                    "raw_severity": "aws-access-token",
                },
            }],
        }],
    }
    findings = extract_findings(sarif)
    assert isinstance(findings, list)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "gitleaks"
    assert f["rule_id"] == "aws-access-token"
    assert f["severity"] == "Critical"
    assert f["file"] == "config.py"
    assert f["line"] == 5
    assert f["raw_severity"] == "aws-access-token"


def test_extract_findings_empty_results():
    """extract_findings should return an empty list for a SARIF with no results."""
    from contracts.validate import extract_findings  # noqa: PLC0415

    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "syft", "version": "1.5.0"}},
            "results": [],
        }],
    }
    findings = extract_findings(sarif)
    assert findings == []


def test_extract_findings_defaults():
    """extract_findings should default line to 0 and fix to None when absent."""
    from contracts.validate import extract_findings  # noqa: PLC0415

    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "tool", "version": "1.0"}},
            "results": [{
                "ruleId": "r1",
                "level": "warning",
                "message": {"text": "issue"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file.py"}}}],
                "properties": {"severity": "Low", "category": "sast"},
            }],
        }],
    }
    findings = extract_findings(sarif)
    assert findings[0]["line"] == 0
    assert findings[0]["fix"] is None

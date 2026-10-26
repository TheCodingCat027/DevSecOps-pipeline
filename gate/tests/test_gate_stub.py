import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "gate" / "run_gate.py"
POLICY = REPO_ROOT / "security-policy.yaml"
SAMPLES = REPO_ROOT / "contracts" / "samples"


def enabled_stage_names():
    with open(REPO_ROOT / "stages" / "stages.json", encoding="utf-8") as f:
        stages = json.load(f)["stages"]
    return [stage["name"] for stage in stages if stage.get("enabled", True)]


def run_gate(tmp_path, stages=None, env=None):
    reports = tmp_path / "reports"
    output = tmp_path / "out"
    reports.mkdir()
    for stage in enabled_stage_names() if stages is None else stages:
        shutil.copyfile(SAMPLES / f"{stage}.sarif", reports / f"{stage}.sarif")

    process_env = os.environ.copy()
    process_env.pop("GATE_FORCE_FAIL", None)
    if env:
        process_env.update(env)
    result = subprocess.run(
        [
            sys.executable,
            str(GATE),
            "--reports",
            str(reports),
            "--policy",
            str(POLICY),
            "--out",
            str(output),
        ],
        cwd=REPO_ROOT,
        env=process_env,
        capture_output=True,
        text=True,
    )
    gate_result = json.loads((output / "gate-result.json").read_text(encoding="utf-8"))
    return result, gate_result, reports


def test_all_enabled_stage_reports_pass(tmp_path):
    result, gate_result, _ = run_gate(tmp_path)

    assert result.returncode == 0
    assert gate_result["decision"] == "pass"


def test_force_fail_returns_one(tmp_path):
    result, gate_result, _ = run_gate(tmp_path, env={"GATE_FORCE_FAIL": "1"})

    assert result.returncode == 1
    assert gate_result["decision"] == "fail"


def test_missing_stage_report_returns_two(tmp_path):
    stages = [stage for stage in enabled_stage_names() if stage != "sast"]
    result, gate_result, _ = run_gate(tmp_path, stages=stages)

    assert result.returncode == 2
    assert gate_result["decision"] == "error"
    assert any("sast" in violation for violation in gate_result["violations"])


def test_empty_reports_directory_returns_two(tmp_path):
    result, gate_result, reports = run_gate(tmp_path, stages=[])

    assert result.returncode == 2
    assert gate_result["decision"] == "error"
    assert not list(reports.glob("*.sarif"))


def test_invalid_sarif_returns_two(tmp_path):
    result, gate_result, reports = run_gate(tmp_path)
    shutil.copyfile(
        SAMPLES / "invalid" / "bad-severity.sarif",
        reports / "sast.sarif",
    )

    output = tmp_path / "out-invalid"
    process_env = os.environ.copy()
    process_env.pop("GATE_FORCE_FAIL", None)
    result = subprocess.run(
        [
            sys.executable,
            str(GATE),
            "--reports",
            str(reports),
            "--policy",
            str(POLICY),
            "--out",
            str(output),
        ],
        cwd=REPO_ROOT,
        env=process_env,
        capture_output=True,
        text=True,
    )
    gate_result = json.loads((output / "gate-result.json").read_text(encoding="utf-8"))

    assert result.returncode == 2
    assert gate_result["decision"] == "error"

"""
demo-app/tests/test_seeded_vulns.py

Drift-protection test: ensures every vulnerability listed in seeded-vulnerabilities.json
exists at the stated file and line, and that the expected pattern is present.

If a code refactor moves a seeded vulnerability to a different line, this test fails,
alerting the team to update the JSON and Markdown ground-truth files before running
Phase 5 evaluation.

Run with: pytest demo-app/tests/test_seeded_vulns.py
"""

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent.resolve()
SEEDED_JSON = REPO_ROOT / "demo-app" / "seeded-vulnerabilities.json"

# Pattern fragments to search for on the expected line.
# Key: vulnerability ID, Value: regex pattern expected on that line.
PATTERNS = {
    "V1a": r"AKIAIOSFODNN7FAKEKEY",
    "V1b": r"FAKESECRETKEY",
    "V2":  r"name\s*=.*\+.*name.*\+",     # string concat SQL query
    "V3a": r"Flask==1\.1\.\d+",
    "V3b": r"Jinja2==2\.11\.\d+",
    "V3c": r"Werkzeug==1\.0\.\d+",
    "V4":  r"FROM python:",               # file-level, check FROM line
    "V5":  r"FROM python:",               # same FROM line - unpinned tag
    "V6":  r"hashlib\.md5\(",
    "V7":  r"debug=True",
    "V8":  r"FROM python:",               # Dockerfile file-level check
}


def load_seeded_data():
    with open(SEEDED_JSON, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def seeded_data():
    return load_seeded_data()


def test_seeded_json_schema(seeded_data):
    """Verify the JSON has the expected top-level structure."""
    assert "schema_version" in seeded_data
    assert seeded_data["schema_version"] == 1
    assert "vulnerabilities" in seeded_data
    assert isinstance(seeded_data["vulnerabilities"], list)
    assert len(seeded_data["vulnerabilities"]) > 0


@pytest.mark.parametrize("vuln", load_seeded_data()["vulnerabilities"])
def test_seeded_file_exists(vuln):
    """Every listed file must exist in the repository."""
    fpath = REPO_ROOT / vuln["file"]
    assert fpath.exists(), (
        f"[{vuln['id']}] Listed file does not exist: {vuln['file']}\n"
        "Update seeded-vulnerabilities.json if the file was moved."
    )


@pytest.mark.parametrize("vuln", load_seeded_data()["vulnerabilities"])
def test_seeded_pattern_at_line(vuln):
    """The expected pattern must appear at or near the listed line number."""
    vid = vuln["id"]
    pattern = PATTERNS.get(vid)
    if pattern is None:
        pytest.skip(f"No pattern defined for {vid}")

    fpath = REPO_ROOT / vuln["file"]
    lines = fpath.read_text(encoding="utf-8").splitlines()
    line_no = vuln["line"]

    # Check a window of ±5 lines to be tolerant of minor whitespace changes
    window_start = max(0, line_no - 6)
    window_end = min(len(lines), line_no + 5)
    window = "\n".join(lines[window_start:window_end])

    assert re.search(pattern, window, re.IGNORECASE), (
        f"[{vid}] Pattern '{pattern}' not found near line {line_no} "
        f"in {vuln['file']} (searched lines {window_start+1}–{window_end}).\n"
        f"Window content:\n{window}\n\n"
        "If the code was refactored, update demo-app/seeded-vulnerabilities.json "
        "and demo-app/seeded-vulnerabilities.md with the new line number."
    )

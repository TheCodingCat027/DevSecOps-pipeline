#!/usr/bin/env python3
"""stages/secrets/to_sarif.py - convert raw Gitleaks JSON reports to contract-valid SARIF.

Standard library only.  Called by run.sh; not meant to be run by hand.

Responsibilities
  * map every finding to the SARIF profile in contracts/sarif-profile.md
  * severity per contracts/severity-map.md (Gitleaks has no severity: cloud-provider
    credentials -> Critical, everything else -> High)
  * NEVER copy a secret value, match text, snippet, author, e-mail or commit message
    into the output: only rule id, file, line and a short commit id are used
  * normalise paths to repo-relative URIs
  * merge the working-tree scan and the (optional) history scan, deduplicate
  * deterministic output (stable ordering, no timestamps)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

# Explicit, documented list of rule ids that are cloud-provider credentials
# (contracts/severity-map.md: "AWS, GCP, Azure credentials -> Critical").
CLOUD_PROVIDER_RULES = frozenset({
    "aws-access-token",
    "aws-secret-access-key",                      # custom rule in gitleaks.toml
    "aws-amazon-bedrock-api-key-long-lived",
    "aws-amazon-bedrock-api-key-short-lived",
    "gcp-api-key",
    "azure-ad-client-secret",
})

FIX_TEXT = (
    "Rotate the credential immediately, remove it from the source and from git history "
    "(e.g. git filter-repo), and load it from a secrets manager or an environment variable."
)

# Heuristic confidence: provider-specific patterns are high, generic / low-entropy
# patterns are medium (see README "Severity and confidence").
MEDIUM_CONFIDENCE_RULES = frozenset({"flask-hardcoded-secret-key"})


def severity_for(rule_id: str) -> str:
    return "Critical" if rule_id in CLOUD_PROVIDER_RULES else "High"


def confidence_for(rule_id: str) -> str:
    if rule_id.startswith("generic-") or rule_id in MEDIUM_CONFIDENCE_RULES:
        return "medium"
    return "high"


def level_for(severity: str) -> str:
    return {"Critical": "error", "High": "error", "Medium": "warning"}.get(severity, "note")


def load_report(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array of findings")
    return data


def to_uri(abs_path: Path, base: Path) -> str:
    """Repo-relative POSIX path; never absolute."""
    try:
        rel = abs_path.relative_to(base)
    except ValueError:
        rel = Path(os.path.relpath(abs_path, base))
    return rel.as_posix()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree-report", required=True)
    ap.add_argument("--history-report")
    ap.add_argument("--git-top")
    ap.add_argument("--target", required=True)
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--tool-version", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if not args.tool_version.strip():
        print("[to_sarif] ERROR: empty tool version", file=sys.stderr)
        return 1

    target = Path(args.target).resolve()
    repo_root = Path(args.repo_root).resolve()
    scan_dir = target if target.is_dir() else target.parent
    # URIs are relative to the repo root when the target lives inside it, otherwise
    # relative to the scan directory (never absolute, never leaking host paths).
    try:
        scan_dir.relative_to(repo_root)
        base = repo_root
    except ValueError:
        base = scan_dir

    def in_target(p: Path) -> bool:
        if target.is_file():
            return p == target
        try:
            p.relative_to(target)
            return True
        except ValueError:
            return False

    # key -> record.  key = (rule, uri, line)
    found: dict[tuple[str, str, int], dict] = {}
    descriptions: dict[str, str] = {}

    # --- working tree ------------------------------------------------------------
    for f in load_report(args.tree_report):
        rule = f.get("RuleID") or ""
        file_ = f.get("File") or ""
        if not rule or not file_:
            continue
        p = Path(file_)
        if not p.is_absolute():
            p = (Path.cwd() / p)
        p = p.resolve()
        if not in_target(p):
            continue
        line = int(f.get("StartLine") or 0)
        uri = to_uri(p, base)
        descriptions.setdefault(rule, f.get("Description") or rule)
        found[(rule, uri, line)] = {"rule": rule, "uri": uri, "line": line, "history_only": False,
                                    "commits": set()}

    # --- history -----------------------------------------------------------------
    if args.history_report:
        git_top = Path(args.git_top or ".").resolve()
        for f in load_report(args.history_report):
            rule = f.get("RuleID") or ""
            file_ = f.get("File") or ""
            if not rule or not file_:
                continue
            p = (git_top / file_).resolve()
            if not in_target(p):
                continue   # defence in depth: history scan must stay inside the target
            line = int(f.get("StartLine") or 0)
            uri = to_uri(p, base)
            descriptions.setdefault(rule, f.get("Description") or rule)
            commit = (f.get("Commit") or "")[:8]
            key = (rule, uri, line)
            rec = found.get(key)
            if rec is None:
                rec = found[key] = {"rule": rule, "uri": uri, "line": line,
                                    "history_only": True, "commits": set()}
            if rec["history_only"] and commit:
                rec["commits"].add(commit)

    # --- build SARIF ---------------------------------------------------------------
    results = []
    for (rule, uri, line), rec in sorted(found.items(), key=lambda kv: (kv[0][1], kv[0][2], kv[0][0])):
        sev = severity_for(rule)
        desc = descriptions.get(rule, rule)
        where = f"{uri}:{line}" if line else uri
        text = f"{desc.rstrip('.')} ({rule}) detected at {where}. The secret value is redacted from this report."
        if rec["history_only"]:
            commits = sorted(rec["commits"])
            shown = f" (first commit {commits[0]}, {len(commits)} commit(s))" if commits else ""
            text = (f"{desc.rstrip('.')} ({rule}) found in commit history only at {where}{shown}; "
                    "it is no longer in the working tree but remains retrievable from git history. "
                    "The secret value is redacted from this report.")
        region = {"startLine": line} if line > 0 else {}
        loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        if region:
            loc["physicalLocation"]["region"] = region
        results.append({
            "ruleId": rule,
            "level": level_for(sev),
            "message": {"text": text},
            "locations": [loc],
            "properties": {
                "severity": sev,
                "category": "secret",
                "raw_severity": rule,          # gitleaks has no severity; sample SARIF uses the rule id
                "fix": FIX_TEXT,
                "confidence": confidence_for(rule),
            },
        })

    rules = [{"id": r, "shortDescription": {"text": descriptions[r]}} for r in sorted(descriptions)
             if any(x["ruleId"] == r for x in results)]
    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "gitleaks",
                "version": args.tool_version.strip(),
                "informationUri": "https://github.com/gitleaks/gitleaks",
                "rules": rules,
            }},
            "results": results,
        }],
    }

    # --- atomic write ----------------------------------------------------------------
    out = Path(args.out)
    fd, tmp_name = tempfile.mkstemp(prefix=".secrets.sarif.", suffix=".tmp", dir=str(out.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, sort_keys=False)
            fh.write("\n")
        os.replace(tmp_name, out)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    print(f"[to_sarif] wrote {len(results)} result(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

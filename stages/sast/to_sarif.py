#!/usr/bin/env python3
"""stages/sast/to_sarif.py - convert a Semgrep JSON report to contract-valid SARIF.

Standard library only.  Called by run.sh.

  * severity per contracts/severity-map.md: ERROR -> High, WARNING -> Medium, INFO -> Low,
    anything else -> Low (default fallback); the original label goes to raw_severity
  * CWE id parsed from rule metadata / tags -> properties.cwe
  * rule `remediation` metadata -> properties.fix; rule `confidence` -> properties.confidence
  * repo-relative URIs, de-duplication, deterministic ordering, atomic write
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

SEVERITY_MAP = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
LEVEL_FOR = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}
CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
RULE_ID_RE = re.compile(r"^\s*-?\s*id:\s*([A-Za-z0-9_.\-]+)\s*$", re.MULTILINE)
MAX_TEXT = 600


def first_cwe(*candidates) -> str | None:
    for c in candidates:
        items = c if isinstance(c, list) else [c]
        for item in items:
            if isinstance(item, str):
                m = CWE_RE.search(item)
                if m:
                    return f"CWE-{int(m.group(1))}"
    return None


def clean(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"


def first_http(*candidates) -> str | None:
    for c in candidates:
        items = c if isinstance(c, list) else [c]
        for item in items:
            if isinstance(item, str) and re.match(r"^https?://\S+$", item):
                return item
    return None


def custom_rule_ids(rules_dir: str | None) -> set[str]:
    ids: set[str] = set()
    if not rules_dir:
        return ids
    for p in sorted(Path(rules_dir).glob("*.y*ml")):
        ids.update(RULE_ID_RE.findall(p.read_text(encoding="utf-8")))
    return ids


def normalise_rule_id(check_id: str, custom: set[str]) -> str:
    """Semgrep may prefix a local rule id with the dotted path of its directory."""
    for cid in custom:
        if check_id == cid or check_id.endswith("." + cid):
            return cid
    return check_id


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--custom-rules-dir")
    ap.add_argument("--custom-rules", default="1")
    ap.add_argument("--registry-packs", default="")
    ap.add_argument("--registry-applied", default="false")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.report, encoding="utf-8") as fh:
        report = json.load(fh)
    if not isinstance(report, dict) or "results" not in report:
        print("[to_sarif] ERROR: not a semgrep JSON report", file=sys.stderr)
        return 1
    version = str(report.get("version") or "").strip()
    if not version:
        print("[to_sarif] ERROR: semgrep report has no version", file=sys.stderr)
        return 1

    target = Path(args.target).resolve()
    repo_root = Path(args.repo_root).resolve()
    scan_dir = target if target.is_dir() else target.parent
    try:
        scan_dir.relative_to(repo_root)
        base = repo_root
    except ValueError:
        base = scan_dir

    custom = custom_rule_ids(args.custom_rules_dir)

    seen: dict[tuple[str, str, int], dict] = {}
    for r in report["results"]:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        rule = normalise_rule_id(r.get("check_id", ""), custom)
        if not rule:
            continue
        p = Path(r.get("path", ""))
        if not p.is_absolute():
            p = Path.cwd() / p
        p = p.resolve()
        try:
            uri = p.relative_to(base).as_posix()
        except ValueError:
            uri = Path(os.path.relpath(p, base)).as_posix()
        line = int((r.get("start") or {}).get("line") or 0)
        key = (rule, uri, line)
        if key in seen:
            continue
        raw_sev = str(extra.get("severity") or "")
        sev = SEVERITY_MAP.get(raw_sev.upper(), "Low")
        props: dict = {"severity": sev, "category": "sast"}
        if raw_sev:
            props["raw_severity"] = raw_sev
        cwe = first_cwe(meta.get("cwe"), meta.get("tags"))
        if cwe:
            props["cwe"] = cwe
        fix = meta.get("remediation") or extra.get("fix")
        if isinstance(fix, str) and fix.strip():
            props["fix"] = clean(fix)
        conf = str(meta.get("confidence") or "").lower()
        if conf in ("high", "medium", "low"):
            props["confidence"] = conf
        help_uri = first_http(meta.get("references"), meta.get("source"), meta.get("shortlink"))
        if help_uri:
            props["help_uri"] = help_uri
        loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        if line > 0:
            loc["physicalLocation"]["region"] = {"startLine": line}
        seen[key] = {
            "ruleId": rule,
            "level": LEVEL_FOR[sev],
            "message": {"text": clean(extra.get("message") or rule)},
            "locations": [loc],
            "properties": props,
        }

    results = [seen[k] for k in sorted(seen, key=lambda k: (k[1], k[2], k[0]))]
    rules = []
    for rid in sorted({x["ruleId"] for x in results}):
        first = next(x for x in results if x["ruleId"] == rid)
        entry = {"id": rid, "shortDescription": {"text": clean(first["message"]["text"])[:200]}}
        if "help_uri" in first["properties"]:
            entry["helpUri"] = first["properties"]["help_uri"]
        rules.append(entry)

    errors = report.get("errors") or []
    packs = [p for p in args.registry_packs.split() if p]
    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "semgrep",
                "version": version,
                "informationUri": "https://semgrep.dev",
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "custom_rules_enabled": args.custom_rules == "1",
                "registry_packs_requested": packs,
                "registry_packs_applied": args.registry_applied == "true" and bool(packs),
                "scan_errors": len(errors),
            },
        }],
    }
    if errors:
        print(f"[to_sarif] WARNING: semgrep reported {len(errors)} non-fatal scan error(s) "
              "(e.g. files it could not parse); those files may be incompletely covered", file=sys.stderr)

    out = Path(args.out)
    fd, tmp_name = tempfile.mkstemp(prefix=".sast.sarif.", suffix=".tmp", dir=str(out.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2)
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

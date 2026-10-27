#!/usr/bin/env python3
"""stages/sca/to_sarif.py - convert a Trivy JSON report (trivy fs --format json) to contract-valid SARIF.

Standard library only.  Called by run.sh.

Why JSON and not Trivy's own SARIF output: the JSON carries the structured fields the
contract's optional properties need (package, installed/fixed version, CVE id, CWE, severity).

  * one SARIF result per (manifest file, package, installed version, vulnerability id)
  * ruleId            = VulnerabilityID (CVE-... or GHSA-...)
  * severity          per contracts/severity-map.md: CRITICAL/HIGH/MEDIUM/LOW -> same names,
                      UNKNOWN or anything else -> Low; original label -> raw_severity
  * cve_id            only when the id (or a vendor alias) matches the contract pattern CVE-YYYY-NNNN+
  * package / installed_version / fixed_version / fix_available / cwe / help_uri / fix
  * location          repo-relative manifest path; line from Trivy's package Locations, else found by
                      matching the package name inside the manifest, else 0 (file level)
  * zero results      is valid ("no supported manifests" / "no known vulnerabilities")
  * deterministic ordering (file, line, package, rule), atomic write
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

SEVERITY_MAP = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Low"}
LEVEL_FOR = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_RE = re.compile(r"^CWE-\d+$")
MAX_TEXT = 400
MAX_MANIFEST_BYTES = 8 * 1024 * 1024


def clean(text: str, limit: int = MAX_TEXT) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def split_versions(fixed: str) -> list[str]:
    """Trivy writes several fixed versions as "2.2.5, 2.3.2"."""
    return [v.strip() for v in re.split(r"[,;]", fixed or "") if v.strip()]


def name_pattern(name: str) -> re.Pattern:
    """Case-insensitive, separator-insensitive (PEP 503) match of a whole package name."""
    parts = [re.escape(p) for p in re.split(r"[-_.]+", name) if p]
    body = r"[-_.]+".join(parts) if parts else re.escape(name)
    return re.compile(r"(?<![A-Za-z0-9_.\-])" + body + r"(?![A-Za-z0-9_.\-])", re.IGNORECASE)


def find_line(manifest: Path, package: str, version: str, cache: dict) -> int:
    """1-based line of `package` in the manifest (preferring a line that also holds the version), else 0."""
    key = str(manifest)
    if key not in cache:
        try:
            if manifest.is_file() and manifest.stat().st_size <= MAX_MANIFEST_BYTES:
                cache[key] = manifest.read_text(encoding="utf-8", errors="replace").splitlines()
            else:
                cache[key] = []
        except OSError:
            cache[key] = []
    pat = name_pattern(package)
    first = 0
    for i, line in enumerate(cache[key], start=1):
        if line.lstrip().startswith(("#", "//")):
            continue  # comments may mention a package without declaring it
        if pat.search(line):
            if version and version in line:
                return i
            if not first:
                first = i
    return first


def package_lines(result: dict) -> dict[tuple[str, str], int]:
    """(name, version) -> StartLine, from the package list when Trivy provides locations."""
    out: dict[tuple[str, str], int] = {}
    for pkg in result.get("Packages") or []:
        locs = pkg.get("Locations") or []
        if locs and isinstance(locs[0], dict) and int(locs[0].get("StartLine") or 0) > 0:
            out.setdefault((str(pkg.get("Name", "")), str(pkg.get("Version", ""))), int(locs[0]["StartLine"]))
    return out


def first_http(*candidates) -> str | None:
    for c in candidates:
        items = c if isinstance(c, list) else [c]
        for item in items:
            if isinstance(item, str) and re.match(r"^https?://\S+$", item):
                return item
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True, help="Trivy JSON report")
    ap.add_argument("--target", required=True, help="absolute path that was scanned")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--tool-version", default="", help="version reported by `trivy --version`")
    ap.add_argument("--db-metadata", default="", help="trivy-db metadata.json (provenance only)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    try:
        with open(args.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"[to_sarif] ERROR: cannot read the Trivy report: {exc}", file=sys.stderr)
        return 1
    if not isinstance(report, dict) or "SchemaVersion" not in report:
        print("[to_sarif] ERROR: not a Trivy JSON report (no SchemaVersion)", file=sys.stderr)
        return 1
    if int(report["SchemaVersion"]) != 2:
        print(f"[to_sarif] ERROR: unsupported Trivy report SchemaVersion {report['SchemaVersion']}", file=sys.stderr)
        return 1
    results_in = report.get("Results")
    if results_in is None:
        results_in = []  # Trivy omits Results when nothing relevant was found / no manifests exist
    if not isinstance(results_in, list):
        print("[to_sarif] ERROR: Trivy report has a malformed Results field", file=sys.stderr)
        return 1

    version = (args.tool_version or "").strip() or str((report.get("Trivy") or {}).get("Version") or "").strip()
    if not version:
        print("[to_sarif] ERROR: cannot determine the Trivy version", file=sys.stderr)
        return 1

    target = Path(args.target).resolve()
    repo_root = Path(args.repo_root).resolve()
    scan_dir = target if target.is_dir() else target.parent
    try:
        scan_dir.relative_to(repo_root)
        base = repo_root
    except ValueError:
        base = scan_dir

    line_cache: dict = {}
    seen: dict[tuple, dict] = {}
    n_manifests = 0
    for res in results_in:
        if not isinstance(res, dict):
            continue
        vulns = res.get("Vulnerabilities") or []
        if res.get("Class") not in (None, "lang-pkgs", "os-pkgs", "") and not vulns:
            continue
        n_manifests += 1
        rel_target = str(res.get("Target") or "")
        if not rel_target:
            continue
        manifest = (scan_dir / rel_target) if not os.path.isabs(rel_target) else Path(rel_target)
        manifest = Path(os.path.normpath(manifest))
        try:
            uri = manifest.relative_to(base).as_posix()
        except ValueError:
            uri = Path(os.path.relpath(manifest, base)).as_posix()
        locations = package_lines(res)

        for v in vulns:
            vid = str(v.get("VulnerabilityID") or "").strip()
            pkg = str(v.get("PkgName") or "").strip()
            if not vid or not pkg:
                continue
            installed = str(v.get("InstalledVersion") or "").strip()
            key = (uri, pkg.lower(), installed, vid)
            if key in seen:
                continue

            raw_sev = str(v.get("Severity") or "").strip()
            sev = SEVERITY_MAP.get(raw_sev.upper(), "Low")

            line = locations.get((pkg, installed), 0) or find_line(manifest, pkg, installed, line_cache)

            fixed_raw = str(v.get("FixedVersion") or "").strip()
            fixed = split_versions(fixed_raw)
            props: dict = {"severity": sev, "category": "sca", "package": pkg}
            if raw_sev:
                props["raw_severity"] = raw_sev
            cve = vid if CVE_RE.match(vid) else next(
                (a for a in (v.get("VendorIDs") or []) if isinstance(a, str) and CVE_RE.match(a)), None)
            if cve:
                props["cve_id"] = cve
            if installed:
                props["installed_version"] = installed
            if fixed:
                props["fixed_version"] = ", ".join(fixed)
            props["fix_available"] = bool(fixed)
            cwe = next((c for c in (v.get("CweIDs") or []) if isinstance(c, str) and CWE_RE.match(c)), None)
            if cwe:
                props["cwe"] = cwe
            help_uri = first_http(v.get("PrimaryURL"), v.get("References"))
            if help_uri:
                props["help_uri"] = help_uri
            if fixed:
                target_v = fixed[0] if len(fixed) == 1 else None
                props["fix"] = (f"Upgrade {pkg} from {installed} to {target_v} or later." if target_v
                                else f"Upgrade {pkg} from {installed} to a fixed release ({', '.join(fixed)}).")
            else:
                status = str(v.get("Status") or "").strip()
                props["fix"] = "No fixed version available yet" + (f" (status: {status})." if status else ".")

            title = clean(v.get("Title") or "")
            text = f"{pkg} {installed} is affected by {vid}" + (f": {title}" if title else "")
            loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
            if line > 0:
                loc["physicalLocation"]["region"] = {"startLine": line}
            seen[key] = {
                "ruleId": vid,
                "level": LEVEL_FOR[sev],
                "message": {"text": clean(text)},
                "locations": [loc],
                "properties": props,
            }

    def order(item):
        r = item
        loc = r["locations"][0]["physicalLocation"]
        return (loc["artifactLocation"]["uri"], loc.get("region", {}).get("startLine", 0),
                r["properties"]["package"].lower(), r["ruleId"])

    results = sorted(seen.values(), key=order)
    rules = []
    for rid in sorted({r["ruleId"] for r in results}):
        first = next(r for r in results if r["ruleId"] == rid)
        entry = {"id": rid, "shortDescription": {"text": clean(first["message"]["text"], 200)}}
        if "help_uri" in first["properties"]:
            entry["helpUri"] = first["properties"]["help_uri"]
        rules.append(entry)

    run_props: dict = {"scanned_manifests": n_manifests}
    if args.db_metadata:
        try:
            meta = json.loads(Path(args.db_metadata).read_text(encoding="utf-8"))
            for src, dst in (("UpdatedAt", "db_updated_at"), ("Version", "db_schema_version")):
                if src in meta:
                    run_props[dst] = meta[src]
        except (OSError, ValueError):
            pass  # provenance only; never fail the stage over it

    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "trivy",
                "version": version,
                "informationUri": "https://trivy.dev",
                "rules": rules,
            }},
            "results": results,
            "properties": run_props,
        }],
    }

    out = Path(args.out)
    fd, tmp_name = tempfile.mkstemp(prefix=".sca.sarif.", suffix=".tmp", dir=str(out.parent))
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
    print(f"[to_sarif] wrote {len(results)} result(s) from {n_manifests} manifest(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""eval/p2-code/evaluate.py - reproducible evaluation of the Phase 2 code-level stages.

Runs the real `secrets`, `sast` and `sca` stages on demo-app/vulnerable and demo-app/fixed,
compares the SARIF they produce with the seeded ground truth (demo-app/seeded-vulnerabilities.json)
and writes:

    results.json   machine readable (every number in the docs comes from here)
    results.md     tables for the report
    triage.md      every finding that matches no seeded flaw, with a PROPOSED verdict
    runs/          raw SARIF copies, per configuration and app
    fig-p2-*.png   charts (only if matplotlib is importable; tables are complete without them)

Standard library only (matplotlib is optional).  Nothing is estimated: a configuration that could not run
(exit != 0) is recorded as "not run" with the reason taken from the stage's own stderr.

Matching rules (documented in results.md as well)
  * The evaluated flaws are the entries of seeded-vulnerabilities.json whose `class` is
    secret, sast or sca (derived from the file, never hard-coded ids).
  * secret / sast : a finding matches a flaw when it is in the same file, in the same category, and
                    |finding line - seeded line| <= LINE_TOLERANCE.
  * sca           : a finding matches when it is in the same file and its CVE id (ruleId or
                    properties.cve_id) is one of the flaw's cve_ids.  (Line delta is reported, not required.)
  * one-to-one    : a finding can satisfy at most one flaw (greedy by [rule-id agreement, line distance]),
                    so two adjacent seeded secrets need two findings.
  * `rule_id_agrees` records whether the finding's rule id equals the seed's expected_rule_id; it is
    informational only (the seed list names Semgrep registry rule ids, the stage also ships custom rules).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
LINE_TOLERANCE = 2
CLASS_TO_STAGE = {"secret": "secrets", "sast": "sast", "sca": "sca"}
STAGE_TO_CLASS = {v: k for k, v in CLASS_TO_STAGE.items()}
SEVERITIES = ["Critical", "High", "Medium", "Low"]

# (config name, extra environment).  The first one that RUNS is the "primary" configuration used for the headline numbers.
CONFIGS: dict[str, list[tuple[str, dict[str, str]]]] = {
    "secrets": [("tuned", {}),
                ("gitleaks-default", {"SECRETS_CONFIG": str(HERE / "gitleaks-default.toml")})],
    "sast": [("custom+registry", {}),
             ("custom-only", {"SAST_REGISTRY_PACKS": ""}),
             ("registry-only", {"SAST_CUSTOM_RULES": "0"})],
    "sca": [("default", {})],
}
PRIMARY_ORDER = {"secrets": ["tuned"], "sast": ["custom+registry", "custom-only"], "sca": ["default"]}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def tail_lines(text: str, n: int = 3) -> list[str]:
    return [l.strip() for l in text.strip().splitlines() if l.strip()][-n:]


def run_stage(stage: str, target: str, outdir: Path, env_extra: dict, base_env: dict, timeout: int) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    sarif = outdir / f"{stage}.sarif"
    if sarif.exists():
        sarif.unlink()
    env = dict(base_env)
    env.update(env_extra)
    t0 = time.perf_counter()
    try:
        p = subprocess.run(["bash", str(REPO / "stages" / stage / "run.sh"), target, str(outdir)],
                           cwd=str(REPO), env=env, capture_output=True, text=True, timeout=timeout)
        rc, err = p.returncode, p.stderr
    except subprocess.TimeoutExpired:
        rc, err = 124, "evaluation harness timeout"
    dt = time.perf_counter() - t0
    errs = [l.strip() for l in err.splitlines() if "ERROR" in l]
    reason = [errs[-1]] if errs else tail_lines(err, 2)
    res = {"exit_code": rc, "seconds": round(dt, 2), "sarif": str(sarif) if sarif.exists() else None,
           "stderr_tail": reason if rc != 0 else [l.strip() for l in err.splitlines() if "WARNING" in l][-2:]}
    return res


def cold_install_seconds(stage: str, cache: Path, base_env: dict) -> dict:
    """Time install.sh against an EMPTY cache (tool provisioning cost of a cold CI runner)."""
    env = dict(base_env)
    env["XDG_CACHE_HOME"] = str(cache)
    t0 = time.perf_counter()
    p = subprocess.run(["bash", str(REPO / "stages" / stage / "install.sh")], cwd=str(REPO), env=env,
                       capture_output=True, text=True)
    return {"seconds": round(time.perf_counter() - t0, 2), "exit_code": p.returncode}


def load_sarif(path: str | None):
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def findings_of(sarif: dict | None) -> list[dict]:
    out = []
    if not sarif:
        return out
    run = sarif["runs"][0]
    for r in run.get("results", []):
        loc = r["locations"][0]["physicalLocation"]
        p = r.get("properties", {})
        out.append({"rule_id": r["ruleId"], "file": loc["artifactLocation"]["uri"],
                    "line": loc.get("region", {}).get("startLine", 0), "severity": p.get("severity"),
                    "raw_severity": p.get("raw_severity"), "category": p.get("category"),
                    "cve_id": p.get("cve_id"), "cwe": p.get("cwe"), "package": p.get("package"),
                    "confidence": p.get("confidence"), "fix_present": bool(p.get("fix")),
                    "message": r["message"]["text"]})
    return out


def tool_version(sarif: dict | None) -> str | None:
    if not sarif:
        return None
    d = sarif["runs"][0]["tool"]["driver"]
    return f'{d.get("name")} {d.get("version")}'


def validate(sarif_path: str | None, stage: str, py: str) -> str:
    if not sarif_path:
        return "n/a"
    p = subprocess.run([py, str(REPO / "contracts" / "validate.py"), sarif_path, "--stage", stage],
                       capture_output=True, text=True)
    if p.returncode == 0:
        return "valid"
    if "jsonschema is not installed" in p.stderr or "PyYAML is not installed" in p.stderr:
        return "not run (jsonschema missing)"
    return "INVALID"


def match(flaws: list[dict], findings: list[dict]) -> tuple[list[dict], set[int]]:
    """One-to-one greedy assignment.  Returns (per-flaw result, indexes of matched findings)."""
    pairs = []
    for fi, v in enumerate(flaws):
        for gi, f in enumerate(findings):
            if f["file"] != v["file"]:
                continue
            if v["class"] == "sca":
                ids = set(v.get("cve_ids") or [])
                if not ({f["rule_id"], f.get("cve_id")} & ids):
                    continue
                dist = abs((f["line"] or 0) - v["line"])
            else:
                if f["category"] != v["class"]:
                    continue
                dist = abs((f["line"] or 0) - v["line"])
                if dist > LINE_TOLERANCE:
                    continue
            agrees = f["rule_id"] == v.get("expected_rule_id")
            pairs.append((0 if agrees else 1, dist, fi, gi))
    pairs.sort()
    used_f, used_g, assigned = set(), set(), {}
    for _, dist, fi, gi in pairs:
        if fi in used_f or gi in used_g:
            continue
        used_f.add(fi)
        used_g.add(gi)
        assigned[fi] = (gi, dist)
    out = []
    for fi, v in enumerate(flaws):
        if fi in assigned:
            gi, dist = assigned[fi]
            f = findings[gi]
            out.append({"id": v["id"], "detected": True, "by_rule": f["rule_id"], "line_delta": dist,
                        "severity": f["severity"], "rule_id_agrees": f["rule_id"] == v.get("expected_rule_id")})
        else:
            same_file = sorted((abs((f["line"] or 0) - v["line"]), f["rule_id"], f["line"])
                               for f in findings if f["file"] == v["file"])
            reason = (f"no {v['class']} finding for this flaw; nearest finding in the same file: "
                      f"{same_file[0][1]} at line {same_file[0][2]}" if same_file
                      else f"no finding at all in {v['file']}")
            out.append({"id": v["id"], "detected": False, "reason": reason})
    return out, {gi for gi, _ in assigned.values()}


def sev_counts(findings: list[dict]) -> dict:
    c = Counter(f["severity"] for f in findings)
    return {s: c.get(s, 0) for s in SEVERITIES}


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--warm-runs", type=int, default=int(os.environ.get("EVAL_WARM_RUNS", "3")))
    ap.add_argument("--timeout", type=int, default=int(os.environ.get("EVAL_STAGE_TIMEOUT", "900")))
    ap.add_argument("--cache-dir", default=os.environ.get("EVAL_CACHE_DIR", ""),
                    help="reuse this cache (cold timings are then NOT measured); default: a fresh temporary cache")
    ap.add_argument("--no-figures", action="store_true")
    ap.add_argument("--out-dir", default=str(HERE))
    args = ap.parse_args()
    out_dir = Path(args.out_dir).resolve()
    runs_dir = out_dir / "runs"
    if runs_dir.exists():
        shutil.rmtree(runs_dir)
    runs_dir.mkdir(parents=True)
    py = os.environ.get("EVAL_PYTHON") or sys.executable

    seed_doc = json.loads((REPO / "demo-app" / "seeded-vulnerabilities.json").read_text(encoding="utf-8"))
    flaws = [v for v in seed_doc["vulnerabilities"] if v["class"] in CLASS_TO_STAGE]
    flaws_by_stage = {s: [v for v in flaws if CLASS_TO_STAGE[v["class"]] == s] for s in CLASS_TO_STAGE.values()}

    tmp_cache = None
    cold_measured = not args.cache_dir
    if args.cache_dir:
        cache = Path(args.cache_dir)
        cache.mkdir(parents=True, exist_ok=True)
    else:
        tmp_cache = tempfile.mkdtemp(prefix="p2-eval-cache.")
        cache = Path(tmp_cache)
    base_env = dict(os.environ)
    base_env["XDG_CACHE_HOME"] = str(cache)
    base_env.setdefault("PYTHON", py)
    base_env["STAGE_TIMEOUT"] = base_env.get("STAGE_TIMEOUT", "600")
    # SCA: do not wait through long retry back-offs when the registry is blocked
    base_env.setdefault("SCA_DB_RETRY_DELAY", "2")

    apps = {"vulnerable": "demo-app/vulnerable", "fixed": "demo-app/fixed"}
    results: dict = {
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "line_tolerance": LINE_TOLERANCE,
        "seeded_flaws_evaluated": [{"id": v["id"], "stage": CLASS_TO_STAGE[v["class"]], "file": v["file"],
                                    "line": v["line"], "expected_rule_id": v.get("expected_rule_id"),
                                    "cve_ids": v.get("cve_ids", [])} for v in flaws],
        "environment": {"cold_timing_measured": cold_measured, "warm_runs": args.warm_runs,
                        "git_commit": subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                                                     capture_output=True, text=True).stdout.strip() or None},
        "configs": {},
    }

    primary_for: dict[str, str] = {}
    cold: dict[str, dict] = {}
    if cold_measured:
        for stage in CONFIGS:
            cold[stage] = cold_install_seconds(stage, cache, base_env)
    unmatched_all: list[dict] = []

    for stage, configs in CONFIGS.items():
        for cname, cenv in configs:
            entry = {"stage": stage, "config": cname, "env": {k: ("<path>" if "CONFIG" in k else v) for k, v in cenv.items()},
                     "apps": {}}
            for app, rel in apps.items():
                outdir = runs_dir / f"{stage}__{cname}" / app
                r = run_stage(stage, rel, outdir, cenv, base_env, args.timeout)
                if r["exit_code"] == 0:
                    sarif = load_sarif(r["sarif"])
                    fnds = findings_of(sarif)
                    r["tool"] = tool_version(sarif)
                    r["run_properties"] = sarif["runs"][0].get("properties", {})
                    r["contract_validation"] = validate(r["sarif"], stage, py)
                    r["findings"] = fnds
                    r["findings_count"] = len(fnds)
                    r["by_severity"] = sev_counts(fnds)
                    r["status"] = "ran"
                    if r["sarif"]:
                        r["sarif"] = os.path.relpath(r["sarif"], out_dir)
                else:
                    r["status"] = "not run"
                    r["not_run_reason"] = " | ".join(r["stderr_tail"]) or f"exit {r['exit_code']}"
                    r["sarif"] = None
                entry["apps"][app] = r
            # ground-truth comparison on the vulnerable app
            v = entry["apps"]["vulnerable"]
            if v["status"] == "ran":
                per, matched = match(flaws_by_stage[stage], v["findings"])
                entry["per_flaw"] = per
                entry["detected"] = sum(1 for p in per if p["detected"])
                entry["seeded"] = len(per)
                entry["unmatched_on_vulnerable"] = [f for i, f in enumerate(v["findings"]) if i not in matched]
            else:
                entry["per_flaw"] = None
                entry["detected"] = None
                entry["seeded"] = len(flaws_by_stage[stage])
                entry["unmatched_on_vulnerable"] = None
            results["configs"][f"{stage}/{cname}"] = entry
            if stage not in primary_for and entry["apps"]["vulnerable"]["status"] == "ran" \
                    and cname in PRIMARY_ORDER[stage]:
                primary_for[stage] = cname
        # prefer the earliest entry of PRIMARY_ORDER that ran
        for cname in PRIMARY_ORDER[stage]:
            if results["configs"][f"{stage}/{cname}"]["apps"]["vulnerable"]["status"] == "ran":
                primary_for[stage] = cname
                break

    # warm timing + determinism for the primary configurations (cache is warm now)
    timing = {}
    for stage, cname in primary_for.items():
        env = dict(next(e for n, e in CONFIGS[stage] if n == cname))
        secs, outs = [], []
        for i in range(max(1, args.warm_runs)):
            r = run_stage(stage, apps["vulnerable"], runs_dir / "_timing" / stage / str(i), env, base_env, args.timeout)
            if r["exit_code"] != 0:
                break
            secs.append(r["seconds"])
            outs.append((runs_dir / "_timing" / stage / str(i) / f"{stage}.sarif").read_bytes())
        timing[stage] = {"config": cname, "warm_seconds": secs,
                         "warm_median": round(statistics.median(secs), 2) if secs else None,
                         "cold_install_seconds": cold.get(stage, {}).get("seconds") if cold.get(stage, {}).get("exit_code") == 0 else None,
                         "deterministic_across_warm_runs": (len(set(outs)) == 1) if len(outs) > 1 else None}
    shutil.rmtree(runs_dir / "_timing", ignore_errors=True)
    for stage in CONFIGS:
        timing.setdefault(stage, {"config": None, "warm_seconds": [], "warm_median": None, "cold_install_seconds": None,
                                  "deterministic_across_warm_runs": None,
                                  "note": "not run (see configs)"})
        if cold.get(stage) and cold[stage]["exit_code"] != 0:
            timing[stage]["cold_note"] = f"install failed (exit {cold[stage]['exit_code']})"
    results["timing"] = timing
    results["primary_config"] = primary_for

    # per-stage and overall headline
    head = {}
    tot_seeded = tot_detected = tot_eval_seeded = 0
    for stage in CONFIGS:
        n = len(flaws_by_stage[stage])
        tot_seeded += n
        if stage in primary_for:
            e = results["configs"][f"{stage}/{primary_for[stage]}"]
            head[stage] = {"config": primary_for[stage], "seeded": n, "detected": e["detected"],
                           "detection_rate": round(e["detected"] / n, 4) if n else None,
                           "strict_default_ran": primary_for[stage] == CONFIGS[stage][0][0]}
            tot_detected += e["detected"]
            tot_eval_seeded += n
        else:
            head[stage] = {"config": None, "seeded": n, "detected": None, "detection_rate": None,
                           "strict_default_ran": False}
    results["headline"] = {
        "per_stage": head,
        "overall_seeded": tot_seeded,
        "overall_evaluated_seeded": tot_eval_seeded,
        "overall_detected": tot_detected,
        "overall_rate_among_evaluated": round(tot_detected / tot_eval_seeded, 4) if tot_eval_seeded else None,
        "overall_rate_not_run_counted_as_missed": round(tot_detected / tot_seeded, 4) if tot_seeded else None,
    }

    # false positives on the fixed app, severity totals
    fp = {}
    for key, e in results["configs"].items():
        f = e["apps"]["fixed"]
        fp[key] = ({"status": "ran", "count": f["findings_count"], "findings": f["findings"]}
                   if f["status"] == "ran" else {"status": "not run", "reason": f.get("not_run_reason")})
    results["fixed_app_findings"] = fp

    # triage list (unmatched findings of the primary configurations)
    for stage, cname in primary_for.items():
        for f in results["configs"][f"{stage}/{cname}"]["unmatched_on_vulnerable"] or []:
            unmatched_all.append({"stage": stage, "config": cname, **f})
    results["unmatched_primary"] = unmatched_all

    (out_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    write_results_md(results, out_dir)
    write_triage_md(results, out_dir)
    if not args.no_figures:
        make_figures(results, out_dir)
    if tmp_cache:
        shutil.rmtree(tmp_cache, ignore_errors=True)
    print(f"[eval] wrote {out_dir/'results.json'}, results.md, triage.md", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# report writers
# ---------------------------------------------------------------------------
def pct(x):
    return "n/a" if x is None else f"{x*100:.1f}%"


def write_results_md(R: dict, out: Path) -> None:
    L: list[str] = []
    A = L.append
    A("# Phase 2 evaluation results (code-level stages)")
    A("")
    A(f"Generated {R['generated_at_utc']} from commit `{R['environment']['git_commit']}` by `eval/p2-code/evaluate.py`. "
      "Every number below is read from `results.json`; nothing is estimated. A configuration marked **not run** exited non-zero in this environment; the reason is quoted from the stage's own stderr.")
    A("")
    A("## Matching rules")
    A("")
    A(f"* Evaluated flaws: every entry of `seeded-vulnerabilities.json` whose class is secret, sast or sca ({len(R['seeded_flaws_evaluated'])} flaws).")
    A(f"* secret / sast: same file, same category, |finding line - seeded line| <= {R['line_tolerance']}.")
    A("* sca: same file and the CVE id (ruleId / cve_id) is one of the seeded CVE ids; the line delta is reported.")
    A("* One-to-one: a finding satisfies at most one flaw (greedy by rule-id agreement, then line distance).")
    A("")
    A("## Headline detection rate (primary configuration per stage)")
    A("")
    A("| Stage | Primary configuration | Seeded | Detected | Detection rate | Strict CI default ran? |")
    A("|---|---|---|---|---|---|")
    H = R["headline"]
    for s, h in H["per_stage"].items():
        if h["config"]:
            A(f"| {s} | {h['config']} | {h['seeded']} | {h['detected']} | {pct(h['detection_rate'])} | {'yes' if h['strict_default_ran'] else '**no** (fallback config)'} |")
        else:
            A(f"| {s} | **not run** | {h['seeded']} | n/a | n/a | no |")
    A(f"| **Overall (evaluated stages only)** | | {H['overall_evaluated_seeded']} | {H['overall_detected']} | {pct(H['overall_rate_among_evaluated'])} | |")
    A(f"| **Overall (not-run stages counted as missed)** | | {H['overall_seeded']} | {H['overall_detected']} | {pct(H['overall_rate_not_run_counted_as_missed'])} | |")
    A("")
    A("## Per-flaw results (primary configuration)")
    A("")
    A("| Flaw | Stage | Detected | By rule | Line delta | Severity | Rule id = seed's expected id |")
    A("|---|---|---|---|---|---|---|")
    meta = {f["id"]: f for f in R["seeded_flaws_evaluated"]}
    for stage, cname in R["primary_config"].items():
        for p in R["configs"][f"{stage}/{cname}"]["per_flaw"]:
            if p["detected"]:
                A(f"| {p['id']} | {stage} | yes | `{p['by_rule']}` | {p['line_delta']} | {p['severity']} | {'yes' if p['rule_id_agrees'] else 'no'} |")
            else:
                A(f"| {p['id']} | {stage} | **NO** | - | - | - | - |")
    for stage in R["headline"]["per_stage"]:
        if stage not in R["primary_config"]:
            for f in R["seeded_flaws_evaluated"]:
                if f["stage"] == stage:
                    A(f"| {f['id']} | {stage} | **not evaluated** (stage did not run) | - | - | - | - |")
    A("")
    A("## False negatives and not-evaluated flaws")
    A("")
    fn_rows = []
    for stage, cname in R["primary_config"].items():
        for p in R["configs"][f"{stage}/{cname}"]["per_flaw"]:
            if not p["detected"]:
                fn_rows.append(f"| {p['id']} | {stage}/{cname} | missed | {p['reason']} |")
    for stage in R["headline"]["per_stage"]:
        if stage not in R["primary_config"]:
            reasons = {k: v["apps"]["vulnerable"].get("not_run_reason") for k, v in R["configs"].items() if v["stage"] == stage}
            for f in R["seeded_flaws_evaluated"]:
                if f["stage"] == stage:
                    fn_rows.append(f"| {f['id']} | {stage} | not evaluated | stage exited non-zero: {next(iter(reasons.values()))} |")
    if fn_rows:
        A("| Flaw | Configuration | Outcome | Evidence |")
        A("|---|---|---|---|")
        L.extend(fn_rows)
    else:
        A("None.")
    A("")
    A("## Findings on the vulnerable app that match no seeded flaw")
    A("")
    A(f"{len(R['unmatched_primary'])} finding(s) in the primary configurations; each is listed with a PROPOSED verdict in `triage.md` (needs human confirmation).")
    A("")
    A("## False positives on the fixed app")
    A("")
    A("| Configuration | Status | Findings |")
    A("|---|---|---|")
    for key, f in R["fixed_app_findings"].items():
        if f["status"] == "ran":
            detail = "; ".join(f"`{x['rule_id']}` {x['file']}:{x['line']}" for x in f["findings"]) or "-"
            A(f"| {key} | ran | {f['count']} {('(' + detail + ')') if f['count'] else ''} |")
        else:
            A(f"| {key} | **not run** | {f['reason']} |")
    A("")
    A("## Findings by severity (vulnerable app)")
    A("")
    A("| Configuration | Critical | High | Medium | Low | Total |")
    A("|---|---|---|---|---|---|")
    for key, e in R["configs"].items():
        v = e["apps"]["vulnerable"]
        if v["status"] == "ran":
            s = v["by_severity"]
            A(f"| {key} | {s['Critical']} | {s['High']} | {s['Medium']} | {s['Low']} | {v['findings_count']} |")
        else:
            A(f"| {key} | **not run** | | | | |")
    A("")
    A("## Tuning comparison")
    A("")
    A("| Configuration | Status | Detected / seeded | Findings (vulnerable) | Findings (fixed) | Missed flaws |")
    A("|---|---|---|---|---|---|")
    for key, e in R["configs"].items():
        v, f = e["apps"]["vulnerable"], e["apps"]["fixed"]
        if v["status"] == "ran":
            missed = ", ".join(p["id"] for p in e["per_flaw"] if not p["detected"]) or "-"
            A(f"| {key} | ran | {e['detected']} / {e['seeded']} | {v['findings_count']} | {f['findings_count'] if f['status']=='ran' else 'not run'} | {missed} |")
        else:
            A(f"| {key} | **not run** | n/a / {e['seeded']} | n/a | n/a | n/a ({v.get('not_run_reason')}) |")
    A("")
    A("## Runtime (primary configuration, vulnerable app)")
    A("")
    A("Cold = `install.sh` against an empty cache (tool provisioning on a fresh runner; the Trivy vulnerability-DB download is additional and is not included). "
      "Warm = the scan with the tool already cached.")
    A("")
    A("| Stage | Configuration | Cold install (empty cache), s | Warm scan median, s | Warm runs, s | Byte-identical across warm runs |")
    A("|---|---|---|---|---|---|")
    for s, t in R["timing"].items():
        cold = "not measured" if t.get("cold_install_seconds") is None else f"{t['cold_install_seconds']}"
        if t.get("cold_note"):
            cold = f"n/a ({t['cold_note']})"
        if not R["environment"]["cold_timing_measured"]:
            cold = "not measured (cache reused)"
        det = {True: "yes", False: "**NO**", None: "n/a"}[t.get("deterministic_across_warm_runs")]
        A(f"| {s} | {t['config'] or 'not run'} | {cold} | {t['warm_median'] if t['warm_median'] is not None else 'n/a'} | {', '.join(map(str, t['warm_seconds'])) or 'n/a'} | {det} |")
    A("")
    A("## Tool versions and contract validation")
    A("")
    A("| Configuration | Tool | `validate.py --stage` (vulnerable / fixed) |")
    A("|---|---|---|")
    for key, e in R["configs"].items():
        v, f = e["apps"]["vulnerable"], e["apps"]["fixed"]
        A(f"| {key} | {v.get('tool') or 'n/a'} | {v.get('contract_validation', 'n/a')} / {f.get('contract_validation', 'n/a')} |")
    A("")
    notes = []
    for key, e in R["configs"].items():
        rp = e["apps"]["vulnerable"].get("run_properties") or {}
        if rp.get("registry_packs_requested") and not rp.get("registry_packs_applied"):
            notes.append(f"* `{key}`: registry packs were requested but NOT applied.")
    if notes:
        A("## Coverage caveats")
        A("")
        L.extend(notes)
        A("")
    (out / "results.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def write_triage_md(R: dict, out: Path) -> None:
    prop_path = HERE / "triage-proposals.json"
    props = json.loads(prop_path.read_text(encoding="utf-8")) if prop_path.exists() else []
    import fnmatch

    def proposal(item: dict):
        for p in props:
            if p["stage"] == item["stage"] and fnmatch.fnmatch(item["rule_id"], p.get("rule_id", "*")) \
                    and fnmatch.fnmatch(item["file"], p.get("file", "*")) \
                    and fnmatch.fnmatch(item.get("package") or "", p.get("package", "*")):
                return p
        return None

    L = ["# Triage of findings that match no seeded flaw (vulnerable app)", "",
         "**All verdicts are PROPOSED (needs human confirmation).** They were written by the P2 author from the "
         "scanner output and the source files; they are not ground truth. Verdict vocabulary: "
         "`true positive not in seed list`, `false positive`, `informational`.", "",
         f"Generated {R['generated_at_utc']} by `evaluate.py` from `results.json`; justifications come from `triage-proposals.json`.", ""]
    if not R["unmatched_primary"]:
        L.append("No unmatched findings in the primary configurations.")
    else:
        L.append("| # | Stage | Rule | Location | Severity | Message | PROPOSED verdict | Justification |")
        L.append("|---|---|---|---|---|---|---|---|")
        untriaged = 0
        for i, f in enumerate(R["unmatched_primary"], 1):
            p = proposal(f)
            if p is None:
                untriaged += 1
            verdict = p["verdict"] if p else "NO PROPOSAL - needs human triage"
            just = p["justification"] if p else "not covered by triage-proposals.json"
            msg = f["message"].replace("|", "\\|")[:140]
            L.append(f"| {i} | {f['stage']} | `{f['rule_id']}` | `{f['file']}:{f['line']}` | {f['severity']} | {msg} | {verdict} | {just} |")
        L += ["", f"{len(R['unmatched_primary'])} unmatched finding(s); {untriaged} without a proposal."]
    L.append("")
    (out / "triage.md").write_text("\n".join(L), encoding="utf-8")


def make_figures(R: dict, out: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:  # optional dependency
        print(f"[eval] figures skipped (matplotlib unavailable: {exc})", file=sys.stderr)
        return
    for old in out.glob("fig-p2-*.png"):
        old.unlink()
    ink, muted, blue, grey = "#1f2933", "#6b7785", "#2b6cb0", "#c3cad3"
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
                         "axes.edgecolor": muted, "axes.labelcolor": ink, "xtick.color": ink, "ytick.color": ink})

    # fig 1: detected vs seeded per stage (primary configuration)
    stages = list(R["headline"]["per_stage"])
    seeded = [R["headline"]["per_stage"][s]["seeded"] for s in stages]
    det = [R["headline"]["per_stage"][s]["detected"] for s in stages]
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    xs = range(len(stages))
    ax.bar(xs, seeded, color=grey, label="seeded flaws")
    ax.bar(xs, [d or 0 for d in det], color=blue, width=0.55, label="detected")
    for x, s, d, st in zip(xs, seeded, det, stages):
        cfg = R["headline"]["per_stage"][st]["config"]
        ax.text(x, s + 0.08, f"{d}/{s}" if d is not None else "not run", ha="center", color=ink, fontsize=10)
        ax.text(x, -0.55, cfg or "", ha="center", color=muted, fontsize=8)
    ax.set_xticks(list(xs)); ax.set_xticklabels(stages)
    ax.set_ylabel("seeded flaws"); ax.set_ylim(0, max(seeded) + 1)
    ax.set_title("Seeded flaws detected per stage (primary configuration)", loc="left", color=ink, fontsize=11)
    ax.legend(frameon=False, loc="upper right")
    fig.tight_layout(); fig.savefig(out / "fig-p2-01.png", dpi=160); plt.close(fig)

    # fig 2: findings by severity, vulnerable app, configurations that ran
    keys = [k for k, e in R["configs"].items() if e["apps"]["vulnerable"]["status"] == "ran"]
    if keys:
        fig, ax = plt.subplots(figsize=(7.0, 3.6))
        shades = {"Critical": "#7b1e1e", "High": "#c0392b", "Medium": "#e0953a", "Low": "#9aa5b1"}
        left = [0] * len(keys)
        for sev in SEVERITIES:
            vals = [R["configs"][k]["apps"]["vulnerable"]["by_severity"][sev] for k in keys]
            ax.barh(range(len(keys)), vals, left=left, color=shades[sev], label=sev)
            left = [l + v for l, v in zip(left, vals)]
        ax.set_yticks(range(len(keys))); ax.set_yticklabels(keys); ax.invert_yaxis()
        ax.set_xlabel("findings on demo-app/vulnerable")
        ax.set_title("Findings by severity", loc="left", color=ink, fontsize=11)
        ax.legend(frameon=False, ncol=4, loc="lower right")
        fig.tight_layout(); fig.savefig(out / "fig-p2-02.png", dpi=160); plt.close(fig)

    # fig 3: warm runtime
    t = [(s, v["warm_median"]) for s, v in R["timing"].items() if v["warm_median"] is not None]
    if t:
        fig, ax = plt.subplots(figsize=(5.6, 3.0))
        ax.barh([s for s, _ in t], [m for _, m in t], color=blue)
        for i, (_, m) in enumerate(t):
            ax.text(m, i, f" {m}s", va="center", color=ink)
        ax.invert_yaxis(); ax.set_xlabel("warm-cache runtime, seconds (median)")
        ax.set_title("Stage runtime on demo-app/vulnerable", loc="left", color=ink, fontsize=11)
        fig.tight_layout(); fig.savefig(out / "fig-p2-03.png", dpi=160); plt.close(fig)


if __name__ == "__main__":
    sys.exit(main())

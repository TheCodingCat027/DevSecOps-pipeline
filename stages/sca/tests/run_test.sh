#!/usr/bin/env bash
# stages/sca/tests/run_test.sh — integration tests for the SCA stage (Trivy fs)
#
# Run by `make test`.  Layers:
#   A. usage errors, fail-closed behaviour and the real binary's no-database failure  (always run)
#   B. converter / run.sh behaviour driven by a TEST DOUBLE (tests/fake-trivy.sh) replaying canned
#      reports from tests/fixtures/  -> these prove the stage logic, NOT Trivy's detection
#   C. ground truth on demo-app (V3) with the REAL scanner and the REAL vulnerability database
#      -> needs network access to the DB registry.  If the DB cannot be downloaded this prints
#         "NOT RUN (vulnerability DB unavailable): ..." — never a silent pass.
#
# If the pinned trivy binary cannot be installed at all the test prints
#   SKIPPED (tool unavailable): <reason>
# and exits 0; STAGE_TEST_STRICT=1 (CI) turns a skip OR a NOT RUN into a failure (exit 77).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$STAGE_DIR/../.." && pwd)"
RUN="$STAGE_DIR/run.sh"
FAKE="$SCRIPT_DIR/fake-trivy.sh"
FIX="$SCRIPT_DIR/fixtures"
VALIDATE_PY="$REPO_ROOT/contracts/validate.py"
PYTHON="${PYTHON:-python3}"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sca-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

FAILS=0
ok()   { echo "[test:sca]   ok   - $*" >&2; }
bad()  { echo "[test:sca]   FAIL - $*" >&2; FAILS=$((FAILS + 1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

# ---------------------------------------------------------------------------
# 0. Tool availability
# ---------------------------------------------------------------------------
if ! TRIVY_REAL="$(bash "$STAGE_DIR/install.sh" 2>"$TMP/install.log")"; then
    echo "[test:sca] SKIPPED (tool unavailable): could not install pinned trivy: $(tail -n1 "$TMP/install.log")" >&2
    [[ "${STAGE_TEST_STRICT:-0}" == "1" ]] && exit 77
    exit 0
fi
echo "[test:sca] trivy binary: $TRIVY_REAL" >&2

unset SCA_DB_REPOSITORY SCA_CACHE_DIR STAGE_TIMEOUT TRIVY_BIN 2>/dev/null || true
export SCA_DB_RETRY_DELAY=0

tree_hash() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1); }
count_results() { "$PYTHON" -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["runs"][0]["results"]))' "$1"; }
rule_ids() { "$PYTHON" -I -c 'import json,sys; print(" ".join(sorted(r["ruleId"] for r in json.load(open(sys.argv[1]))["runs"][0]["results"])))' "$1"; }

# Run the stage with the test double: fake_run <report.json> <target> <outdir> [extra env as VAR=val ...]
fake_run() {
    local report="$1" target="$2" out="$3"; shift 3
    env TRIVY_BIN="$FAKE" FAKE_TRIVY_REPORT="$report" SCA_CACHE_DIR="$TMP/cache-$(basename "$out")" "$@" \
        bash "$RUN" "$target" "$out"
}

# ---------------------------------------------------------------------------
# A1. Usage errors -> exit 2
# ---------------------------------------------------------------------------
echo "[test:sca] A1. usage errors" >&2
set +e
bash "$RUN" >/dev/null 2>&1;                          rc=$?; [[ $rc -eq 2 ]] && ok "no arguments -> exit 2" || bad "no arguments exited $rc"
bash "$RUN" "$TMP" >/dev/null 2>&1;                   rc=$?; [[ $rc -eq 2 ]] && ok "one argument -> exit 2" || bad "one argument exited $rc"
bash "$RUN" "$TMP" "$TMP/o" extra >/dev/null 2>&1;    rc=$?; [[ $rc -eq 2 ]] && ok "three arguments -> exit 2" || bad "three arguments exited $rc"
bash "$RUN" "$TMP/does-not-exist" "$TMP/o" >/dev/null 2>&1; rc=$?; [[ $rc -eq 2 ]] && ok "missing target -> exit 2" || bad "missing target exited $rc"
SCA_DB_RETRIES=abc bash "$RUN" "$TMP" "$TMP/o" >/dev/null 2>&1; rc=$?; [[ $rc -eq 2 ]] && ok "non-numeric SCA_DB_RETRIES -> exit 2" || bad "bad SCA_DB_RETRIES exited $rc"
SCA_DB_RETRIES=0 bash "$RUN" "$TMP" "$TMP/o" >/dev/null 2>&1; rc=$?; [[ $rc -eq 2 ]] && ok "SCA_DB_RETRIES=0 -> exit 2" || bad "SCA_DB_RETRIES=0 exited $rc"
set -e

# ---------------------------------------------------------------------------
# A2. The REAL binary without a reachable vulnerability DB fails closed
#     (empty private cache + a closed local port as DB repository -> fails in every environment)
# ---------------------------------------------------------------------------
echo "[test:sca] A2. real trivy, no database -> fail closed" >&2
mkdir -p "$TMP/real-target" "$TMP/out-nodb"; printf 'flask==3.1.0\n' > "$TMP/real-target/requirements.txt"
echo '{"stale":true}' > "$TMP/out-nodb/sca.sarif"
set +e
SCA_CACHE_DIR="$TMP/cache-empty" SCA_DB_REPOSITORY="127.0.0.1:9/none/trivy-db:2" SCA_DB_RETRIES=2 \
    bash "$RUN" "$TMP/real-target" "$TMP/out-nodb" >/dev/null 2>"$TMP/stderr-nodb"; rc=$?
set -e
[[ $rc -eq 1 ]] && ok "no vulnerability DB -> exit 1" || bad "no DB exited $rc (expected 1)"
[[ ! -e "$TMP/out-nodb/sca.sarif" ]] && ok "no SARIF left behind (stale file removed too)" || bad "SARIF exists after DB failure"
[[ "$(grep -c 'update attempt' "$TMP/stderr-nodb")" == "2" ]] && ok "DB download retried exactly SCA_DB_RETRIES times" || bad "wrong number of DB attempts"

# ---------------------------------------------------------------------------
# B1. Converter and orchestration with the test double (synthetic demo-app report)
# ---------------------------------------------------------------------------
echo "[test:sca] B1. known-bad fixture (test double, synthetic report)" >&2
BAD="$TMP/bad"; mkdir -p "$BAD/app"
cat > "$BAD/app/requirements.txt" <<'REQ'
# Flask==1.1.4 is mentioned in this comment but declared below
Flask==1.1.4
Jinja2==2.11.3
Werkzeug==1.0.1
MarkupSafe==1.1.1
REQ
cp "$FIX/synthetic-demo-app.json" "$TMP/report-bad.json"
# the synthetic report names the manifest "requirements.txt"; point Target at app/requirements.txt
"$PYTHON" -I - "$TMP/report-bad.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["Results"][0]["Target"] = "app/requirements.txt"; json.dump(d, open(p, "w"))
PY
H_BAD="$(tree_hash "$BAD")"
set +e; fake_run "$TMP/report-bad.json" "$BAD" "$TMP/out-bad" >"$TMP/stdout-bad" 2>"$TMP/stderr-bad"; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "exit 0 although findings exist" || { bad "exit code with findings was $rc (expected 0)"; tail -n 6 "$TMP/stderr-bad" >&2; }
[[ ! -s "$TMP/stdout-bad" ]] && ok "stdout is quiet" || bad "stdout is not empty"
check "validate.py --stage sca passes" "$PYTHON" "$VALIDATE_PY" "$TMP/out-bad/sca.sarif" --stage sca
n="$(count_results "$TMP/out-bad/sca.sarif")"
[[ "$n" == "5" ]] && ok "finding count = 5 (duplicate collapsed)" || bad "finding count = $n (expected 5)"
ids="$(rule_ids "$TMP/out-bad/sca.sarif")"
[[ "$ids" == "CVE-2000-00001 CVE-2023-25577 CVE-2023-30861 CVE-2024-34064 GHSA-xxxx-0000-yyyy" ]] && ok "expected rule ids" || bad "unexpected rule ids: $ids"
"$PYTHON" -I - "$TMP/out-bad/sca.sarif" <<'PY' && ok "severity map, optional properties, lines, ordering" || bad "result properties wrong"
import json, sys
res = json.load(open(sys.argv[1]))["runs"][0]["results"]
by = {(r["ruleId"], r["properties"]["package"]): r for r in res}
def P(k): return by[k]["properties"]
assert P(("CVE-2023-30861", "Flask"))["severity"] == "High" and P(("CVE-2023-30861", "Flask"))["raw_severity"] == "HIGH"
assert P(("CVE-2024-34064", "Jinja2"))["severity"] == "Medium"
assert P(("GHSA-xxxx-0000-yyyy", "Werkzeug"))["severity"] == "Low"        # unrecognised label -> Low (default rule)
assert P(("GHSA-xxxx-0000-yyyy", "Werkzeug"))["raw_severity"] == "WEIRD"
assert "cve_id" not in P(("GHSA-xxxx-0000-yyyy", "Werkzeug"))              # not a CVE id -> field omitted
assert P(("CVE-2000-00001", "MarkupSafe"))["severity"] == "Low" and P(("CVE-2000-00001", "MarkupSafe"))["raw_severity"] == "UNKNOWN"
f = P(("CVE-2023-30861", "Flask"))
assert f["cve_id"] == "CVE-2023-30861" and f["package"] == "Flask" and f["installed_version"] == "1.1.4"
assert f["fixed_version"] == "2.2.5, 2.3.2" and f["fix_available"] is True and f["cwe"] == "CWE-539", f
assert "Upgrade Flask" in f["fix"] and f["help_uri"].startswith("https://")
nf = P(("GHSA-xxxx-0000-yyyy", "Werkzeug"))
assert nf["fix_available"] is False and "fixed_version" not in nf and nf["fix"].startswith("No fixed version"), nf
single = P(("CVE-2023-25577", "Werkzeug"))
assert single["fix"] == "Upgrade Werkzeug from 1.0.1 to 2.2.3 or later.", single["fix"]
line = {k[1]: r["locations"][0]["physicalLocation"]["region"]["startLine"] for k, r in by.items()}
assert line == {"Flask": 2, "Jinja2": 3, "Werkzeug": 4, "MarkupSafe": 5}, line   # comment line 1 is skipped
for r in res:
    p = r["properties"]
    assert p["category"] == "sca"
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/requirements.txt"
keys = [(r["locations"][0]["physicalLocation"]["region"]["startLine"], r["properties"]["package"].lower(), r["ruleId"]) for r in res]
assert keys == sorted(keys), keys
run = json.load(open(sys.argv[1]))["runs"][0]
assert run["tool"]["driver"]["name"] == "trivy" and run["tool"]["driver"]["version"] == "0.76.1"
assert "db_updated_at" in run["properties"]
PY
[[ "$(tree_hash "$BAD")" == "$H_BAD" ]] && ok "target tree unmodified" || bad "target tree was modified"
fake_run "$TMP/report-bad.json" "$BAD" "$TMP/out-bad2" >/dev/null 2>&1
# provenance timestamp differs between the two fake DB downloads; compare everything else
"$PYTHON" -I - "$TMP/out-bad/sca.sarif" "$TMP/out-bad2/sca.sarif" <<'PY' && ok "two runs give identical findings" || bad "findings are not deterministic"
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
for d in (a, b): d["runs"][0].pop("properties")
assert a == b
PY
# byte-identical when the DB (and therefore its provenance) is the same: second run reuses the cache
env TRIVY_BIN="$FAKE" FAKE_TRIVY_REPORT="$TMP/report-bad.json" SCA_CACHE_DIR="$TMP/cache-out-bad" bash "$RUN" "$BAD" "$TMP/out-bad3" >/dev/null 2>&1
env TRIVY_BIN="$FAKE" FAKE_TRIVY_REPORT="$TMP/report-bad.json" SCA_CACHE_DIR="$TMP/cache-out-bad" bash "$RUN" "$BAD" "$TMP/out-bad4" >/dev/null 2>&1
cmp -s "$TMP/out-bad3/sca.sarif" "$TMP/out-bad4/sca.sarif" && ok "two runs on the same DB are byte-identical" || bad "output is not byte-identical"

# real upstream report: line numbers come from Trivy's Packages[].Locations
echo "[test:sca] B2. real upstream report shape" >&2
mkdir -p "$TMP/pip"; printf 'click==7.0\nFlask==2.0.0\n' > "$TMP/pip/requirements.txt"
set +e; fake_run "$FIX/upstream-pip.json" "$TMP/pip" "$TMP/out-pip" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "upstream report converts (exit 0)" || bad "upstream report exited $rc"
check "upstream report SARIF validates" "$PYTHON" "$VALIDATE_PY" "$TMP/out-pip/sca.sarif" --stage sca
"$PYTHON" -I - "$TMP/out-pip/sca.sarif" <<'PY' && ok "upstream: Trivy Locations line, CWE, GHSA/CVE handling" || bad "upstream conversion wrong"
import json, sys
res = json.load(open(sys.argv[1]))["runs"][0]["results"]
assert res and all(r["properties"]["category"] == "sca" for r in res)
w = [r for r in res if r["ruleId"] == "CVE-2019-14806"][0]
assert w["locations"][0]["physicalLocation"]["region"]["startLine"] == 6        # StartLine from Trivy's Packages[].Locations
assert w["properties"]["cwe"] == "CWE-331" and w["properties"]["severity"] == "High"
PY

# ---------------------------------------------------------------------------
# B3. Clean and "no manifests" targets -> valid empty reports (NOT failures)
# ---------------------------------------------------------------------------
echo "[test:sca] B3. clean and no-manifest targets" >&2
mkdir -p "$TMP/clean"; printf 'flask==3.1.0\n' > "$TMP/clean/requirements.txt"
set +e; fake_run "$FIX/clean.json" "$TMP/clean" "$TMP/out-clean" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "clean fixture exits 0" || bad "clean fixture exited $rc"
check "clean SARIF validates" "$PYTHON" "$VALIDATE_PY" "$TMP/out-clean/sca.sarif" --stage sca
[[ "$(count_results "$TMP/out-clean/sca.sarif")" == "0" ]] && ok "zero findings on clean fixture" || bad "clean fixture produced findings"
mkdir -p "$TMP/nomani"; echo "hello" > "$TMP/nomani/README.txt"
set +e; fake_run "$FIX/no-manifests.json" "$TMP/nomani" "$TMP/out-nomani" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "tree without manifests exits 0" || bad "no-manifest tree exited $rc"
[[ -f "$TMP/out-nomani/sca.sarif" && "$(count_results "$TMP/out-nomani/sca.sarif")" == "0" ]] && ok "no manifests -> valid empty SARIF" || bad "no-manifest SARIF missing or non-empty"
check "no-manifest SARIF validates" "$PYTHON" "$VALIDATE_PY" "$TMP/out-nomani/sca.sarif" --stage sca

# ---------------------------------------------------------------------------
# B4. Fail closed: scanner / DB / report problems -> exit 1 and NO SARIF
# ---------------------------------------------------------------------------
echo "[test:sca] B4. fail closed" >&2
expect_fail() { # expect_fail "<description>" <outdir> <env...>
    local d="$1" out="$2"; shift 2
    mkdir -p "$out"; echo '{"stale":true}' > "$out/sca.sarif"
    set +e; fake_run "$FIX/synthetic-demo-app.json" "$BAD" "$out" "$@" >/dev/null 2>&1; local rc=$?; set -e
    [[ $rc -eq 1 ]] && ok "$d -> exit 1" || bad "$d exited $rc (expected 1)"
    [[ ! -e "$out/sca.sarif" ]] && ok "$d: no SARIF left behind" || bad "$d: SARIF exists after failure"
}
expect_fail "scanner crash" "$TMP/f-crash" FAKE_TRIVY_MODE=crash
expect_fail "scanner timeout" "$TMP/f-hang" FAKE_TRIVY_MODE=hang STAGE_TIMEOUT=2
expect_fail "unparsable scanner output" "$TMP/f-garbage" FAKE_TRIVY_MODE=garbage
expect_fail "DB download fails, no cache" "$TMP/f-nodb" FAKE_TRIVY_DB_FAIL=1
echo '{"foo": 1}' > "$TMP/not-trivy.json"
mkdir -p "$TMP/f-schema"; echo '{"stale":true}' > "$TMP/f-schema/sca.sarif"
set +e; fake_run "$TMP/not-trivy.json" "$BAD" "$TMP/f-schema" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 && ! -e "$TMP/f-schema/sca.sarif" ]] && ok "JSON that is not a Trivy report -> exit 1, no SARIF" || bad "foreign JSON accepted (rc=$rc)"
set +e; TRIVY_BIN="$TMP/missing-binary" bash "$RUN" "$BAD" "$TMP/f-nobin" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 && ! -e "$TMP/f-nobin/sca.sarif" ]] && ok "missing tool binary -> exit 1" || bad "missing binary exited $rc"

# DB cache behaviour: retries, fresh-enough cache, stale cache
cnt="$TMP/db-attempts"; : > "$cnt"
set +e; fake_run "$FIX/synthetic-demo-app.json" "$BAD" "$TMP/f-retry" FAKE_TRIVY_DB_FAIL=1 FAKE_TRIVY_DB_COUNT="$cnt" SCA_DB_RETRIES=3 >/dev/null 2>&1; set -e
[[ "$(wc -l < "$cnt")" == "3" ]] && ok "DB download retried 3 times (bounded)" || bad "DB retries: $(wc -l < "$cnt") (expected 3)"

mkcache() { # mkcache <dir> <days-old>
    mkdir -p "$1/db"; echo fake > "$1/db/trivy.db"
    "$PYTHON" -I - "$1/db/metadata.json" "$2" <<'PY'
import json, sys, datetime
t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=int(sys.argv[2]))
json.dump({"Version": 2, "UpdatedAt": t.strftime("%Y-%m-%dT%H:%M:%SZ")}, open(sys.argv[1], "w"))
PY
}
mkcache "$TMP/cache-fresh" 2
set +e; env TRIVY_BIN="$FAKE" FAKE_TRIVY_REPORT="$FIX/synthetic-demo-app.json" FAKE_TRIVY_DB_FAIL=1 SCA_CACHE_DIR="$TMP/cache-fresh" \
    bash "$RUN" "$BAD" "$TMP/o-fresh" >/dev/null 2>"$TMP/stderr-fresh"; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "DB update fails but a 2-day-old cached DB is used" || bad "fresh cache fallback exited $rc"
grep -q 'cached vulnerability DB' "$TMP/stderr-fresh" && ok "cache fallback is announced on stderr" || bad "cache fallback is silent"
mkcache "$TMP/cache-stale" 30
mkdir -p "$TMP/o-stale"; echo '{"stale":true}' > "$TMP/o-stale/sca.sarif"
set +e; env TRIVY_BIN="$FAKE" FAKE_TRIVY_REPORT="$FIX/synthetic-demo-app.json" FAKE_TRIVY_DB_FAIL=1 SCA_CACHE_DIR="$TMP/cache-stale" \
    bash "$RUN" "$BAD" "$TMP/o-stale" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 && ! -e "$TMP/o-stale/sca.sarif" ]] && ok "30-day-old cached DB is refused (exit 1, no SARIF)" || bad "stale cache accepted (rc=$rc)"
set +e; env TRIVY_BIN="$FAKE" FAKE_TRIVY_REPORT="$FIX/synthetic-demo-app.json" FAKE_TRIVY_DB_FAIL=1 SCA_CACHE_DIR="$TMP/cache-stale" SCA_DB_MAX_AGE_DAYS=60 \
    bash "$RUN" "$BAD" "$TMP/o-stale2" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "SCA_DB_MAX_AGE_DAYS=60 accepts the 30-day-old cache" || bad "max-age override ignored (rc=$rc)"
set +e; fake_run "$FIX/synthetic-demo-app.json" "$BAD" "$TMP/o-incache" SCA_CACHE_DIR="$BAD/.cache" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "cache directory inside the target is refused" || bad "cache inside target exited $rc"
[[ "$(tree_hash "$BAD")" == "$H_BAD" ]] && ok "target tree still unmodified after all failure cases" || bad "target tree modified by a failing run"

# ---------------------------------------------------------------------------
# C. Ground truth on the demo app with the REAL scanner and REAL database
# ---------------------------------------------------------------------------
echo "[test:sca] C. demo-app ground truth (real trivy, real database)" >&2
VULN="$REPO_ROOT/demo-app/vulnerable"; FIXED="$REPO_ROOT/demo-app/fixed"
set +e
SCA_DB_RETRIES=1 bash "$RUN" "$VULN" "$TMP/out-vuln" >/dev/null 2>"$TMP/stderr-vuln"; rc=$?
set -e
if [[ $rc -ne 0 ]]; then
    echo "[test:sca] NOT RUN (vulnerability DB unavailable): V3 ground truth NOT verified — $(grep -E 'ERROR' "$TMP/stderr-vuln" | tail -n1 | sed 's/^\[sca\] //')" >&2
    echo "[test:sca] NOT RUN: re-run where the DB registry (mirror.gcr.io / ghcr.io, or SCA_DB_REPOSITORY) is reachable" >&2
    NOT_RUN=1
else
    NOT_RUN=0
    H_VULN="$(tree_hash "$VULN")"
    ok "vulnerable app: exit 0"
    check "vulnerable app SARIF validates" "$PYTHON" "$VALIDATE_PY" "$TMP/out-vuln/sca.sarif" --stage sca
    "$PYTHON" -I - "$TMP/out-vuln/sca.sarif" "$REPO_ROOT/demo-app/seeded-vulnerabilities.json" <<'PY' \
        && ok "every seeded CVE (V3a-c) is reported on its requirements.txt line" \
        || bad "a seeded V3 CVE was NOT reported"
import json, sys
res = json.load(open(sys.argv[1]))["runs"][0]["results"]
seeded = [v for v in json.load(open(sys.argv[2]))["vulnerabilities"] if v["class"] == "sca"]
assert seeded
for v in seeded:
    hit = [r for r in res if r["ruleId"] in v["cve_ids"]
           and r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == v["file"]
           and abs(r["locations"][0]["physicalLocation"]["region"].get("startLine", 0) - v["line"]) <= 2]
    assert hit, f"{v['id']} ({v['cve_ids']}) not reported"
PY
    [[ "$(tree_hash "$VULN")" == "$H_VULN" ]] && ok "demo-app/vulnerable unmodified by the scan" || bad "demo-app/vulnerable was modified"
    ( cd "$REPO_ROOT" && bash "$RUN" demo-app/vulnerable "$TMP/out-rel" >/dev/null 2>&1 )
    cmp -s "$TMP/out-rel/sca.sarif" "$TMP/out-vuln/sca.sarif" && ok "relative target gives identical SARIF" || bad "relative/absolute targets differ"
    bash "$RUN" "$FIXED" "$TMP/out-fixed" >/dev/null 2>&1 && rc=0 || rc=$?
    [[ $rc -eq 0 ]] && ok "fixed app: exit 0" || bad "fixed app exited $rc"
    echo "[test:sca]   info - fixed app has $(count_results "$TMP/out-fixed/sca.sarif") SCA finding(s) (reported, not asserted: depends on the live DB)" >&2
fi

# ---------------------------------------------------------------------------
echo "" >&2
if [[ $FAILS -ne 0 ]]; then
    echo "[test:sca] FAIL: $FAILS check(s) failed" >&2
    exit 1
fi
if [[ $NOT_RUN -eq 1 ]]; then
    echo "[test:sca] PASS (layers A+B) — layer C NOT RUN, see above" >&2
    [[ "${STAGE_TEST_STRICT:-0}" == "1" ]] && exit 77
    exit 0
fi
echo "[test:sca] PASS (all checks)" >&2
exit 0

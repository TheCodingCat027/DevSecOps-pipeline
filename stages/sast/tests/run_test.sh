#!/usr/bin/env bash
# stages/sast/tests/run_test.sh — integration tests for the SAST stage (Semgrep)
#
# Run by `make test`.  Needs the pinned Semgrep (installed on demand into the cache by
# stages/sast/install.sh).  If it cannot be installed the test prints
#   SKIPPED (tool unavailable): <reason>
# and exits 0 so `make test` keeps working offline; set STAGE_TEST_STRICT=1 (e.g. in CI)
# to turn a skip into a failure (exit 77).
#
# The tests are HERMETIC: they never contact the Semgrep registry.  The pipeline scans use
# SAST_REGISTRY_PACKS="" (local rules only); registry behaviour (fail closed when it is
# unreachable) is tested by pointing the reachability probe at a closed local port.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$STAGE_DIR/../.." && pwd)"
RUN="$STAGE_DIR/run.sh"
VALIDATE_PY="$REPO_ROOT/contracts/validate.py"
PYTHON="${PYTHON:-python3}"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sast-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

FAILS=0
ok()   { echo "[test:sast]   ok   - $*" >&2; }
bad()  { echo "[test:sast]   FAIL - $*" >&2; FAILS=$((FAILS + 1)); }
check() { # check "<description>" <command...>
    local d="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}

# ---------------------------------------------------------------------------
# 0. Tool availability
# ---------------------------------------------------------------------------
if ! SEMGREP="$(bash "$STAGE_DIR/install.sh" 2>"$TMP/install.log")"; then
    echo "[test:sast] SKIPPED (tool unavailable): could not install pinned semgrep: $(tail -n1 "$TMP/install.log")" >&2
    [[ "${STAGE_TEST_STRICT:-0}" == "1" ]] && exit 77
    exit 0
fi
echo "[test:sast] semgrep binary: $SEMGREP" >&2

# Hermetic by default: local rules only, no registry traffic.
export SAST_REGISTRY_PACKS=""
unset SAST_ALLOW_OFFLINE SAST_CUSTOM_RULES SAST_RULES_DIR SEMGREP_BIN STAGE_TIMEOUT 2>/dev/null || true

tree_hash() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1); }
count_results() { "$PYTHON" -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["runs"][0]["results"]))' "$1"; }
rule_ids() { "$PYTHON" -I -c 'import json,sys; print(" ".join(sorted(r["ruleId"] for r in json.load(open(sys.argv[1]))["runs"][0]["results"])))' "$1"; }

# ---------------------------------------------------------------------------
# 1. Custom rule unit tests (# ruleid: / # ok: annotations)
# ---------------------------------------------------------------------------
echo "[test:sast] 1. custom rule tests (semgrep --test)" >&2
set +e
SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SETTINGS_FILE="$TMP/settings.yml" \
    SEMGREP_VERSION_CACHE_PATH="$TMP/vcache" SEMGREP_LOG_FILE="$TMP/semgrep-test.log" \
    "$SEMGREP" --test --metrics=off --disable-version-check --config "$STAGE_DIR/rules" "$STAGE_DIR/rules/tests" \
    >"$TMP/rule-tests.out" 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then ok "semgrep --test passes for every custom rule"; else bad "semgrep --test failed (rc=$rc)"; sed 's/^/[test:sast]   | /' "$TMP/rule-tests.out" >&2; fi
n_rules=$(cat "$STAGE_DIR"/rules/*.yaml | grep -c '^  - id:')
n_tests=$(ls "$STAGE_DIR"/rules/tests/*.py | wc -l)
[[ "$n_rules" -ge 3 && "$n_tests" -ge "$n_rules" ]] && ok "every custom rule ($n_rules) has a test file" || bad "rules ($n_rules) vs test files ($n_tests) mismatch"
for f in "$STAGE_DIR"/rules/*.yaml; do
    id="$(grep -m1 '^  - id:' "$f" | awk '{print $3}')"
    pos=$(grep -c "# ruleid: $id" "$STAGE_DIR"/rules/tests/*.py | awk -F: '{s+=$2} END{print s}')
    neg=$(grep -c "# ok: $id" "$STAGE_DIR"/rules/tests/*.py | awk -F: '{s+=$2} END{print s}')
    [[ "$pos" -ge 2 && "$neg" -ge 2 ]] && ok "$id: $pos positive / $neg negative cases" || bad "$id has only $pos positive / $neg negative cases (need >= 2 each)"
done

# ---------------------------------------------------------------------------
# 2. Usage errors -> exit 2
# ---------------------------------------------------------------------------
echo "[test:sast] 2. usage errors" >&2
set +e
bash "$RUN" >/dev/null 2>&1;                          rc=$?; [[ $rc -eq 2 ]] && ok "no arguments -> exit 2" || bad "no arguments exited $rc"
bash "$RUN" "$TMP" >/dev/null 2>&1;                   rc=$?; [[ $rc -eq 2 ]] && ok "one argument -> exit 2" || bad "one argument exited $rc"
bash "$RUN" "$TMP" "$TMP/o" extra >/dev/null 2>&1;    rc=$?; [[ $rc -eq 2 ]] && ok "three arguments -> exit 2" || bad "three arguments exited $rc"
bash "$RUN" "$TMP/does-not-exist" "$TMP/o" >/dev/null 2>&1; rc=$?; [[ $rc -eq 2 ]] && ok "missing target -> exit 2" || bad "missing target exited $rc"
SAST_CUSTOM_RULES=2 bash "$RUN" "$TMP" "$TMP/o" >/dev/null 2>&1; rc=$?; [[ $rc -eq 2 ]] && ok "invalid SAST_CUSTOM_RULES -> exit 2" || bad "invalid SAST_CUSTOM_RULES exited $rc"
SAST_CUSTOM_RULES=0 bash "$RUN" "$TMP" "$TMP/o" >/dev/null 2>&1; rc=$?; [[ $rc -eq 2 ]] && ok "no rules selected -> exit 2" || bad "no rules selected exited $rc"
set -e

# ---------------------------------------------------------------------------
# 3. Known-bad fixture: SQLi (V2 pattern), MD5 password (V6), debug=True (V7)
# ---------------------------------------------------------------------------
echo "[test:sast] 3. known-bad fixture" >&2
BAD="$TMP/bad"; mkdir -p "$BAD/app" "$BAD/app/tests"
cat > "$BAD/app/web.py" <<'PY'
import hashlib
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def users():
    name = request.args.get("name", "")
    db = sqlite3.connect("x.db")
    query = "SELECT id FROM users WHERE name = '" + name + "'"
    return str(db.execute(query).fetchall())


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    app.run(debug=True)
PY
# test code must be excluded from the scan (noise control), even though it is vulnerable
cat > "$BAD/app/tests/test_web.py" <<'PY'
import sqlite3
def test_x(name):
    sqlite3.connect("x.db").execute("SELECT 1 WHERE a = '" + name + "'")
PY
H_BAD="$(tree_hash "$BAD")"

set +e; bash "$RUN" "$BAD" "$TMP/out-bad" >"$TMP/stdout-bad" 2>"$TMP/stderr-bad"; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "exit 0 although findings exist" || { bad "exit code with findings was $rc (expected 0)"; tail -n 8 "$TMP/stderr-bad" >&2; }
[[ ! -s "$TMP/stdout-bad" ]] && ok "stdout is quiet" || bad "stdout is not empty"
[[ -f "$TMP/out-bad/sast.sarif" ]] && ok "sast.sarif written" || bad "sast.sarif missing"
check "validate.py --stage sast passes" "$PYTHON" "$VALIDATE_PY" "$TMP/out-bad/sast.sarif" --stage sast
n="$(count_results "$TMP/out-bad/sast.sarif")"
[[ "$n" == "3" ]] && ok "finding count = 3 (test directory excluded)" || bad "finding count = $n (expected 3)"
ids="$(rule_ids "$TMP/out-bad/sast.sarif")"
[[ "$ids" == "devsecops-flask-debug-enabled devsecops-python-sql-injection-string-built-query devsecops-python-weak-hash-for-password" ]] \
    && ok "expected rule ids" || bad "unexpected rule ids: $ids"
"$PYTHON" -I - "$TMP/out-bad/sast.sarif" <<'PY' && ok "severity/category/cwe/fix/confidence/raw_severity/uri/line populated" || bad "result properties wrong"
import json, sys
res = json.load(open(sys.argv[1]))["runs"][0]["results"]
by = {r["ruleId"]: r for r in res}
sev = {k: v["properties"]["severity"] for k, v in by.items()}
assert sev["devsecops-python-sql-injection-string-built-query"] == "High", sev       # ERROR
assert sev["devsecops-python-weak-hash-for-password"] == "High", sev                # ERROR
assert sev["devsecops-flask-debug-enabled"] == "Medium", sev                        # WARNING
cwe = {k: v["properties"].get("cwe") for k, v in by.items()}
assert cwe["devsecops-python-sql-injection-string-built-query"] == "CWE-89", cwe
assert cwe["devsecops-python-weak-hash-for-password"] == "CWE-327", cwe
for r in res:
    p = r["properties"]
    assert p["category"] == "sast" and p["fix"] and p["raw_severity"] in ("ERROR", "WARNING", "INFO"), p
    assert p["confidence"] in ("high", "medium", "low"), p
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/web.py", loc    # outside the repo -> relative to target
    assert loc["region"]["startLine"] >= 1
keys = [(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
         r["locations"][0]["physicalLocation"]["region"]["startLine"], r["ruleId"]) for r in res]
assert keys == sorted(keys) and len(keys) == len(set(keys)), keys                   # ordered, no duplicates
PY
[[ "$(tree_hash "$BAD")" == "$H_BAD" ]] && ok "target tree unmodified" || bad "target tree was modified"
bash "$RUN" "$BAD" "$TMP/out-bad2" >/dev/null 2>&1
cmp -s "$TMP/out-bad/sast.sarif" "$TMP/out-bad2/sast.sarif" && ok "two runs are byte-identical" || bad "output is not deterministic"
# SARIF records which rule sources were applied (traceability)
grep -q '"registry_packs_applied": false' "$TMP/out-bad/sast.sarif" && ok "SARIF states that no registry packs were applied" || bad "SARIF does not record the rule sources"

# ---------------------------------------------------------------------------
# 4. Clean fixture (the safe counterparts) -> zero findings
# ---------------------------------------------------------------------------
echo "[test:sast] 4. clean fixture" >&2
CLEAN="$TMP/clean"; mkdir -p "$CLEAN/app"
cat > "$CLEAN/app/web.py" <<'PY'
import hashlib
import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def users():
    name = request.args.get("name", "")
    db = sqlite3.connect("x.db")
    return str(db.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchall())


def hash_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def etag(blob):
    return hashlib.md5(blob).hexdigest()  # not password handling


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
PY
set +e; bash "$RUN" "$CLEAN" "$TMP/out-clean" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "clean fixture exits 0" || bad "clean fixture exited $rc"
check "clean SARIF validates" "$PYTHON" "$VALIDATE_PY" "$TMP/out-clean/sast.sarif" --stage sast
[[ "$(count_results "$TMP/out-clean/sast.sarif")" == "0" ]] && ok "zero findings on clean fixture" || bad "clean fixture produced findings"

# ---------------------------------------------------------------------------
# 5. Fail closed: scanner failure / registry unavailable -> exit 1 and NO sarif
# ---------------------------------------------------------------------------
echo "[test:sast] 5. fail closed" >&2
mkdir -p "$TMP/badrules" "$TMP/out-fail"
printf 'rules:\n  - id: [this is not valid\n    pattern: (((\n' > "$TMP/badrules/broken.yaml"
echo '{"stale":true}' > "$TMP/out-fail/sast.sarif"
set +e; SAST_RULES_DIR="$TMP/badrules" bash "$RUN" "$BAD" "$TMP/out-fail" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "invalid rule file -> exit 1" || bad "invalid rule file exited $rc (expected 1)"
[[ ! -e "$TMP/out-fail/sast.sarif" ]] && ok "no SARIF left behind (stale file removed too)" || bad "SARIF exists after failure"

printf '#!/usr/bin/env bash\n[[ "${1:-}" == --version ]] && { echo 1.182.1; exit 0; }\necho boom >&2; exit 3\n' > "$TMP/crash-semgrep"
chmod +x "$TMP/crash-semgrep"
set +e; SEMGREP_BIN="$TMP/crash-semgrep" bash "$RUN" "$BAD" "$TMP/out-crash" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "crashing scanner -> exit 1" || bad "crashing scanner exited $rc"
[[ ! -e "$TMP/out-crash/sast.sarif" ]] && ok "no SARIF after crash" || bad "SARIF exists after crash"

printf '#!/usr/bin/env bash\n[[ "${1:-}" == --version ]] && { echo 1.182.1; exit 0; }\nsleep 30\n' > "$TMP/hang-semgrep"
chmod +x "$TMP/hang-semgrep"
set +e; STAGE_TIMEOUT=2 SEMGREP_BIN="$TMP/hang-semgrep" bash "$RUN" "$BAD" "$TMP/out-hang" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "timeout -> exit 1" || bad "hanging scanner exited $rc"
[[ ! -e "$TMP/out-hang/sast.sarif" ]] && ok "no SARIF after timeout" || bad "SARIF exists after timeout"

printf '#!/usr/bin/env bash\n[[ "${1:-}" == --version ]] && { echo 1.182.1; exit 0; }\nfor a in "$@"; do [[ "$prev" == --output ]] && printf "not json {" > "$a"; prev="$a"; done\nexit 0\n' > "$TMP/garbage-semgrep"
sed -i '2i prev=""' "$TMP/garbage-semgrep"; chmod +x "$TMP/garbage-semgrep"
set +e; SEMGREP_BIN="$TMP/garbage-semgrep" bash "$RUN" "$BAD" "$TMP/out-garbage" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "unparsable scanner output -> exit 1" || bad "unparsable output exited $rc"
[[ ! -e "$TMP/out-garbage/sast.sarif" ]] && ok "no SARIF after unparsable output" || bad "SARIF exists after unparsable output"

set +e; SEMGREP_BIN="$TMP/missing-binary" bash "$RUN" "$BAD" "$TMP/out-nobin" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "missing tool binary -> exit 1" || bad "missing binary exited $rc"

# registry unreachable: closed local port stands in for semgrep.dev
set +e
SAST_REGISTRY_PACKS="p/python" SAST_REGISTRY_URL="http://127.0.0.1:9" bash "$RUN" "$BAD" "$TMP/out-reg" >/dev/null 2>&1; rc=$?
set -e
[[ $rc -eq 1 ]] && ok "registry unreachable without SAST_ALLOW_OFFLINE -> exit 1" || bad "unreachable registry exited $rc (expected 1)"
[[ ! -e "$TMP/out-reg/sast.sarif" ]] && ok "no SARIF when the registry is unreachable" || bad "SARIF exists although the registry was unreachable"
set +e
SAST_ALLOW_OFFLINE=1 SAST_REGISTRY_PACKS="p/python" SAST_REGISTRY_URL="http://127.0.0.1:9" \
    bash "$RUN" "$BAD" "$TMP/out-off" >/dev/null 2>"$TMP/stderr-off"; rc=$?
set -e
[[ $rc -eq 0 ]] && ok "SAST_ALLOW_OFFLINE=1 -> local-rules-only scan succeeds" || bad "offline fallback exited $rc"
grep -q 'LOCAL RULES ONLY' "$TMP/stderr-off" && ok "offline fallback prints a loud warning" || bad "offline fallback is silent"
[[ "$(count_results "$TMP/out-off/sast.sarif")" == "3" ]] && ok "offline fallback still finds the 3 flaws" || bad "offline fallback finding count wrong"
grep -q '"registry_packs_applied": false' "$TMP/out-off/sast.sarif" && ok "SARIF records that registry packs were NOT applied" || bad "SARIF hides the missing registry coverage"

# ---------------------------------------------------------------------------
# 6. Real demo app: V2, V6, V7 detected; fixed app clean
# ---------------------------------------------------------------------------
echo "[test:sast] 6. demo-app ground truth" >&2
VULN="$REPO_ROOT/demo-app/vulnerable"; FIXED="$REPO_ROOT/demo-app/fixed"
H_VULN="$(tree_hash "$VULN")"
bash "$RUN" "$VULN" "$TMP/out-vuln" >/dev/null 2>&1 && rc=0 || rc=$?
[[ $rc -eq 0 ]] && ok "vulnerable app: exit 0" || bad "vulnerable app exited $rc"
check "vulnerable app SARIF validates" "$PYTHON" "$VALIDATE_PY" "$TMP/out-vuln/sast.sarif" --stage sast
"$PYTHON" -I - "$TMP/out-vuln/sast.sarif" "$REPO_ROOT/demo-app/seeded-vulnerabilities.json" <<'PY' \
    && ok "every seeded SAST flaw (V2, V6, V7) is detected within +-2 lines" \
    || bad "a seeded SAST flaw was NOT detected"
import json, sys
res = json.load(open(sys.argv[1]))["runs"][0]["results"]
seeded = [v for v in json.load(open(sys.argv[2]))["vulnerabilities"] if v["class"] == "sast"]
assert {v["id"] for v in seeded} >= {"V2", "V6", "V7"}, seeded
for v in seeded:
    hit = [r for r in res
           if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == v["file"]
           and abs(r["locations"][0]["physicalLocation"]["region"]["startLine"] - v["line"]) <= 2]
    assert hit, f"{v['id']} not detected"
for r in res:
    uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.startswith("demo-app/vulnerable/") and not uri.startswith("/"), uri
PY
[[ "$(tree_hash "$VULN")" == "$H_VULN" ]] && ok "demo-app/vulnerable unmodified by the scan" || bad "demo-app/vulnerable was modified"

( cd "$REPO_ROOT" && bash "$RUN" demo-app/vulnerable "$TMP/out-rel" >/dev/null 2>&1 )
( cd "$TMP" && bash "$RUN" "$VULN" "$TMP/out-abs" >/dev/null 2>&1 )
cmp -s "$TMP/out-rel/sast.sarif" "$TMP/out-abs/sast.sarif" \
    && cmp -s "$TMP/out-rel/sast.sarif" "$TMP/out-vuln/sast.sarif" \
    && ok "relative / absolute target and any cwd give identical SARIF" || bad "path forms differ"

H_FIXED="$(tree_hash "$FIXED")"
bash "$RUN" "$FIXED" "$TMP/out-fixed" >/dev/null 2>&1 && rc=0 || rc=$?
[[ $rc -eq 0 ]] && ok "fixed app: exit 0" || bad "fixed app exited $rc"
[[ "$(count_results "$TMP/out-fixed/sast.sarif")" == "0" ]] && ok "fixed app: zero findings" || bad "fixed app has findings"
[[ "$(tree_hash "$FIXED")" == "$H_FIXED" ]] && ok "demo-app/fixed unmodified" || bad "demo-app/fixed was modified"

# ---------------------------------------------------------------------------
echo "" >&2
if [[ $FAILS -eq 0 ]]; then
    echo "[test:sast] PASS (all checks)" >&2
    exit 0
fi
echo "[test:sast] FAIL: $FAILS check(s) failed" >&2
exit 1

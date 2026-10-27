#!/usr/bin/env bash
# stages/secrets/tests/run_test.sh — integration tests for the secrets stage (Gitleaks)
#
# Run by `make test`.  Needs the pinned gitleaks binary (installed on demand into the
# cache by stages/secrets/install.sh).  If it cannot be installed the test prints
#   SKIPPED (tool unavailable): <reason>
# and exits 0 so that `make test` keeps working offline; set STAGE_TEST_STRICT=1
# (e.g. in CI) to turn a skip into a failure (exit 77).
#
# No complete secret-looking string is committed: the fake credentials used by the
# fixtures are assembled from parts at run time, inside a temp directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$STAGE_DIR/../.." && pwd)"
RUN="$STAGE_DIR/run.sh"
VALIDATE_PY="$REPO_ROOT/contracts/validate.py"
PYTHON="${PYTHON:-python3}"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/secrets-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

FAILS=0
ok()   { echo "[test:secrets]   ok   - $*" >&2; }
bad()  { echo "[test:secrets]   FAIL - $*" >&2; FAILS=$((FAILS + 1)); }
check() { # check "<description>" <command...>
    local d="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}

# ---------------------------------------------------------------------------
# 0. Tool availability
# ---------------------------------------------------------------------------
if ! BIN_CHECK="$(bash "$STAGE_DIR/install.sh" 2>"$TMP/install.log")"; then
    echo "[test:secrets] SKIPPED (tool unavailable): could not install pinned gitleaks: $(tail -n1 "$TMP/install.log")" >&2
    [[ "${STAGE_TEST_STRICT:-0}" == "1" ]] && exit 77
    exit 0
fi
echo "[test:secrets] gitleaks binary: $BIN_CHECK" >&2

tree_hash() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1); }
count_results() { "$PYTHON" -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["runs"][0]["results"]))' "$1"; }
rule_ids() { "$PYTHON" -I -c 'import json,sys; print(" ".join(sorted(r["ruleId"] for r in json.load(open(sys.argv[1]))["runs"][0]["results"])))' "$1"; }

# ---------------------------------------------------------------------------
# 1. Usage errors -> exit 2
# ---------------------------------------------------------------------------
echo "[test:secrets] 1. usage errors" >&2
set +e
bash "$RUN" >/dev/null 2>&1;                          rc=$?; [[ $rc -eq 2 ]] && ok "no arguments -> exit 2" || bad "no arguments exited $rc"
bash "$RUN" "$TMP" >/dev/null 2>&1;                   rc=$?; [[ $rc -eq 2 ]] && ok "one argument -> exit 2" || bad "one argument exited $rc"
bash "$RUN" "$TMP" "$TMP/o" extra >/dev/null 2>&1;    rc=$?; [[ $rc -eq 2 ]] && ok "three arguments -> exit 2" || bad "three arguments exited $rc"
bash "$RUN" "$TMP/does-not-exist" "$TMP/o" >/dev/null 2>&1; rc=$?; [[ $rc -eq 2 ]] && ok "missing target -> exit 2" || bad "missing target exited $rc"
set -e

# ---------------------------------------------------------------------------
# 2. Known-bad fixture (generated at test time; values assembled from parts)
# ---------------------------------------------------------------------------
echo "[test:secrets] 2. known-bad fixture" >&2
BAD="$TMP/bad"; mkdir -p "$BAD/app"
P_AKIA="AKIA"; P_ID="FAKEKEYFORTEST""S2"                 # AWS access key id (fake)
P_SEC1="fakeSecretAccessKey""ForTests"; P_SEC2="0123456789ABCDEFGHIJ""KLMNOPQRSTUV"  # 40+ chars (fake)
P_SK1="not-a-real-"; P_SK2="flask-session-key"
{
    echo "AWS_ACCESS_KEY_ID = \"${P_AKIA}${P_ID}\""
    echo "AWS_SECRET_ACCESS_KEY = \"${P_SEC1}${P_SEC2}\""
    echo "SECRET_KEY = \"${P_SK1}${P_SK2}\""
} > "$BAD/app/settings.py"
FAKE_VALUES=("${P_AKIA}${P_ID}" "${P_SEC1}${P_SEC2}" "${P_SK1}${P_SK2}" "$P_ID" "$P_SEC2")
H_BAD="$(tree_hash "$BAD")"

set +e; bash "$RUN" "$BAD" "$TMP/out-bad" >"$TMP/stdout-bad" 2>"$TMP/stderr-bad"; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "exit 0 although findings exist" || bad "exit code with findings was $rc (expected 0)"
[[ ! -s "$TMP/stdout-bad" ]] && ok "stdout is quiet" || bad "stdout is not empty"
[[ -f "$TMP/out-bad/secrets.sarif" ]] && ok "secrets.sarif written" || bad "secrets.sarif missing"
check "validate.py --stage secrets passes" "$PYTHON" "$VALIDATE_PY" "$TMP/out-bad/secrets.sarif" --stage secrets
n="$(count_results "$TMP/out-bad/secrets.sarif")"
[[ "$n" == "3" ]] && ok "finding count = 3" || bad "finding count = $n (expected 3)"
ids="$(rule_ids "$TMP/out-bad/secrets.sarif")"
[[ "$ids" == "aws-access-token aws-secret-access-key flask-hardcoded-secret-key" ]] \
    && ok "expected rule ids ($ids)" || bad "unexpected rule ids: $ids"
"$PYTHON" -I - "$TMP/out-bad/secrets.sarif" <<'PY' && ok "severity/category/uri/line/fix populated" || bad "severity/category/uri/line/fix wrong"
import json, sys
res = json.load(open(sys.argv[1]))["runs"][0]["results"]
sev = {r["ruleId"]: r["properties"]["severity"] for r in res}
assert sev == {"aws-access-token": "Critical", "aws-secret-access-key": "Critical",
               "flask-hardcoded-secret-key": "High"}, sev
for r in res:
    p = r["properties"]
    assert p["category"] == "secret" and p["fix"] and p["raw_severity"] and p["confidence"]
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/settings.py", loc    # outside repo -> relative to target
    assert loc["region"]["startLine"] >= 1
PY
[[ "$(tree_hash "$BAD")" == "$H_BAD" ]] && ok "target tree unmodified" || bad "target tree was modified"

# no secret material in the report, the log or stdout
leak=0
for v in "${FAKE_VALUES[@]}"; do
    grep -rqF -- "$v" "$TMP/out-bad" "$TMP/stderr-bad" "$TMP/stdout-bad" && leak=1
done
[[ $leak -eq 0 ]] && ok "no secret value in SARIF / stderr / stdout" || bad "a secret value leaked into an output"

# determinism
bash "$RUN" "$BAD" "$TMP/out-bad2" >/dev/null 2>&1
cmp -s "$TMP/out-bad/secrets.sarif" "$TMP/out-bad2/secrets.sarif" && ok "two runs are byte-identical" || bad "output is not deterministic"

# ---------------------------------------------------------------------------
# 3. Clean fixture -> zero findings (incl. allowlisted placeholder template)
# ---------------------------------------------------------------------------
echo "[test:secrets] 3. clean fixture" >&2
CLEAN="$TMP/clean"; mkdir -p "$CLEAN/app"
cat > "$CLEAN/app/settings.py" <<'PY'
import os
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
SECRET_KEY = os.environ["SECRET_KEY"]
PY
printf 'SECRET_KEY=replace-with-a-random-secret-key\nAWS_SECRET_ACCESS_KEY=your-aws-secret-access-key\n' > "$CLEAN/.env.example"
set +e; bash "$RUN" "$CLEAN" "$TMP/out-clean" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 0 ]] && ok "clean fixture exits 0" || bad "clean fixture exited $rc"
check "clean SARIF validates" "$PYTHON" "$VALIDATE_PY" "$TMP/out-clean/secrets.sarif" --stage secrets
[[ "$(count_results "$TMP/out-clean/secrets.sarif")" == "0" ]] && ok "zero findings on clean fixture" || bad "clean fixture produced findings"

# ---------------------------------------------------------------------------
# 4. History-only finding (secret committed, then removed)
# ---------------------------------------------------------------------------
echo "[test:secrets] 4. git history" >&2
if command -v git >/dev/null 2>&1; then
    HIST="$TMP/hist"; mkdir -p "$HIST"
    G=(git -C "$HIST" -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false)
    git -C "$HIST" init -q
    printf 'AWS_ACCESS_KEY_ID = "%s%s"\n' "$P_AKIA" "$P_ID" > "$HIST/old.py"
    "${G[@]}" add old.py && "${G[@]}" commit -q -m "add"
    printf 'AWS_ACCESS_KEY_ID = ""\n' > "$HIST/old.py"
    "${G[@]}" commit -q -am "remove"
    bash "$RUN" "$HIST" "$TMP/out-hist" >/dev/null 2>&1 && rc=0 || rc=$?
    [[ $rc -eq 0 ]] && ok "history scan exits 0" || bad "history scan exited $rc"
    "$PYTHON" -I - "$TMP/out-hist/secrets.sarif" <<'PY' && ok "history-only finding reported and marked" || bad "history-only finding missing or unmarked"
import json, sys
res = json.load(open(sys.argv[1]))["runs"][0]["results"]
assert len(res) == 1, res
assert res[0]["ruleId"] == "aws-access-token"
assert "commit history only" in res[0]["message"]["text"]
PY
    SECRETS_SCAN_HISTORY=0 bash "$RUN" "$HIST" "$TMP/out-hist0" >/dev/null 2>&1
    [[ "$(count_results "$TMP/out-hist0/secrets.sarif")" == "0" ]] && ok "SECRETS_SCAN_HISTORY=0 skips history" || bad "history not skipped"
else
    echo "[test:secrets]   (git not available: history test not run)" >&2
fi

# ---------------------------------------------------------------------------
# 5. Fail closed: scanner failure -> exit 1 and NO sarif left behind
# ---------------------------------------------------------------------------
echo "[test:secrets] 5. fail closed" >&2
printf 'this is = = not [valid toml\n' > "$TMP/broken.toml"
mkdir -p "$TMP/out-fail"; echo '{"stale":true}' > "$TMP/out-fail/secrets.sarif"
set +e; SECRETS_CONFIG="$TMP/broken.toml" bash "$RUN" "$BAD" "$TMP/out-fail" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "invalid config -> exit 1" || bad "invalid config exited $rc (expected 1)"
[[ ! -e "$TMP/out-fail/secrets.sarif" ]] && ok "no SARIF left behind (stale file removed too)" || bad "SARIF exists after failure"

printf '#!/usr/bin/env bash\n[[ "${1:-}" == version ]] && { echo %s; exit 0; }\necho boom >&2; exit 3\n' "8.30.1" > "$TMP/crash-gitleaks"
chmod +x "$TMP/crash-gitleaks"
set +e; GITLEAKS_BIN="$TMP/crash-gitleaks" bash "$RUN" "$BAD" "$TMP/out-crash" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "crashing scanner -> exit 1" || bad "crashing scanner exited $rc"
[[ ! -e "$TMP/out-crash/secrets.sarif" ]] && ok "no SARIF after crash" || bad "SARIF exists after crash"

printf '#!/usr/bin/env bash\n[[ "${1:-}" == version ]] && { echo %s; exit 0; }\nsleep 30\n' "8.30.1" > "$TMP/hang-gitleaks"
chmod +x "$TMP/hang-gitleaks"
set +e; STAGE_TIMEOUT=2 GITLEAKS_BIN="$TMP/hang-gitleaks" bash "$RUN" "$BAD" "$TMP/out-hang" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "timeout -> exit 1" || bad "hanging scanner exited $rc"
[[ ! -e "$TMP/out-hang/secrets.sarif" ]] && ok "no SARIF after timeout" || bad "SARIF exists after timeout"

set +e; GITLEAKS_BIN="$TMP/missing-binary" bash "$RUN" "$BAD" "$TMP/out-nobin" >/dev/null 2>&1; rc=$?; set -e
[[ $rc -eq 1 ]] && ok "missing tool binary -> exit 1" || bad "missing binary exited $rc"

# ---------------------------------------------------------------------------
# 6. Real demo app: V1 detected (allowlist must never hide it), fixed app clean
# ---------------------------------------------------------------------------
echo "[test:secrets] 6. demo-app ground truth" >&2
VULN="$REPO_ROOT/demo-app/vulnerable"; FIXED="$REPO_ROOT/demo-app/fixed"
H_VULN="$(tree_hash "$VULN")"
bash "$RUN" "$VULN" "$TMP/out-vuln" >/dev/null 2>&1 && rc=0 || rc=$?
[[ $rc -eq 0 ]] && ok "vulnerable app: exit 0" || bad "vulnerable app exited $rc"
check "vulnerable app SARIF validates" "$PYTHON" "$VALIDATE_PY" "$TMP/out-vuln/secrets.sarif" --stage secrets
"$PYTHON" -I - "$TMP/out-vuln/secrets.sarif" "$REPO_ROOT/demo-app/seeded-vulnerabilities.json" <<'PY' \
    && ok "every seeded secret (V1*) is detected within +-2 lines (allowlist does not hide V1)" \
    || bad "a seeded secret (V1*) was NOT detected"
import json, sys
res = json.load(open(sys.argv[1]))["runs"][0]["results"]
seeded = [v for v in json.load(open(sys.argv[2]))["vulnerabilities"] if v["class"] == "secret"]
assert seeded, "no seeded secrets in ground truth"
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
for v in "wJalrXUtnFEMI" "AKIAIOSFODNN7FAKEKEY" "dev-secret-key-not-for-production"; do
    grep -rqF -- "$v" "$TMP/out-vuln" && bad "seeded value '$v' leaked into the SARIF"
done; ok "no seeded secret value in the SARIF"

# path forms: relative target from another cwd, absolute target, repo root -> same URIs
( cd "$REPO_ROOT" && bash "$RUN" demo-app/vulnerable "$TMP/out-rel" >/dev/null 2>&1 )
( cd "$TMP" && bash "$RUN" "$VULN" "$TMP/out-abs" >/dev/null 2>&1 )
cmp -s "$TMP/out-rel/secrets.sarif" "$TMP/out-abs/secrets.sarif" \
    && cmp -s "$TMP/out-rel/secrets.sarif" "$TMP/out-vuln/secrets.sarif" \
    && ok "relative / absolute target and any cwd give identical SARIF" || bad "path forms differ"
bash "$RUN" "$REPO_ROOT" "$TMP/out-root" >/dev/null 2>&1 && rc=0 || rc=$?
[[ $rc -eq 0 ]] && ok "repo-root target exits 0" || bad "repo-root target exited $rc"
"$PYTHON" -I - "$TMP/out-root/secrets.sarif" <<'PY' && ok "repo-root target: URIs stay repo-relative and V1 keeps its path" || bad "repo-root URIs wrong"
import json, sys
res = json.load(open(sys.argv[1]))["runs"][0]["results"]
uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in res}
assert all(not u.startswith("/") and ".." not in u.split("/") for u in uris), uris
assert "demo-app/vulnerable/config.py" in uris, uris
PY

H_FIXED="$(tree_hash "$FIXED")"
bash "$RUN" "$FIXED" "$TMP/out-fixed" >/dev/null 2>&1 && rc=0 || rc=$?
[[ $rc -eq 0 ]] && ok "fixed app: exit 0" || bad "fixed app exited $rc"
[[ "$(count_results "$TMP/out-fixed/secrets.sarif")" == "0" ]] && ok "fixed app: zero findings" || bad "fixed app has findings"
[[ "$(tree_hash "$FIXED")" == "$H_FIXED" ]] && ok "demo-app/fixed unmodified" || bad "demo-app/fixed was modified"

# ---------------------------------------------------------------------------
echo "" >&2
if [[ $FAILS -eq 0 ]]; then
    echo "[test:secrets] PASS (all checks)" >&2
    exit 0
fi
echo "[test:secrets] FAIL: $FAILS check(s) failed" >&2
exit 1

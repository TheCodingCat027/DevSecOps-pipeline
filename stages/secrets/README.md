# Secrets Stage

**Owner:** P2  
**Status:** Stub (Phase 1) — replace with Gitleaks in Phase 2  
**Interface:** See [`contracts/stage-interface.md`](../../contracts/stage-interface.md)

## Purpose

Scans the target directory for accidentally committed secrets, API keys, tokens, and credentials.

## Real Tool (Phase 2)

**Gitleaks v8.18.4** — [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)  
Pinned version placeholder: `gitleaks v8.18.4`

Installation:
```bash
# Linux/macOS
curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz | tar xz
sudo mv gitleaks /usr/local/bin/
```

## How to Replace This Stub (4 Steps)

1. Read `contracts/stage-interface.md` thoroughly.
2. Replace the stub body in `run.sh` with: `gitleaks detect --source "$TARGET_PATH" --report-format sarif --report-path "$OUTPUT_DIR/secrets.sarif" --exit-code 0`
3. Apply the severity mapping from `contracts/severity-map.md` (Gitleaks has no native severity; map cloud-provider keys to Critical, all others to High).
4. Extend `tests/run_test.sh` with a known-bad input test and verify `validate.py --stage secrets` exits 0.

## Stage Interface

```
stages/secrets/run.sh <target_path> <output_dir>
  -> writes  <output_dir>/secrets.sarif
  -> exit 0  scan completed (even with findings)
  -> exit 1  Gitleaks crashed
  -> exit 2  wrong arguments
```

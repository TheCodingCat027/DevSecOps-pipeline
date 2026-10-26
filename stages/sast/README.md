# SAST Stage

**Owner:** P2  
**Status:** Stub (Phase 1) — replace with Semgrep in Phase 2  
**Interface:** See [`contracts/stage-interface.md`](../../contracts/stage-interface.md)

## Purpose

Static Application Security Testing: scans source code for security vulnerabilities such as SQL injection, weak cryptography, path traversal, and hardcoded secrets patterns.

## Real Tool (Phase 2)

**Semgrep v1.78.0** — [https://semgrep.dev](https://semgrep.dev)  
Pinned version placeholder: `semgrep 1.78.0`

Installation:
```bash
pip install semgrep==1.78.0
```

## How to Replace This Stub (4 Steps)

1. Read `contracts/stage-interface.md`.
2. Replace the stub body in `run.sh` with: `semgrep scan --config "p/python" --sarif --output "$OUTPUT_DIR/sast.sarif" "$TARGET_PATH" ; exit 0`
3. Apply the severity mapping from `contracts/severity-map.md` (Semgrep ERROR→High, WARNING→Medium, INFO→Low).
4. Extend `tests/run_test.sh` to scan `demo-app/vulnerable` and assert ≥3 findings (V2, V6, V7).

## Stage Interface

```
stages/sast/run.sh <target_path> <output_dir>
  -> writes  <output_dir>/sast.sarif
  -> exit 0  scan completed (even with findings)
  -> exit 1  Semgrep crashed
  -> exit 2  wrong arguments
```

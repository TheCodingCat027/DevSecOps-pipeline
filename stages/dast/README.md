# DAST Stage

**Owner:** P3  
**Status:** Stub (Phase 1) — DISABLED by default — replace with ZAP in Phase 3  
**Interface:** See [`contracts/stage-interface.md`](../../contracts/stage-interface.md)

> **This stage is disabled.** `stages/stages.json` has `"enabled": false` for `dast`.  
> P3 sets `"enabled": true` when the real ZAP scanner is implemented.

## Purpose

Dynamic Application Security Testing: runs a live web scanner against the running application to detect XSS, CSRF, insecure headers, and other runtime vulnerabilities.

## Real Tool (Phase 3)

**OWASP ZAP v2.15.0** — [https://www.zaproxy.org](https://www.zaproxy.org)  
Pinned version placeholder: `zap 2.15.0`

## How to Replace This Stub (4 Steps)

1. Read `contracts/stage-interface.md`. Note that DAST needs a running app — start it before calling ZAP.
2. Replace stub body: start the app, run ZAP scan, write SARIF to `$OUTPUT_DIR/dast.sarif`, stop the app.
3. Apply severity mapping from `contracts/severity-map.md` (ZAP High→High, Medium→Medium, etc.).
4. Set `"enabled": true` in `stages/stages.json` and add `stage (dast)` to the required CI checks.

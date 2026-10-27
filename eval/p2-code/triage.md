# Triage of findings that match no seeded flaw (vulnerable app)

**All verdicts are PROPOSED (needs human confirmation).** They were written by the P2 author from the scanner output and the source files; they are not ground truth. Verdict vocabulary: `true positive not in seed list`, `false positive`, `informational`.

Generated 2026-10-27T05:21:43Z by `evaluate.py` from `results.json`; justifications come from `triage-proposals.json`.

| # | Stage | Rule | Location | Severity | Message | PROPOSED verdict | Justification |
|---|---|---|---|---|---|---|---|
| 1 | secrets | `flask-hardcoded-secret-key` | `demo-app/vulnerable/app.py:22` | High | Hard-coded application SECRET_KEY (session signing key) in source (flask-hardcoded-secret-key) detected at demo-app/vulnerable/app.py:22. Th | true positive not in seed list | Literal Flask SECRET_KEY in source (value labelled 'dev-secret-key-not-for-production'). A fixed session-signing key lets anyone forge session cookies if it reaches production; demo-app/fixed replaces it with os.environ['SECRET_KEY'] (config.py:19-21), i.e. Phase 1 treats it as a flaw too, yet seeded-vulnerabilities.json does not list it. Suggest adding it to the seed list (see docs/p2-requests-to-p1.md). |
| 2 | secrets | `flask-hardcoded-secret-key` | `demo-app/vulnerable/config.py:24` | High | Hard-coded application SECRET_KEY (session signing key) in source (flask-hardcoded-secret-key) detected at demo-app/vulnerable/config.py:24. | true positive not in seed list | Literal Flask SECRET_KEY in source (value labelled 'dev-secret-key-not-for-production'). A fixed session-signing key lets anyone forge session cookies if it reaches production; demo-app/fixed replaces it with os.environ['SECRET_KEY'] (config.py:19-21), i.e. Phase 1 treats it as a flaw too, yet seeded-vulnerabilities.json does not list it. Suggest adding it to the seed list (see docs/p2-requests-to-p1.md). |

2 unmatched finding(s); 0 without a proposal.

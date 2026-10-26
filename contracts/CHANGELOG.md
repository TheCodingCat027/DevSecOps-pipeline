# Contracts CHANGELOG

> **IMPORTANT: The files in `contracts/` are FROZEN as of Phase 1 sign-off (see `docs/team-signoff.md`).**  
> Any modification requires a numbered amendment entry in this file with acknowledgement from all four team members and a corresponding PR approved by all four CODEOWNERS.

---

## Amendment Process

1. Identify the gap or error in the current contract.
2. Discuss the proposed change with all four team members (Slack, meeting, or issue).
3. Draft the change in a branch (e.g. `p4/contracts-amendment-1`).
4. Add a numbered entry to this CHANGELOG using the template below.
5. Open a PR — GitHub will automatically require reviews from all four handles listed on the `/contracts/` line in `CODEOWNERS`.
6. Merge only after all four have approved.

### Amendment Entry Template

```
## Amendment N — YYYY-MM-DD

**Changed:** <which file and which field/section>  
**Reason:** <why the change is needed>  
**Backward compatible:** Yes / No (if No, explain migration path)  
**Acknowledged by:**  
- P1 @p1-handle — YYYY-MM-DD  
- P2 @p2-handle — YYYY-MM-DD  
- P3 @p3-handle — YYYY-MM-DD  
- P4 @p4-handle — YYYY-MM-DD  
```

---

## v1.0.0 — DRAFT — becomes frozen when all four members sign `docs/team-signoff.md`

**Freeze date: pending sign-off**  
**Scope:** Initial freeze of all contract files.

**Files frozen:**
- `finding.schema.json` — normalized finding schema (JSON Schema draft 2020-12)
- `policy.schema.json` — security policy schema
- `sarif-profile.md` — SARIF 2.1.0 subset that every stage must emit
- `severity-map.md` — mapping from tool-native labels to canonical four-level severity
- `stage-interface.md` — universal stage CLI, exit codes, and `extract_findings` function
- `gate-interface.md` — gate CLI, exit codes, and output document schemas
- `validate.py` — the enforcement tool and the `extract_findings` module function
- `requirements.txt` — pinned Python dependencies for validation tooling

**Signed off by:** (see `docs/team-signoff.md` — must be completed before freeze is official)

---

## Amendments (none yet)

*No amendments have been made to the v1.0.0 contracts.*

# Team Sign-off for Contracts v1.0.0

> **This sign-off is the real gate for freezing `contracts/`.** 
> The contracts are not officially frozen until all four team members have signed below and this file is merged to `main`.

Once signed, any further change to `contracts/` must follow the amendment process in `contracts/CHANGELOG.md`.

---

## What You Are Signing Off On

By signing below, you confirm that you have read and understood:

- [ ] `contracts/finding.schema.json` — the normalized finding schema
- [ ] `contracts/policy.schema.json` — the security policy schema
- [ ] `contracts/sarif-profile.md` — the SARIF 2.1.0 subset requirement
- [ ] `contracts/severity-map.md` — severity normalization table
- [ ] `contracts/stage-interface.md` — the universal stage interface and `extract_findings` function
- [ ] `contracts/gate-interface.md` — the gate CLI, exit codes, and output schemas
- [ ] `contracts/validate.py` — the enforcement tool
- [ ] `contracts/requirements.txt` — pinned Python dependencies

You also confirm that:

- The schemas contain all fields your phase needs.
- The interfaces are correct and implementable.
- You understand the amendment process for any future changes.

---

## Sign-off Table

| Member | Role | Signed | Date |
|---|---|---|---|
| P1 | Repository infrastructure | ☐ `@p1-handle` | ___________ |
| P2 | Secrets, SAST, SCA stages | ☐ `@p2-handle` | ___________ |
| P3 | IaC, Container, SBOM, DAST stages | ☐ `@p3-handle` | ___________ |
| P4 | Gate, policy, contracts owner | ☐ `@p4-handle` | ___________ |

**To sign:** Replace ☐ with ☑, add your GitHub handle next to your row, and fill in the date (YYYY-MM-DD). Commit to a PR targeting `main` — GitHub will require approval from all four CODEOWNERS.

---

## Status

**Not yet signed.** The contracts are in draft state until all four members sign.

Once all four checkboxes are ticked and this file is merged, update `contracts/CHANGELOG.md` v1.0.0 entry to add the merge date.

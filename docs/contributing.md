# Contributing Guide

This document covers everything a contributor needs to know before opening a pull request.

---

## Ownership Model

Every file in this repository belongs to exactly one owner (see `CODEOWNERS`). **Never edit files outside your designated folders.** The one exception is shared documentation in `docs/` where each file has a `p<n>-` prefix indicating the owner.

| Owner | Folders |
|---|---|
| P1 | `/README.md`, `/Makefile`, `/.github/`, `/scripts/`, `/demo-app/`, `/eval/p1-performance/`, `/docs/p1-*` |
| P2 | `/stages/secrets/`, `/stages/sast/`, `/stages/sca/`, `/eval/p2-code/`, `/docs/p2-*` |
| P3 | `/stages/iac/`, `/stages/container/`, `/stages/sbom/`, `/stages/dast/`, `/demo-app/fixed/Dockerfile`, `/eval/p3-container/`, `/docs/p3-*` |
| P4 | `/contracts/`, `/gate/`, `/security-policy.yaml`, `/eval/p4-policy/`, `/docs/p4-*` |

---

## Branch Naming

Use the pattern `<owner>/<short-description>`, for example:

```
p2/secrets-gitleaks
p3/iac-hadolint-integration
p4/policy-gate-real
p1/fix-makefile-validate
```

This naming convention makes ownership instantly visible in the branch list and avoids merge conflicts between owners working in parallel.

---

## Small, Frequent PRs

Prefer PRs that do one thing. A large PR touching many files is harder to review and more likely to block others. If your phase has multiple stages, open one PR per stage.

---

## Reviewer Rotation

| Author | Reviewer |
|---|---|
| P2 | P3 reviews P2's PRs |
| P3 | P4 reviews P3's PRs |
| P4 | P2 reviews P4's PRs |
| Anyone touching `pipeline.yml` | P1 must also review |

This rotation keeps knowledge distributed across the team.

---

## Merge-Ready Definition of Done

A PR is merge-ready when **all** of the following are true:

1. All required CI status checks are green (see `docs/branch-protection.md`).
2. The CODEOWNERS reviewer(s) for the changed paths have approved.
3. The PR checklist (`.github/pull_request_template.md`) is fully checked.
4. No unresolved review comments remain.
5. The branch is up-to-date with `main` (squash or rebase — linear history required).

---

## How to Replace a Stub with a Real Stage

This is the primary task for P2 and P3. Follow these four steps **exactly**. You do **not** need to touch `pipeline.yml`, `stages.json`, or `contracts/`.

### Step 1: Understand the interface

Read `contracts/stage-interface.md` thoroughly. Your script must:
- Accept exactly two positional arguments: `<target_path>` and `<output_dir>`.
- Write `<output_dir>/<stage_name>.sarif` (always, even with zero findings).
- Exit 0 on success (even with findings), exit 1 only if the tool crashes, exit 2 on wrong arguments.
- Log to stderr only; keep stdout quiet.

### Step 2: Replace the body of `stages/<name>/run.sh`

Keep the argument validation and `set -euo pipefail` header. Replace the stub body (the `cp` command and the stub message) with real scanner invocation. The SARIF written must conform to the profile in `contracts/sarif-profile.md`.

### Step 3: Update `stages/<name>/README.md`

Fill in the real tool name, exact pinned version (e.g., `trivy 0.51.1`), installation method, and any environment prerequisites.

### Step 4: Extend `stages/<name>/tests/run_test.sh`

The existing test checks that the stub SARIF is emitted and validates. Add a second test case:
1. Run the real scanner against a known-bad input (use the demo app's vulnerable target).
2. Assert that the expected finding count (or at least one finding) is present in the SARIF.
3. Run `python contracts/validate.py reports/<name>.sarif --stage <name>` and assert it exits 0.

Open your PR only when all tests pass.

---

## Contract Amendment Process

The files in `contracts/` are **frozen** at the end of Phase 1 (see `contracts/CHANGELOG.md`). If you discover a schema gap:

1. Discuss with all four team members first.
2. Draft the change and list it as a numbered entry in `contracts/CHANGELOG.md`: what changed, why, the date, and acknowledgement from all four.
3. Open a PR that touches `contracts/` — GitHub will automatically require reviews from all four owners.
4. Merge only after all four have approved.

**Do not make ad-hoc changes to `contracts/` between phases.**

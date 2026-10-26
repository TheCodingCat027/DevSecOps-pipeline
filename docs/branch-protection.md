# Branch Protection Settings for `main`

This document describes the required GitHub branch protection rules for `main` and provides the exact API commands to apply them.

> **Note:** These settings cannot be applied automatically by the Phase 1 implementation script because they require admin access to the GitHub repository. A team member with admin rights must run the commands below after the repo is pushed to GitHub.

---

## Required Settings

| Setting | Value | Reason |
|---|---|---|
| Require pull request reviews | **Yes** | No direct pushes to `main` |
| Required approving reviews | **1** (minimum; raise to 2 for contracts PRs per CODEOWNERS) | Enforces code review |
| Dismiss stale reviews on push | **Yes** | New commits re-require approval |
| Require review from CODEOWNERS | **Yes** | Enforces ownership boundaries |
| Required status checks | See list below | Gates on passing CI |
| Require status checks to be up-to-date | **Yes** | Prevents stale CI results |
| Require linear history | **Yes** | Keeps git log readable; requires squash or rebase merge |
| Restrict force pushes | **Yes (block all)** | Preserves audit trail |
| Allow deletions | **No** | Protects `main` from accidental deletion |
| Require conversation resolution | **Yes** | All review comments must be resolved before merge |

### Required Status Checks (job names from `pipeline.yml`)

- `contracts-and-tests`
- `stage (secrets)`
- `stage (sast)`
- `stage (sca)`
- `stage (iac)`
- `stage (container)`
- `stage (sbom)`
- `gate`

> `dast` is disabled by default (`enabled: false` in `stages.json`); omit it from required checks until P3 enables it.

### Contracts PRs Require All Four Approvals

The `CODEOWNERS` file lists all four handles on the `/contracts/` line. GitHub will automatically require a review from **each** of the four owners when a PR touches any file in `contracts/`. Ensure all four handles are added as collaborators with at least "Write" access.

---

## Applying Branch Protection via GitHub API

Replace `ORG` and `REPO` with your GitHub organization/username and repository name. Run these after pushing the repo.

```bash
# Set variables
GITHUB_TOKEN="<your-personal-access-token>"
ORG="<your-org-or-username>"
REPO="devsecops-pipeline"

# Apply branch protection to main
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/${ORG}/${REPO}/branches/main/protection \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "contracts-and-tests",
      "stage (secrets)",
      "stage (sast)",
      "stage (sca)",
      "stage (iac)",
      "stage (container)",
      "stage (sbom)",
      "gate"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "dismissal_restrictions": {},
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true
}
EOF
```

### Verify the Protection Was Applied

```bash
gh api \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/${ORG}/${REPO}/branches/main/protection
```

### Enable GitHub's Secret Scanning Push Protection

```bash
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  /repos/${ORG}/${REPO} \
  -f security_and_analysis[secret_scanning][status]=enabled \
  -f security_and_analysis[secret_scanning_push_protection][status]=enabled
```

> **Why push protection matters for Phase 1:** `demo-app/vulnerable/` contains a deliberately fake AWS key (pattern-matching but not a real credential). GitHub's push protection may flag it. See `demo-app/README.md` for the documented bypass procedure for known-fake test values.

---

## Rulesets (Alternative — GitHub Enterprise or Modern UI)

If your organization uses GitHub Rulesets instead of the older branch protection API, apply equivalent settings via the UI at:  
`Settings → Branches → Add ruleset → target: main`

The settings are identical; the Rulesets UI labels them slightly differently.

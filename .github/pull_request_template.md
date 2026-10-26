## Pull Request Checklist

Before requesting a review, confirm every item below. This protects the team from accidental cross-ownership edits and keeps contracts stable.

- [ ] I only changed files inside my own folders (see `CODEOWNERS`)
- [ ] Stage output passes `python contracts/validate.py` (if this PR adds or modifies a stage)
- [ ] Tests for my module run and pass in CI (`make test`)
- [ ] Tool versions are pinned (in `requirements.txt`, `run.sh`, or `Dockerfile`)
- [ ] No real secrets (only clearly fake values) are committed
- [ ] `README.md` / docs and `eval/` notes are updated to reflect this change
- [ ] I have **not** edited `contracts/` — **OR** — a numbered amendment entry is logged in `contracts/CHANGELOG.md` with acknowledgement from all four members

## What does this PR do?

<!-- Short description: what problem does it solve and what files does it change? -->

## Testing evidence

<!-- Paste the key output lines from `make test` or your stage test here. -->

## Related issues or tasks

<!-- Link any issues or tasks this PR closes. -->

# Orchestrator Report

## Task Requested
Add branch-aware devcontainer image caching with a 15-day retention window and reuse `main` cache from all branches.

## Workspace Findings
- `.github/workflows/ci.yml` now restores local branch and `main` caches, and also uses OCI registry cache refs for non-fork builds.
- Branch names can contain characters and lengths that are invalid for OCI tags, so the cache tag needs sanitizing and truncation.
- `actions/cache` split restore/save inputs did not accept `retention-days`, so a separate prune workflow is needed to keep the local fallback cache bounded.

## Plan Summary
- Keep local branch and `main` caches for fallback and 15-day cleanup.
- Use OCI registry cache refs for branch builds, with `main` as the shared fallback.
- Gate registry pull/push on non-fork runs.
- Add a prune workflow to delete stale local cache entries.

## Workflow Status
- [x] Research complete
- [x] Implementation complete
- [x] Review complete

## Agents Used
- Implementer
- Reviewer

## Review Status
Clean.

## Blockers
None.

## Final Outcome
Branch-aware devcontainer caching is implemented in `.github/workflows/ci.yml` with OCI registry refs, `main` fallback, fork-safe gating, and a prune workflow in `.github/workflows/devcontainer-cache-prune.yml`.

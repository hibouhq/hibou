# ADR 017: One canonical ref per pull request

## Status
Accepted

## Context
A pull/merge request was represented by **two** `refs` rows:

- `refs/pull/N/head` — created by forge sync / webhooks, carrying PR metadata
  (title, state, source branch, merge target), but no CI snapshot.
- `refs/pull/N/merge` — created by CI uploads, because GitHub Actions sets
  `GITHUB_REF=refs/pull/N/merge` for PR builds. This row carries the snapshot
  (SBOM, SARIF, tests, coverage) but no title.

A `pr_ref_kind` column (`head` / `merge`) distinguished them. Because the title
lived on one row and the data on the other, every PR data view (tests,
vulnerabilities, coverage, trends, snapshot list) showed nothing for the
title-bearing ref. The codebase worked around this in two places:

- Backend: a read-time `preferPRRefWithData` that, for a snapshot-less PR ref,
  hunted for the sibling head/merge ref that had data — on every data request.
- Frontend: a `visiblePullRequestRefs` dedup in the ref switcher that hid the
  merge duplicate so a PR appeared once.

Both are symptom patches for a data-model split.

## Decision
Represent each pull request as a **single canonical ref**: `refs/pull/N`
(GitLab: `refs/merge-requests/N`), with the `/head` and `/merge` suffix stripped
at the point of creation. Both the upload path and the webhook/sync path upsert
the **same** row, so title and snapshot live together.

Consequences:
- `pr_ref_kind` is removed (head/merge no longer distinguished).
- The read-time `preferPRRefWithData` redirect and its helpers are deleted; data
  endpoints resolve the canonical ref directly via `resolveRefForRepo`.
- The frontend `visiblePullRequestRefs`/`effectivePRRefKind` dedup is removed;
  one row per PR means no duplicate to hide.
- A migration collapses existing split rows: per (repo, canonical PR name) it
  picks a survivor, repoints that PR's snapshots onto it, coalesces
  PR metadata, deletes the siblings, and renames the survivor to the canonical
  name.

The snapshot's own `commit_sha` still records the exact commit scanned (the
merge commit for PR builds), so collapsing the ref loses no information.

## Alternatives considered
- **Read-time redirect (status quo)** — rejected: spreads head/merge awareness
  across every read path and leaves the duplication in the data model.
- **Normalize only at ingestion, keep both rows** — rejected: still two rows,
  still needs dedup on read and in the UI.

This is an alpha system with no backward-compatibility constraint, so a
one-time collapsing migration is acceptable.

## Consequences
Simpler reads (no sibling lookup), one row per PR, less UI logic. The forge sync
and upload paths must both route through the canonical-name normalization;
adding a new PR-ref creation path without it would reintroduce duplicates.

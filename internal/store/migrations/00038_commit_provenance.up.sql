-- Commit provenance (PLAN §2) and honest fix-in-flight claims (PLAN §5).
--
-- CI on a pull_request event does not test the PR head: it tests an EPHEMERAL
-- MERGE COMMIT of head onto the base branch at that moment. commit_sha keeps
-- meaning the developer's commit (the PR head — what checks attach to and what
-- reviewers look at); these record what was *actually built*:
ALTER TABLE snapshots
    -- The temporary merge commit CI checked out (GITHUB_SHA on pull_request
    -- events; GitLab merged-results equivalent). Empty for branch/tag builds.
    ADD COLUMN merge_commit_sha text DEFAULT ''::text NOT NULL,
    -- The base-branch commit that merge used — which base the delta and any
    -- "this PR fixes X" claim were computed against.
    ADD COLUMN base_commit_sha text DEFAULT ''::text NOT NULL;

-- Which base commit a PR check's resolved-fingerprint claims were verified
-- against. '' = recorded before this migration, i.e. unverified.
ALTER TABLE pr_checks
    ADD COLUMN claims_base_sha text DEFAULT ''::text NOT NULL;

-- Purge the corrupt claims (PLAN §5): every stored row predates verification
-- and the observed data is wrong twice over — mid-scan verdicts recorded the
-- whole base as "resolved" (PR #11: 631 rows), and stale PR snapshots counted
-- everything the base gained since as "resolved" (~94 rows on each July PR).
-- "This PR fixes X" with no basis is worse than no claim; recomputes repopulate
-- honest rows as PRs are re-evaluated.
DELETE FROM pr_check_resolved_fingerprints;

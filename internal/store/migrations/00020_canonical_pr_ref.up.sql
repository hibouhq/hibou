-- Collapse split pull-request refs (refs/pull/N/head + refs/pull/N/merge) into a
-- single canonical ref (refs/pull/N), then drop the now-unused pr_ref_kind.
-- See ADR 017. The head ref carries PR metadata; the merge ref carries the CI
-- snapshot. We keep one survivor per (repo, canonical name), move snapshots and
-- PR metadata onto it, delete the siblings, and rename it to the canonical name.
DO $$
DECLARE
	grp RECORD;
	survivor_id UUID;
BEGIN
	FOR grp IN
		SELECT repo_id,
		       regexp_replace(name, '/(head|merge)$', '') AS canonical
		FROM refs
		WHERE ref_type = 'pull_request'
		  AND name ~ '/(head|merge)$'
		GROUP BY repo_id, regexp_replace(name, '/(head|merge)$', '')
	LOOP
		-- Prefer the ref that carries a title (the head); fall back to oldest.
		SELECT id INTO survivor_id
		FROM refs
		WHERE repo_id = grp.repo_id
		  AND ref_type = 'pull_request'
		  AND regexp_replace(name, '/(head|merge)$', '') = grp.canonical
		ORDER BY (pr_title <> '') DESC, (name LIKE '%/head') DESC, created_at ASC
		LIMIT 1;

		-- Move snapshots from the sibling refs onto the survivor.
		UPDATE snapshots
		SET ref_id = survivor_id
		WHERE ref_id IN (
			SELECT id FROM refs
			WHERE repo_id = grp.repo_id
			  AND ref_type = 'pull_request'
			  AND regexp_replace(name, '/(head|merge)$', '') = grp.canonical
			  AND id <> survivor_id
		);

		-- Coalesce PR metadata from siblings onto the survivor (the merge ref
		-- usually holds pr_number; the head ref holds title/state).
		UPDATE refs s SET
			pr_number = COALESCE(s.pr_number, sib.pr_number),
			pr_state = COALESCE(s.pr_state, sib.pr_state),
			pr_title = CASE WHEN s.pr_title <> '' THEN s.pr_title ELSE COALESCE(sib.pr_title, '') END,
			pr_source_branch = CASE WHEN s.pr_source_branch <> '' THEN s.pr_source_branch ELSE COALESCE(sib.pr_source_branch, '') END,
			merge_target_ref_id = COALESCE(s.merge_target_ref_id, sib.merge_target_ref_id),
			pr_merged_at = COALESCE(s.pr_merged_at, sib.pr_merged_at),
			pr_closed_at = COALESCE(s.pr_closed_at, sib.pr_closed_at)
		FROM (
			SELECT
				MAX(pr_number) AS pr_number,
				MAX(pr_state) AS pr_state,
				MAX(pr_title) AS pr_title,
				MAX(pr_source_branch) AS pr_source_branch,
				MAX(merge_target_ref_id::text)::uuid AS merge_target_ref_id,
				MAX(pr_merged_at) AS pr_merged_at,
				MAX(pr_closed_at) AS pr_closed_at
			FROM refs
			WHERE repo_id = grp.repo_id
			  AND ref_type = 'pull_request'
			  AND regexp_replace(name, '/(head|merge)$', '') = grp.canonical
			  AND id <> survivor_id
		) sib
		WHERE s.id = survivor_id;

		-- Delete the now-empty sibling refs.
		DELETE FROM refs
		WHERE repo_id = grp.repo_id
		  AND ref_type = 'pull_request'
		  AND regexp_replace(name, '/(head|merge)$', '') = grp.canonical
		  AND id <> survivor_id;

		-- Rename the survivor to the canonical name.
		UPDATE refs SET name = grp.canonical WHERE id = survivor_id;
	END LOOP;
END $$;

ALTER TABLE refs DROP COLUMN pr_ref_kind;

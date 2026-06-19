ALTER TABLE snapshots
    ADD COLUMN pinned BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN retention_hold BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN artifact_bytes BIGINT NOT NULL DEFAULT 0;

ALTER TABLE repositories
    ADD COLUMN retention_artifact_bytes BIGINT NOT NULL DEFAULT 0;

WITH snapshot_totals AS (
    SELECT
        s.id,
        CASE
            WHEN s.status IN ('archived', 'purged') THEN 0::bigint
            ELSE COALESCE(SUM(sa.size_bytes), 0)::bigint
        END AS total_bytes
    FROM snapshots s
    LEFT JOIN snapshot_artifacts sa ON sa.snapshot_id = s.id
    GROUP BY s.id, s.status
)
UPDATE snapshots s
SET artifact_bytes = st.total_bytes
FROM snapshot_totals st
WHERE s.id = st.id;

WITH repo_totals AS (
    SELECT r.id, COALESCE(SUM(s.artifact_bytes), 0)::bigint AS total_bytes
    FROM repositories r
    LEFT JOIN refs rf ON rf.repo_id = r.id
    LEFT JOIN snapshots s ON s.ref_id = rf.id
    GROUP BY r.id
)
UPDATE repositories r
SET retention_artifact_bytes = rt.total_bytes
FROM repo_totals rt
WHERE r.id = rt.id;

package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type ReleaseInventory struct {
	State        string     `json:"state"`
	HasInventory bool       `json:"has_inventory"`
	CanExtract   bool       `json:"can_extract"`
	Detail       string     `json:"detail,omitempty"`
	JobID        *uuid.UUID `json:"job_id,omitempty"`
}

type ReleaseInventorySummary struct {
	Enabled     bool  `json:"enabled"`
	Eligible    int64 `json:"eligible"`
	Queued      int64 `json:"queued"`
	Processing  int64 `json:"processing"`
	Matching    int64 `json:"matching"`
	Failed      int64 `json:"failed"`
	Inventoried int64 `json:"inventoried"`
	Unsupported int64 `json:"unsupported"`
}

const releaseInventoryCTE = `
WITH evidence AS (
	SELECT rel.id,COALESCE(rel.published_at,rel.created_at) AS released_at,
		COALESCE(s.inventory_set_id IS NOT NULL,false)
			OR EXISTS(SELECT 1 FROM snapshot_components c WHERE c.snapshot_id=s.id) AS has_inventory,
		ref.ref_type='tag' AND ref.repo_id=rel.repo_id
			AND (rel.snapshot_id IS NULL OR (s.ref_id=ref.id AND s.status<>'purged')) AS valid_target,
		COALESCE(pr.outcome::text,'') AS outcome,COALESCE(pr.detail,'') AS detail,
		j.id AS job_id,COALESCE(j.status,'') AS job_status,j.finished_at,COALESCE(j.last_error,'') AS last_error,
		COALESCE(sc.status::text,'') AS scan_status
	FROM releases rel
	JOIN refs ref ON ref.id=rel.ref_id
	LEFT JOIN snapshots s ON s.id=rel.snapshot_id
	LEFT JOIN LATERAL (
		SELECT p.outcome,p.detail FROM producer_runs p
		WHERE p.snapshot_id=s.id AND p.producer='dependency-inventory:hibou'
		ORDER BY p.created_at DESC LIMIT 1
	) pr ON true
	LEFT JOIN LATERAL (
		SELECT job.id,job.status,job.finished_at,job.last_error FROM dep_extraction_jobs job
		WHERE job.repo_id=rel.repo_id
		AND (job.snapshot_id=rel.snapshot_id OR (
			job.snapshot_id IS NULL AND (job.ref_name='refs/tags/' || ref.name
				OR (job.ref_name=ref.name AND job.reason='release'))
			AND (s.commit_sha IS NULL OR job.commit_sha IN('',s.commit_sha))))
		ORDER BY job.created_at DESC,job.id DESC LIMIT 1
	) j ON true
	LEFT JOIN LATERAL (
		SELECT scan.status FROM scans scan WHERE scan.snapshot_id=s.id
		ORDER BY scan.created_at DESC,scan.id DESC LIMIT 1
	) sc ON true
	WHERE rel.repo_id=$1 AND ($2::uuid[] IS NULL OR rel.id=ANY($2::uuid[]))
), inventory AS (
	SELECT *,CASE
		WHEN has_inventory AND scan_status IN('pending','running') THEN 'matching'
		WHEN has_inventory THEN CASE WHEN outcome='partial' THEN 'partial' ELSE 'complete' END
		WHEN NOT valid_target THEN 'unavailable'
		WHEN job_status='pending' OR (job_status='failed' AND finished_at IS NULL) THEN 'queued'
		WHEN job_status='processing' THEN 'processing'
		WHEN job_status='failed' OR outcome='failed' THEN 'failed'
		WHEN job_status='complete' OR outcome='partial' THEN 'unsupported'
		ELSE 'missing' END AS state
	FROM evidence
) `

func (q *Queries) ListReleaseInventories(ctx context.Context, repoID uuid.UUID, releaseIDs []uuid.UUID) (map[uuid.UUID]ReleaseInventory, error) {
	result := make(map[uuid.UUID]ReleaseInventory, len(releaseIDs))
	if len(releaseIDs) == 0 {
		return result, nil
	}
	rows, err := q.rawDB().QueryContext(ctx, releaseInventoryCTE+`
		SELECT id,state,has_inventory,CASE WHEN job_status='failed' THEN last_error ELSE detail END,job_id
		FROM inventory`, repoID, pq.Array(releaseIDs))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uuid.UUID
		var jobID uuid.NullUUID
		var item ReleaseInventory
		if err := rows.Scan(&id, &item.State, &item.HasInventory, &item.Detail, &jobID); err != nil {
			return nil, err
		}
		item.CanExtract = item.State == "missing" || item.State == "failed"
		item.JobID = uuidPtrFromNull(jobID)
		result[id] = item
	}
	return result, rows.Err()
}

func (q *Queries) GetReleaseInventorySummary(ctx context.Context, repoID uuid.UUID) (ReleaseInventorySummary, error) {
	var summary ReleaseInventorySummary
	err := q.rawDB().QueryRowContext(ctx, releaseInventoryCTE+`
		SELECT count(*) FILTER(WHERE state IN('missing','failed')),
			count(*) FILTER(WHERE state='queued'),count(*) FILTER(WHERE state='processing'),count(*) FILTER(WHERE state='matching'),
			count(*) FILTER(WHERE state='failed'),count(*) FILTER(WHERE has_inventory),
			count(*) FILTER(WHERE state='unsupported') FROM inventory`, repoID, nil).Scan(
		&summary.Eligible, &summary.Queued, &summary.Processing, &summary.Matching, &summary.Failed, &summary.Inventoried, &summary.Unsupported)
	return summary, err
}

func (q *Queries) ListReleaseInventoryCandidates(ctx context.Context, repoID uuid.UUID, limit int) ([]uuid.UUID, error) {
	rows, err := q.rawDB().QueryContext(ctx, releaseInventoryCTE+`
		SELECT id FROM inventory WHERE state IN('missing','failed')
		ORDER BY released_at DESC,id DESC LIMIT $3`, repoID, nil, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

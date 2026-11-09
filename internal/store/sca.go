package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// SCAObservation batches the evidence needed by repository coverage views.
type SCAObservation struct {
	RepoID              uuid.UUID
	HeadCommit          string
	SnapshotID          *uuid.UUID
	CommitSHA           string
	HasInventory        bool
	HasComponents       bool
	ProducerOutcome     string
	Detail              string
	JobID               *uuid.UUID
	JobStatus           string
	JobError            string
	JobCommit           string
	LastAttempt         *time.Time
	ScanStatus          string
	ScanError           string
	ProviderFailed      bool
	LastAssessed        *time.Time
	HasReportedFindings bool
	PreviousInventory   bool
	PreviousCommit      string
	PreviousAssessed    *time.Time
	InventorySource     string
	InventoryCommit     string
	InventorySources    []string
}

// LockSCAInventory pins the current immutable identity until enablement commits.
func (q *Queries) LockSCAInventory(ctx context.Context, orgID uuid.UUID, providerID string) (*ForgeRepository, error) {
	if q.tx == nil {
		return nil, errors.New("inventory locking requires a transaction")
	}
	var key, provider, account string
	err := q.tx.QueryRowContext(ctx, `
		SELECT f.provider_key,f.provider,f.account_login FROM forge_repositories f
		JOIN organizations o ON o.id=$1 AND o.provider=f.provider
		WHERE lower(f.provider_key)=lower($2) AND lower(f.account_login)=lower(o.forge_account_login)
		AND o.forge_account_id<>'' AND f.account_id=o.forge_account_id
		AND COALESCE(f.provider_repo_id,'')<>'' AND f.removed_at IS NULL
		FOR SHARE OF f`, orgID, providerID).Scan(&key, &provider, &account)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return q.GetForgeRepositoryForAccount(ctx, provider, account, key)
}

func (q *Queries) ListSCAObservations(ctx context.Context, orgID, repoID uuid.UUID, refName string, refType RefType) (map[uuid.UUID]SCAObservation, error) {
	rows, err := q.rawDB().QueryContext(ctx, `
	SELECT repo.id, COALESCE(r.latest_commit_sha,''), s.id,
		COALESCE(s.commit_sha,''), COALESCE(s.inventory_set_id IS NOT NULL,false),
		COALESCE(s.has_components,false),
		COALESCE(pr.outcome::text,''), COALESCE(pr.detail,''),
		j.id, COALESCE(j.status,''), COALESCE(j.last_error,''), COALESCE(j.commit_sha,''),
		COALESCE(j.started_at,j.created_at), COALESCE(sc.status::text,''),
		COALESCE(sc.error_message,''),
		EXISTS(SELECT 1 FROM scan_providers sp WHERE sp.scan_id=sc.id AND sp.status='failed'),
		(SELECT max(done.completed_at) FROM scans done WHERE done.snapshot_id=s.id AND done.status='complete'),
		EXISTS(SELECT 1 FROM vulnerabilities v WHERE v.snapshot_id=s.id AND v.type IN('dependency','container','malware')),
		previous.id IS NOT NULL,COALESCE(previous.commit_sha,''),
		(SELECT max(done.completed_at) FROM scans done WHERE done.snapshot_id=previous.id AND done.status='complete'),
		CASE WHEN cardinality(provenance.kinds)>1 THEN 'mixed'
			WHEN cardinality(provenance.kinds)=1 THEN provenance.kinds[1]
			WHEN s.inventory_set_id IS NOT NULL OR COALESCE(s.has_components,false) OR previous.id IS NOT NULL THEN 'unknown'
			ELSE 'none' END,
		CASE WHEN s.inventory_set_id IS NOT NULL OR COALESCE(s.has_components,false) THEN COALESCE(s.commit_sha,'')
			ELSE COALESCE(previous.commit_sha,'') END,
		COALESCE(provenance.kinds,ARRAY[]::text[])
	FROM repositories repo
	LEFT JOIN refs r ON r.repo_id=repo.id AND r.name=CASE WHEN $2='' THEN repo.default_branch ELSE $2 END
		AND r.ref_type=$4::ref_type
	LEFT JOIN LATERAL (
		SELECT sn.id,sn.commit_sha,sn.inventory_set_id,
			EXISTS(SELECT 1 FROM snapshot_components c WHERE c.snapshot_id=sn.id) AS has_components
		FROM snapshots sn WHERE sn.ref_id=r.id AND sn.status<>'purged'
			AND (COALESCE(r.latest_commit_sha,'')='' OR sn.commit_sha=r.latest_commit_sha)
		ORDER BY (sn.status IN('complete','active')) DESC,sn.created_at DESC,sn.id DESC LIMIT 1
	) s ON true
	LEFT JOIN LATERAL (
		SELECT sn.id,sn.commit_sha FROM snapshots sn
		WHERE sn.ref_id=r.id AND sn.status IN('complete','active')
			AND (sn.inventory_set_id IS NOT NULL OR EXISTS(SELECT 1 FROM snapshot_components c WHERE c.snapshot_id=sn.id))
		ORDER BY sn.created_at DESC,sn.id DESC LIMIT 1
	) previous ON true
	LEFT JOIN LATERAL (
		SELECT array_agg(DISTINCT CASE
			WHEN src.extraction_run_id IS NOT NULL OR a.origin='hibou'
				OR (src.artifact_id IS NULL AND src.label='sbom:hibou-depinventory.cdx.json') THEN 'repository'
			WHEN a.kind='sbom' AND a.tool_name='hibou-deps' THEN 'cli'
			WHEN a.kind='sbom' THEN 'sbom'
			ELSE 'unknown' END) AS kinds
		FROM inventory_sources src LEFT JOIN snapshot_artifacts a ON a.id=src.artifact_id
		WHERE src.snapshot_id=CASE WHEN s.inventory_set_id IS NOT NULL OR COALESCE(s.has_components,false) THEN s.id ELSE previous.id END
			AND (a.id IS NULL OR a.revoked_at IS NULL)
	) provenance ON true
	LEFT JOIN LATERAL (
		SELECT p.outcome,p.detail FROM producer_runs p
		WHERE p.snapshot_id=s.id AND p.producer='dependency-inventory:hibou'
		ORDER BY p.created_at DESC LIMIT 1
	) pr ON true
	LEFT JOIN LATERAL (
		SELECT job.* FROM dep_extraction_jobs job
		WHERE job.repo_id=repo.id AND job.ref_name=CASE WHEN $2='' THEN repo.default_branch ELSE $2 END
		ORDER BY job.created_at DESC,job.id DESC LIMIT 1
	) j ON true
	LEFT JOIN LATERAL (
		SELECT scan.* FROM scans scan WHERE scan.snapshot_id=s.id
		ORDER BY scan.created_at DESC,scan.id DESC LIMIT 1
	) sc ON true
	WHERE repo.org_id=$1 AND ($3::uuid='00000000-0000-0000-0000-000000000000' OR repo.id=$3)`, orgID, refName, repoID, refType)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	result := make(map[uuid.UUID]SCAObservation)
	for rows.Next() {
		var o SCAObservation
		var snapshotID, jobID uuid.NullUUID
		var attempt, assessed, previousAssessed sql.NullTime
		if err := rows.Scan(&o.RepoID, &o.HeadCommit, &snapshotID, &o.CommitSHA,
			&o.HasInventory, &o.HasComponents, &o.ProducerOutcome, &o.Detail, &jobID,
			&o.JobStatus, &o.JobError, &o.JobCommit, &attempt, &o.ScanStatus,
			&o.ScanError, &o.ProviderFailed, &assessed, &o.HasReportedFindings,
			&o.PreviousInventory, &o.PreviousCommit, &previousAssessed, &o.InventorySource, &o.InventoryCommit,
			pq.Array(&o.InventorySources)); err != nil {
			return nil, err
		}
		o.SnapshotID = uuidPtrFromNull(snapshotID)
		o.JobID = uuidPtrFromNull(jobID)
		o.LastAttempt = timePtrFromNull(attempt)
		o.LastAssessed = timePtrFromNull(assessed)
		o.PreviousAssessed = timePtrFromNull(previousAssessed)
		sort.Strings(o.InventorySources)
		result[o.RepoID] = o
	}
	return result, rows.Err()
}

// EnqueueSCAExtraction serializes explicit requests for a repository. A
// processing job is adopted instead of creating another clone.
func (q *Queries) EnqueueSCAExtraction(ctx context.Context, params EnqueueDepExtractionJobParams) (*DepExtractionJob, bool, error) {
	if q.tx == nil {
		return nil, false, errors.New("SCA enqueue requires a transaction")
	}
	if _, err := q.tx.ExecContext(ctx, `SELECT id FROM repositories WHERE id=$1 FOR UPDATE`, params.RepoID); err != nil {
		return nil, false, err
	}
	latest, err := q.GetLatestDepExtractionJobForRef(ctx, params.RepoID, params.RefName)
	if err != nil {
		return nil, false, err
	}
	if latest != nil && (latest.Status == "pending" || latest.Status == "processing" ||
		latest.Status == "failed" && latest.FinishedAt == nil) &&
		(params.CommitSHA == "" || latest.CommitSHA == "" || latest.CommitSHA == params.CommitSHA) {
		return latest, false, nil
	}
	job, err := q.EnqueueDepExtractionJob(ctx, params)
	return job, true, err
}

// Bootstrap only repairs never-attempted enrollment, not exhausted failures or
// completed empty inventories. No forge calls or discovery enrollment occur.
func (q *Queries) BootstrapSCA(ctx context.Context, orgID uuid.UUID, limit int) (int64, error) {
	result, err := q.execer().ExecContext(ctx, `
	WITH candidates AS (
		SELECT repo.id,repo.default_branch,COALESCE(r.latest_commit_sha,'') AS commit_sha,
			row_number() OVER (PARTITION BY repo.org_id ORDER BY repo.created_at,repo.id) AS org_rank
		FROM repositories repo
		JOIN organizations o ON o.id=repo.org_id
		JOIN forge_repository_bindings b ON b.repo_id=repo.id AND b.account_id=o.forge_account_id
		JOIN forge_repositories f ON f.provider=repo.provider AND lower(f.provider_key)=lower(repo.provider_id)
			AND f.account_id=b.account_id AND f.provider_repo_id=b.repository_id
			AND lower(f.account_login)=lower(o.forge_account_login) AND NOT f.archived AND f.removed_at IS NULL
		LEFT JOIN refs r ON r.repo_id=repo.id AND r.name=repo.default_branch AND r.ref_type='branch'
		WHERE repo.default_branch<>''
		AND ($2::uuid='00000000-0000-0000-0000-000000000000' OR repo.org_id=$2)
		AND NOT EXISTS (SELECT 1 FROM dep_extraction_jobs j WHERE j.repo_id=repo.id AND j.ref_name=repo.default_branch)
		AND NOT EXISTS (SELECT 1 FROM snapshots s WHERE s.ref_id=r.id AND s.status<>'purged'
			AND s.inventory_set_id IS NOT NULL
			AND (COALESCE(r.latest_commit_sha,'')='' OR s.commit_sha=r.latest_commit_sha))
	), picked AS (
		SELECT repo.id,c.default_branch,c.commit_sha FROM candidates c JOIN repositories repo ON repo.id=c.id
		WHERE c.org_rank<=10 ORDER BY c.org_rank,repo.created_at,repo.id
		LIMIT $1 FOR UPDATE OF repo SKIP LOCKED
	)
	INSERT INTO dep_extraction_jobs(repo_id,ref_name,commit_sha,reason)
	SELECT id,default_branch,commit_sha,'enrollment' FROM picked
	ON CONFLICT (repo_id,ref_name) WHERE status='pending' DO NOTHING`, limit, orgID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

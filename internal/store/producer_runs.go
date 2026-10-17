package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Producer run scopes and outcomes (ADR-034 §2).
const (
	ProducerScopeFull    = "full"
	ProducerScopePartial = "partial"

	ProducerOutcomeCompleted = "completed"
	ProducerOutcomePartial   = "partial"
	ProducerOutcomeFailed    = "failed"

	// ProducerSBOMMatching is SBOM advisory matching. Its runs are the
	// snapshot's advisory scans (scans table), not producer_runs rows: the
	// gate's readiness guard already reads them.
	ProducerSBOMMatching = "sbom-matching"
)

// SkippedFile is a file a producer did not analyse, with why: timeout,
// too_large, parse_error or other.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ProducerRun is what one producer did on one snapshot: the evidence that a
// finding missing from the snapshot was re-checked, or was not (ADR-034).
type ProducerRun struct {
	ID            uuid.UUID     `json:"id"`
	SnapshotID    uuid.UUID     `json:"snapshot_id"`
	ArtifactID    *uuid.UUID    `json:"artifact_id,omitempty"`
	RunIndex      int           `json:"run_index"`
	Producer      string        `json:"producer"`
	Version       *string       `json:"version,omitempty"`
	ConfigDigest  *string       `json:"config_digest,omitempty"`
	Scope         string        `json:"scope"`
	ScopeDeclared bool          `json:"scope_declared"`
	ScopePaths    []string      `json:"scope_paths"`
	Outcome       string        `json:"outcome"`
	SkippedFiles  []SkippedFile `json:"skipped_files"`
	FindingCount  int           `json:"finding_count"`
	Detail        *string       `json:"detail,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
	// PlanID / PlanJobID: the scan plan job that produced the run, when it
	// was planned (ADR-035 §4). Evidence for enforced coverage requires it.
	PlanID    *uuid.UUID `json:"plan_id,omitempty"`
	PlanJobID *string    `json:"plan_job_id,omitempty"`
}

// ProducerRunInput is the write shape for one run.
type ProducerRunInput struct {
	Producer      string
	Version       *string
	ConfigDigest  *string
	Scope         string
	ScopeDeclared bool
	ScopePaths    []string
	Outcome       string
	SkippedFiles  []SkippedFile
	FindingCount  int
	Detail        *string
}

// ReplaceArtifactProducerRuns writes the runs of one artifact, replacing any
// left by an earlier processing attempt. Call inside the artifact's ingest
// transaction so runs and findings land together.
func (q *Queries) ReplaceArtifactProducerRuns(ctx context.Context, snapshotID, artifactID uuid.UUID, runs []ProducerRunInput) error {
	if err := q.db.DeleteProducerRunsByArtifact(ctx, uuid.NullUUID{UUID: artifactID, Valid: true}); err != nil {
		return err
	}
	for index, run := range runs {
		skipped, paths := producerRunCollections(run)
		if _, err := q.db.CreateArtifactProducerRun(ctx, dbgen.CreateArtifactProducerRunParams{
			SnapshotID:    snapshotID,
			ArtifactID:    uuid.NullUUID{UUID: artifactID, Valid: true},
			RunIndex:      int32(index), // #nosec G115 -- SARIF run count, far below int32
			Producer:      run.Producer,
			Version:       nullStringFromPtr(run.Version),
			ConfigDigest:  nullStringFromPtr(run.ConfigDigest),
			Scope:         dbgen.ProducerRunScope(run.Scope),
			ScopeDeclared: run.ScopeDeclared,
			ScopePaths:    paths,
			Outcome:       dbgen.ProducerRunOutcome(run.Outcome),
			SkippedFiles:  skipped,
			FindingCount:  int32(run.FindingCount), // #nosec G115 -- per-run finding count
			Detail:        nullStringFromPtr(run.Detail),
		}); err != nil {
			return err
		}
	}
	return nil
}

// UpsertSnapshotProducerRun records a server-side producer (secret scanning,
// SBOM advisory matching): one row per producer per snapshot.
func (q *Queries) UpsertSnapshotProducerRun(ctx context.Context, snapshotID uuid.UUID, run ProducerRunInput) (*ProducerRun, error) {
	skipped, paths := producerRunCollections(run)
	row, err := q.db.UpsertSnapshotProducerRun(ctx, dbgen.UpsertSnapshotProducerRunParams{
		SnapshotID:    snapshotID,
		Producer:      run.Producer,
		Version:       nullStringFromPtr(run.Version),
		ConfigDigest:  nullStringFromPtr(run.ConfigDigest),
		Scope:         dbgen.ProducerRunScope(run.Scope),
		ScopeDeclared: run.ScopeDeclared,
		ScopePaths:    paths,
		Outcome:       dbgen.ProducerRunOutcome(run.Outcome),
		SkippedFiles:  skipped,
		FindingCount:  int32(run.FindingCount), // #nosec G115 -- per-run finding count
		Detail:        nullStringFromPtr(run.Detail),
	})
	if err != nil {
		return nil, err
	}
	out := producerRunFromRow(row)
	return &out, nil
}

func (q *Queries) ListProducerRunsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]ProducerRun, error) {
	rows, err := q.db.ListProducerRunsBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	out := make([]ProducerRun, len(rows))
	for i, row := range rows {
		out[i] = producerRunFromRow(row)
	}
	return out, nil
}

func producerRunCollections(run ProducerRunInput) (json.RawMessage, []string) {
	skippedFiles := run.SkippedFiles
	if skippedFiles == nil {
		skippedFiles = []SkippedFile{}
	}
	skipped, err := json.Marshal(skippedFiles)
	if err != nil {
		skipped = json.RawMessage(`[]`)
	}
	paths := run.ScopePaths
	if paths == nil {
		paths = []string{}
	}
	return skipped, paths
}

func producerRunFromRow(row dbgen.ProducerRun) ProducerRun {
	out := ProducerRun{
		ID:            row.ID,
		SnapshotID:    row.SnapshotID,
		RunIndex:      int(row.RunIndex),
		Producer:      row.Producer,
		Version:       stringPtrFromNull(row.Version),
		ConfigDigest:  stringPtrFromNull(row.ConfigDigest),
		Scope:         string(row.Scope),
		ScopeDeclared: row.ScopeDeclared,
		ScopePaths:    row.ScopePaths,
		Outcome:       string(row.Outcome),
		SkippedFiles:  []SkippedFile{},
		FindingCount:  int(row.FindingCount),
		Detail:        stringPtrFromNull(row.Detail),
		CreatedAt:     row.CreatedAt,
		PlanID:        uuidPtrFromNull(row.PlanID),
		PlanJobID:     stringPtrFromNull(row.PlanJobID),
	}
	if row.ArtifactID.Valid {
		id := row.ArtifactID.UUID
		out.ArtifactID = &id
	}
	if out.ScopePaths == nil {
		out.ScopePaths = []string{}
	}
	_ = json.Unmarshal(row.SkippedFiles, &out.SkippedFiles)
	return out
}

// GetPreviousCompleteSnapshotByRef returns the snapshot a snapshot's coverage
// is compared with: the latest finished snapshot of its ref created before
// it, or nil.
func (q *Queries) GetPreviousCompleteSnapshotByRef(ctx context.Context, snapshot *Snapshot) (*Snapshot, error) {
	row, err := q.db.GetPreviousCompleteSnapshotByRef(ctx, dbgen.GetPreviousCompleteSnapshotByRefParams{
		RefID:      snapshot.RefID,
		SnapshotID: snapshot.ID,
		CreatedAt:  snapshot.CreatedAt,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return snapshotFromRow(row), nil
}

// CarryInput is one finding to copy into a snapshot as a carried row
// (ADR-034 §3).
type CarryInput struct {
	SourceID            uuid.UUID  `json:"id"`
	Presence            string     `json:"presence"`
	Reason              string     `json:"reason"`
	LastSeenSnapshotID  *uuid.UUID `json:"last_seen_snapshot_id"`
	LastSeenCommit      string     `json:"last_seen_commit"`
	ConsecutiveAbsences int        `json:"consecutive_absences"`
}

func (q *Queries) LockRefForPresence(ctx context.Context, refID uuid.UUID) error {
	return q.db.LockRefForPresence(ctx, refID.String())
}

// CarryVulnerabilitiesForward copies the previous snapshot's rows for the
// given findings into the snapshot (ADR-049: pointer rows, not findings)
// and returns how many were inserted (a row the producer reported
// meanwhile is skipped).
func (q *Queries) CarryVulnerabilitiesForward(ctx context.Context, snapshotID, fromSnapshotID uuid.UUID, carries []CarryInput) (int64, error) {
	if len(carries) == 0 {
		return 0, nil
	}
	encoded, err := json.Marshal(carries)
	if err != nil {
		return 0, err
	}
	return q.db.CarryVulnerabilitiesForward(ctx, dbgen.CarryVulnerabilitiesForwardParams{
		SnapshotID:     snapshotID,
		Carries:        encoded,
		FromSnapshotID: fromSnapshotID,
	})
}

// UpdateCarriedPresence refreshes a carried row's presence fields; reported
// rows are never touched.
func (q *Queries) UpdateCarriedPresence(ctx context.Context, snapshotID, id uuid.UUID, carry CarryInput) error {
	return q.db.UpdateCarriedPresence(ctx, dbgen.UpdateCarriedPresenceParams{
		SnapshotID:          snapshotID,
		ID:                  id,
		Presence:            dbgen.FindingPresence(carry.Presence),
		Reason:              nullStringFromPtr(nonEmptyPtr(carry.Reason)),
		LastSeenSnapshotID:  nullUUIDFromPtr(carry.LastSeenSnapshotID),
		ConsecutiveAbsences: int32(carry.ConsecutiveAbsences), // #nosec G115 -- scan count
	})
}

// DeleteCarriedVulnerabilities removes carried rows that no longer apply.
func (q *Queries) DeleteCarriedVulnerabilities(ctx context.Context, snapshotID uuid.UUID, ids []uuid.UUID) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	return q.db.DeleteCarriedVulnerabilities(ctx, dbgen.DeleteCarriedVulnerabilitiesParams{SnapshotID: snapshotID, Ids: ids})
}

func nonEmptyPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// SnapshotProducerRuns returns the snapshot's recorded runs plus the SBOM
// matching run derived from its latest advisory scan.
func (q *Queries) SnapshotProducerRuns(ctx context.Context, snapshotID uuid.UUID) ([]ProducerRun, error) {
	runs, err := q.ListProducerRunsBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	scans, err := q.ListScansBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	if run, ok := sbomMatchingRun(snapshotID, scans); ok {
		runs = append(runs, run)
	}
	return runs, nil
}

// SnapshotCoverageKnown reports whether the snapshot's producer runs can be
// trusted as its coverage: false for snapshots processed before runs were
// recorded.
func (q *Queries) SnapshotCoverageKnown(ctx context.Context, snapshotID uuid.UUID) (bool, error) {
	return q.db.SnapshotCoverageKnown(ctx, snapshotID)
}

// sbomMatchingRun maps the latest advisory scan (ListScansBySnapshot is
// newest first) onto a producer run. Pending and running scans keep the
// outcome empty: not finished.
func sbomMatchingRun(snapshotID uuid.UUID, scans []dbgen.Scan) (ProducerRun, bool) {
	if len(scans) == 0 {
		return ProducerRun{}, false
	}
	scan := scans[0]
	run := ProducerRun{
		ID:            scan.ID,
		SnapshotID:    snapshotID,
		Producer:      ProducerSBOMMatching,
		Scope:         ProducerScopeFull,
		ScopeDeclared: true,
		ScopePaths:    []string{},
		SkippedFiles:  []SkippedFile{},
		CreatedAt:     scan.CreatedAt,
	}
	if len(scan.ProvidersRequested) > 0 {
		providers := strings.Join(scan.ProvidersRequested, ", ")
		run.ConfigDigest = &providers
	}
	switch dbgen.ScanStatus(scan.Status) {
	case dbgen.ScanStatusComplete:
		run.Outcome = ProducerOutcomeCompleted
	case dbgen.ScanStatusFailed, dbgen.ScanStatusCancelled:
		run.Outcome = ProducerOutcomeFailed
		if detail := strings.TrimSpace(scan.ErrorMessage); detail != "" {
			run.Detail = &detail
		}
	}
	return run, true
}

// ListPresenceRowsBySnapshot returns the snapshot's findings with only the
// fields finding presence reads (ADR-034): identity, location, status,
// provenance, presence, and metadata reduced to trace_files.
func (q *Queries) ListPresenceRowsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]Vulnerability, error) {
	rows, err := q.db.ListPresenceRowsBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	out := make([]Vulnerability, len(rows))
	for i, row := range rows {
		out[i] = Vulnerability{
			ID: row.ID, Type: row.Type, SnapshotID: snapshotID, Fingerprint: row.Fingerprint,
			ScannerName: row.ScannerName, FilePath: stringPtrFromNull(row.FilePath), Status: row.Status,
			Origin: row.Origin, Presence: row.Presence, PresenceReason: stringPtrFromNull(row.PresenceReason),
			LastSeenSnapshotID: uuidPtrFromNull(row.LastSeenSnapshotID), LastSeenCommit: nonEmptyPtr(row.LastSeenCommit),
			ConsecutiveAbsences: int(row.ConsecutiveAbsences),
		}
		if raw, ok := row.TraceFiles.([]byte); ok && len(raw) > 0 && string(raw) != "null" {
			out[i].Metadata = append(append([]byte(`{"trace_files":`), raw...), '}')
		}
	}
	return out, nil
}

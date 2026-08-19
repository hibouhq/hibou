package retention

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/objstore"
	storepkg "github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type workerStoreStub struct {
	repositories   []storepkg.Repository
	refsByRepo     map[uuid.UUID][]storepkg.Ref
	snapshotsByRef map[uuid.UUID][]storepkg.Snapshot
	severityByID   map[uuid.UUID][]dbgen.ListVulnerabilitySummaryBySnapshotRow
	keysByID       map[uuid.UUID][]string
	archivedIDs    []uuid.UUID
	purgedIDs      []uuid.UUID
	failedIDs      []uuid.UUID
	auditLogs      []dbgen.CreateAuditLogParams
	staleSnapshots []dbgen.Snapshot
	staleBefore    time.Time
	staleLimit     int32
	staleListCalls int
	rolledUpIDs    []uuid.UUID
	rollups        map[uuid.UUID]storepkg.SnapshotVulnRollup
}

func (s *workerStoreStub) ListRepositoriesForRetention(context.Context) ([]storepkg.Repository, error) {
	return append([]storepkg.Repository(nil), s.repositories...), nil
}

func (s *workerStoreStub) ListRefsByRepo(_ context.Context, repoID uuid.UUID, limit, offset int) ([]storepkg.Ref, int, error) {
	rows := append([]storepkg.Ref(nil), s.refsByRepo[repoID]...)
	if offset >= len(rows) {
		return nil, len(rows), nil
	}
	end := offset + limit
	if end > len(rows) {
		end = len(rows)
	}
	return rows[offset:end], len(rows), nil
}

func (s *workerStoreStub) ListSnapshotsForRetentionTimeline(_ context.Context, _ uuid.UUID, refID uuid.UUID) ([]storepkg.Snapshot, error) {
	return append([]storepkg.Snapshot(nil), s.snapshotsByRef[refID]...), nil
}

func (s *workerStoreStub) ListVulnerabilitySummaryBySnapshot(_ context.Context, snapshotID uuid.UUID) ([]dbgen.ListVulnerabilitySummaryBySnapshotRow, error) {
	return append([]dbgen.ListVulnerabilitySummaryBySnapshotRow(nil), s.severityByID[snapshotID]...), nil
}

func (s *workerStoreStub) ListStalePendingSnapshots(_ context.Context, startedBefore, placeholderBefore time.Time, limit int32) ([]dbgen.Snapshot, error) {
	s.staleBefore = startedBefore
	s.staleLimit = limit
	s.staleListCalls++
	rows := make([]dbgen.Snapshot, 0, len(s.staleSnapshots))
	for _, snapshot := range s.staleSnapshots {
		if snapshot.Status != dbgen.SnapshotStatusPending {
			continue
		}
		// Mirrors the SQL: run-less zero-upload placeholders get the longer leash.
		cutoff := startedBefore
		if !snapshot.RunID.Valid && snapshot.ReceivedUploads == 0 {
			cutoff = placeholderBefore
		}
		if snapshot.CreatedAt.Before(cutoff) {
			rows = append(rows, snapshot)
		}
	}
	if len(rows) > int(limit) {
		rows = rows[:limit]
	}
	return rows, nil
}

func (s *workerStoreStub) ListSnapshotArtifactObjectKeys(_ context.Context, snapshotID uuid.UUID) ([]string, error) {
	return append([]string(nil), s.keysByID[snapshotID]...), nil
}

func (s *workerStoreStub) ArchiveSnapshot(_ context.Context, id uuid.UUID) error {
	s.archivedIDs = append(s.archivedIDs, id)
	s.mutateSnapshot(id, storepkg.SnapshotStatusArchived)
	return nil
}

func (s *workerStoreStub) PurgeSnapshot(_ context.Context, id uuid.UUID) error {
	s.purgedIDs = append(s.purgedIDs, id)
	s.mutateSnapshot(id, storepkg.SnapshotStatusPurged)
	return nil
}

func (s *workerStoreStub) MarkSnapshotFailed(_ context.Context, id uuid.UUID) error {
	s.failedIDs = append(s.failedIDs, id)
	return nil
}

func (s *workerStoreStub) RollupSnapshotVulnerabilities(_ context.Context, snapshotID uuid.UUID) (int64, error) {
	s.rolledUpIDs = append(s.rolledUpIDs, snapshotID)
	// Simulate the DB: detail rows are gone, a rollup remains.
	rows := s.severityByID[snapshotID]
	if s.rollups == nil {
		s.rollups = map[uuid.UUID]storepkg.SnapshotVulnRollup{}
	}
	counts := map[string]map[string]int64{}
	var total int64
	for _, row := range rows {
		if counts["generic"] == nil {
			counts["generic"] = map[string]int64{}
		}
		counts["generic"][row.Severity] += row.Count
		total += row.Count
	}
	countsJSON, _ := json.Marshal(counts)
	s.rollups[snapshotID] = storepkg.SnapshotVulnRollup{SnapshotID: snapshotID, Counts: countsJSON, Total: int32(total)}
	delete(s.severityByID, snapshotID)
	return total, nil
}

func (s *workerStoreStub) GetSnapshotVulnRollup(_ context.Context, snapshotID uuid.UUID) (storepkg.SnapshotVulnRollup, bool, error) {
	rollup, ok := s.rollups[snapshotID]
	return rollup, ok, nil
}

func (s *workerStoreStub) CreateAuditLog(_ context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error) {
	s.auditLogs = append(s.auditLogs, arg)
	return dbgen.AuditLog{ID: uuid.New(), Action: arg.Action}, nil
}

func (s *workerStoreStub) mutateSnapshot(id uuid.UUID, status storepkg.SnapshotStatus) {
	for refID, snapshots := range s.snapshotsByRef {
		changed := false
		for i := range snapshots {
			if snapshots[i].ID != id {
				continue
			}
			snapshots[i].Status = status
			snapshots[i].ArtifactBytes = 0
			changed = true
		}
		if changed {
			s.snapshotsByRef[refID] = snapshots
		}
	}
	s.recomputeUsage()
}

func (s *workerStoreStub) recomputeUsage() {
	for i := range s.repositories {
		var total int64
		for _, ref := range s.refsByRepo[s.repositories[i].ID] {
			for _, snapshot := range s.snapshotsByRef[ref.ID] {
				total += snapshot.ArtifactBytes
			}
		}
		s.repositories[i].RetentionArtifactBytes = total
	}
}

type workerObjStoreStub struct {
	deleted []string
	err     error
}

func (s *workerObjStoreStub) Put(context.Context, string, io.Reader, string) error { return nil }
func (s *workerObjStoreStub) Get(context.Context, string) (io.ReadCloser, error)   { return nil, nil }
func (s *workerObjStoreStub) Exists(context.Context, string) (bool, error)         { return false, nil }
func (s *workerObjStoreStub) Delete(_ context.Context, key string) error {
	s.deleted = append(s.deleted, key)
	return s.err
}

type workerBusStub struct {
	events []events.Event
}

func (b *workerBusStub) Publish(_ context.Context, evt events.Event) {
	b.events = append(b.events, evt)
}

func TestWorkerFailedRetentionAndEnvelopeAreIdempotent(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	repoID := uuid.New()
	orgID := uuid.New()
	refID := uuid.New()
	failedID := uuid.New()
	oldestID := uuid.New()
	newestID := uuid.New()
	budget := int64(100)
	target := 0.5
	order := EvictOldest
	failedRetention := 24 * time.Hour
	latestPerRef := false

	storeStub := &workerStoreStub{
		repositories: []storepkg.Repository{{ID: repoID, OrgID: orgID, Name: "api", RetentionArtifactBytes: 140}},
		refsByRepo: map[uuid.UUID][]storepkg.Ref{
			repoID: {{ID: refID, RepoID: repoID, Name: "main", RefType: storepkg.RefTypeBranch}},
		},
		snapshotsByRef: map[uuid.UUID][]storepkg.Snapshot{
			refID: {
				{ID: failedID, RefID: refID, Status: storepkg.SnapshotStatusFailed, ArtifactBytes: 20, CreatedAt: now.Add(-10 * 24 * time.Hour)},
				{ID: oldestID, RefID: refID, Status: storepkg.SnapshotStatusComplete, ArtifactBytes: 70, CreatedAt: now.Add(-9 * 24 * time.Hour)},
				{ID: newestID, RefID: refID, Status: storepkg.SnapshotStatusComplete, ArtifactBytes: 50, CreatedAt: now.Add(-8 * 24 * time.Hour)},
			},
		},
		keysByID: map[uuid.UUID][]string{
			failedID: {"failed.json"},
			oldestID: {"oldest.json"},
		},
	}
	objStore := &workerObjStoreStub{}
	bus := &workerBusStub{}
	policy := Resolve("envelope", PolicyOverrides{
		Storage:         StoragePolicyOverrides{Budget: &budget, Target: &target, EvictOrder: &order},
		FailedRetention: &failedRetention,
		Pin:             PinPolicyOverrides{LatestPerRef: &latestPerRef},
		AutoPurge:       boolPtr(true),
	})

	worker := NewWorker(storeStub, objStore, storeStub, bus, zerolog.New(io.Discard), policy, 10*time.Minute)
	worker.now = func() time.Time { return now }

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() first error = %v", err)
	}
	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() second error = %v", err)
	}
	if got := storeStub.archivedIDs; len(got) != 1 || got[0] != oldestID {
		t.Fatalf("archived IDs = %v, want [%s]", got, oldestID)
	}
	// Archiving must downsample: the archived snapshot's detail rows are rolled
	// up (ADR db-review P0.1). Purged snapshots are removed outright, not rolled up.
	if got := storeStub.rolledUpIDs; len(got) != 1 || got[0] != oldestID {
		t.Fatalf("rolled-up IDs = %v, want [%s]", got, oldestID)
	}
	if got := storeStub.purgedIDs; len(got) != 1 || got[0] != failedID {
		t.Fatalf("purged IDs = %v, want [%s]", got, failedID)
	}
	if got := storeStub.repositories[0].RetentionArtifactBytes; got != 50 {
		t.Fatalf("repo retention bytes = %d, want 50", got)
	}
	if len(storeStub.auditLogs) != 2 {
		t.Fatalf("audit logs = %d, want 2", len(storeStub.auditLogs))
	}
	if storeStub.auditLogs[0].Action != audit.ActionRetentionPurge || storeStub.auditLogs[1].Action != audit.ActionRetentionArchive {
		t.Fatalf("audit actions = %+v, want purge then archive", storeStub.auditLogs)
	}
	if len(objStore.deleted) != 2 {
		t.Fatalf("deleted keys = %v, want 2", objStore.deleted)
	}
	if len(bus.events) == 0 || bus.events[0].Type != events.RetentionEviction {
		t.Fatalf("retention events = %#v, want eviction event first", bus.events)
	}
}

func TestWorkerDryRunDoesNotMutate(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	repoID := uuid.New()
	refID := uuid.New()
	firstID := uuid.New()
	secondID := uuid.New()
	budget := int64(100)
	target := 0.5
	order := EvictOldest
	latestPerRef := false
	bus := &workerBusStub{}

	storeStub := &workerStoreStub{
		repositories: []storepkg.Repository{{ID: repoID, OrgID: uuid.New(), Name: "dry-run", RetentionArtifactBytes: 120}},
		refsByRepo: map[uuid.UUID][]storepkg.Ref{
			repoID: {{ID: refID, RepoID: repoID, Name: "main", RefType: storepkg.RefTypeBranch}},
		},
		snapshotsByRef: map[uuid.UUID][]storepkg.Snapshot{
			refID: {
				{ID: firstID, RefID: refID, Status: storepkg.SnapshotStatusComplete, ArtifactBytes: 70, CreatedAt: now.Add(-3 * 24 * time.Hour)},
				{ID: secondID, RefID: refID, Status: storepkg.SnapshotStatusComplete, ArtifactBytes: 50, CreatedAt: now.Add(-2 * 24 * time.Hour)},
			},
		},
	}
	policy := Resolve("envelope", PolicyOverrides{
		Storage:   StoragePolicyOverrides{Budget: &budget, Target: &target, EvictOrder: &order},
		Pin:       PinPolicyOverrides{LatestPerRef: &latestPerRef},
		AutoPurge: boolPtr(true),
		DryRun:    boolPtr(true),
	})
	worker := NewWorker(storeStub, &workerObjStoreStub{}, storeStub, bus, zerolog.New(io.Discard), policy, 10*time.Minute)
	worker.now = func() time.Time { return now }

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(storeStub.archivedIDs) != 0 || len(storeStub.purgedIDs) != 0 {
		t.Fatalf("mutations happened in dry-run mode: archived=%v purged=%v", storeStub.archivedIDs, storeStub.purgedIDs)
	}
	if len(bus.events) == 0 || bus.events[0].Type != events.RetentionEviction {
		t.Fatalf("retention events = %#v, want eviction event", bus.events)
	}
}

func TestWorkerProtectsPinnedLabelsOnClosedPullRequests(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	repoID := uuid.New()
	refID := uuid.New()
	protectedID := uuid.New()
	thinID := uuid.New()
	closed := "closed"
	labels := []string{"baseline"}
	keepAll := 24 * time.Hour
	latestPerRef := false

	storeStub := &workerStoreStub{
		repositories: []storepkg.Repository{{ID: repoID, OrgID: uuid.New(), Name: "pr-repo", RetentionArtifactBytes: 30}},
		refsByRepo: map[uuid.UUID][]storepkg.Ref{
			repoID: {{ID: refID, RepoID: repoID, Name: "pr-42", RefType: storepkg.RefTypePullRequest, PrState: &closed}},
		},
		snapshotsByRef: map[uuid.UUID][]storepkg.Snapshot{
			refID: {
				{ID: protectedID, RefID: refID, Status: storepkg.SnapshotStatusComplete, ArtifactBytes: 10, Labels: []string{"baseline"}, CreatedAt: now.Add(-4 * 24 * time.Hour)},
				{ID: thinID, RefID: refID, Status: storepkg.SnapshotStatusComplete, ArtifactBytes: 20, CreatedAt: now.Add(-3 * 24 * time.Hour)},
			},
		},
		keysByID: map[uuid.UUID][]string{thinID: {"pr.json"}},
	}
	policy := Resolve("envelope", PolicyOverrides{
		Pin:         PinPolicyOverrides{LatestPerRef: &latestPerRef, Labels: &labels},
		PRSnapshots: PRSnapshotsPolicyOverrides{KeepAll: &keepAll, AfterClose: thinActionPtr(ThinPurge)},
		AutoPurge:   boolPtr(true),
	})
	worker := NewWorker(storeStub, &workerObjStoreStub{}, storeStub, &workerBusStub{}, zerolog.New(io.Discard), policy, 10*time.Minute)
	worker.now = func() time.Time { return now }

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(storeStub.archivedIDs) != 0 {
		t.Fatalf("archived IDs = %v, want none", storeStub.archivedIDs)
	}
	if len(storeStub.purgedIDs) != 1 || storeStub.purgedIDs[0] != thinID {
		t.Fatalf("purged IDs = %v, want [%s]", storeStub.purgedIDs, thinID)
	}
}

func TestWorkerFailedSnapshotsDoNotBecomeTierRepresentatives(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	repoID := uuid.New()
	refID := uuid.New()
	completeID := uuid.New()
	failedID := uuid.New()
	failedRetention := 24 * time.Hour
	latestPerRef := false

	storeStub := &workerStoreStub{
		repositories: []storepkg.Repository{{ID: repoID, OrgID: uuid.New(), Name: "tiers", RetentionArtifactBytes: 30}},
		refsByRepo: map[uuid.UUID][]storepkg.Ref{
			repoID: {{ID: refID, RepoID: repoID, Name: "main", RefType: storepkg.RefTypeBranch}},
		},
		snapshotsByRef: map[uuid.UUID][]storepkg.Snapshot{
			refID: {
				{ID: completeID, RefID: refID, Status: storepkg.SnapshotStatusComplete, ArtifactBytes: 10, CreatedAt: now.Add(-2 * time.Hour)},
				{ID: failedID, RefID: refID, Status: storepkg.SnapshotStatusFailed, ArtifactBytes: 20, CreatedAt: now.Add(-1 * time.Hour)},
			},
		},
		keysByID: map[uuid.UUID][]string{failedID: {"failed.json"}},
	}
	policy := Preset("envelope")
	policy.KeepAll = 0
	policy.Tiers.Enabled = true
	policy.Tiers.Daily = Tier{Keep: 1}
	policy.Tiers.Weekly = Tier{Keep: 0}
	policy.Tiers.Monthly = Tier{Keep: 0}
	policy.Tiers.Yearly = Tier{Keep: 0}
	policy.FailedRetention = failedRetention
	policy.Pin.LatestPerRef = latestPerRef
	policy.AutoPurge = true

	worker := NewWorker(storeStub, &workerObjStoreStub{}, storeStub, &workerBusStub{}, zerolog.New(io.Discard), policy, 10*time.Minute)
	worker.now = func() time.Time { return now }

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(storeStub.archivedIDs) != 0 {
		t.Fatalf("archived IDs = %v, want none", storeStub.archivedIDs)
	}
	if len(storeStub.purgedIDs) != 0 {
		t.Fatalf("purged IDs = %v, want none", storeStub.purgedIDs)
	}
	if got := storeStub.snapshotsByRef[refID][1].Status; got != storepkg.SnapshotStatusFailed {
		t.Fatalf("failed snapshot status = %s, want %s", got, storepkg.SnapshotStatusFailed)
	}
}

func TestWorkerIgnoresMissingArtifacts(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	repoID := uuid.New()
	refID := uuid.New()
	snapshotID := uuid.New()
	failedRetention := 24 * time.Hour
	latestPerRef := false

	storeStub := &workerStoreStub{
		repositories: []storepkg.Repository{{ID: repoID, OrgID: uuid.New(), Name: "missing", RetentionArtifactBytes: 50}},
		refsByRepo: map[uuid.UUID][]storepkg.Ref{
			repoID: {{ID: refID, RepoID: repoID, Name: "main", RefType: storepkg.RefTypeBranch}},
		},
		snapshotsByRef: map[uuid.UUID][]storepkg.Snapshot{
			refID: {{ID: snapshotID, RefID: refID, Status: storepkg.SnapshotStatusFailed, ArtifactBytes: 50, CreatedAt: now.Add(-48 * time.Hour)}},
		},
		keysByID: map[uuid.UUID][]string{snapshotID: {"missing.json"}},
	}
	objStore, err := objstore.NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	policy := Resolve("minimal", PolicyOverrides{FailedRetention: &failedRetention, AutoPurge: boolPtr(true), Pin: PinPolicyOverrides{LatestPerRef: &latestPerRef}})
	worker := NewWorker(storeStub, objStore, storeStub, nil, zerolog.New(io.Discard), policy, 10*time.Minute)
	worker.now = func() time.Time { return now }

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(storeStub.purgedIDs) != 1 || storeStub.purgedIDs[0] != snapshotID {
		t.Fatalf("purged IDs = %v, want [%s]", storeStub.purgedIDs, snapshotID)
	}
}

func TestWorkerSweepStalePending(t *testing.T) {
	now := time.Now()
	stalePendingID := uuid.New()
	recentPendingID := uuid.New()
	completeID := uuid.New()
	activeID := uuid.New()
	archivedID := uuid.New()

	tests := []struct {
		name          string
		pendingWindow time.Duration
		snapshots     []dbgen.Snapshot
		wantFailedIDs []uuid.UUID
		wantListCalls int
	}{
		{
			name:          "fails only stale pending snapshots a build has touched",
			pendingWindow: 10 * time.Minute,
			snapshots:     []dbgen.Snapshot{{ID: stalePendingID, Status: dbgen.SnapshotStatusPending, RunID: sql.NullString{String: "run-1", Valid: true}, CreatedAt: now.Add(-11 * time.Minute)}},
			wantFailedIDs: []uuid.UUID{stalePendingID},
			wantListCalls: 1,
		},
		{
			name:          "run-less placeholder outlives the upload window",
			pendingWindow: 10 * time.Minute,
			snapshots:     []dbgen.Snapshot{{ID: recentPendingID, Status: dbgen.SnapshotStatusPending, CreatedAt: now.Add(-30 * time.Minute)}},
			wantFailedIDs: nil,
			wantListCalls: 1,
		},
		{
			name:          "run-less placeholder fails after the placeholder window",
			pendingWindow: 10 * time.Minute,
			snapshots:     []dbgen.Snapshot{{ID: stalePendingID, Status: dbgen.SnapshotStatusPending, CreatedAt: now.Add(-61 * time.Minute)}},
			wantFailedIDs: []uuid.UUID{stalePendingID},
			wantListCalls: 1,
		},
		{
			name:          "recent pending and terminal snapshots stay untouched",
			pendingWindow: 10 * time.Minute,
			snapshots: []dbgen.Snapshot{
				{ID: completeID, Status: dbgen.SnapshotStatusComplete, CreatedAt: now.Add(-20 * time.Minute)},
				{ID: activeID, Status: dbgen.SnapshotStatusActive, CreatedAt: now.Add(-20 * time.Minute)},
				{ID: archivedID, Status: dbgen.SnapshotStatusArchived, CreatedAt: now.Add(-20 * time.Minute)},
				{ID: recentPendingID, Status: dbgen.SnapshotStatusPending, CreatedAt: now.Add(-5 * time.Minute)},
			},
			wantFailedIDs: nil,
			wantListCalls: 1,
		},
		{
			name:          "zero window skips sweep",
			pendingWindow: 0,
			snapshots:     []dbgen.Snapshot{{ID: stalePendingID, Status: dbgen.SnapshotStatusPending, CreatedAt: now.Add(-11 * time.Minute)}},
			wantFailedIDs: nil,
			wantListCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storeStub := &workerStoreStub{staleSnapshots: tt.snapshots}
			worker := NewWorker(storeStub, nil, nil, nil, zerolog.New(io.Discard), Preset("envelope"), tt.pendingWindow)

			if err := worker.SweepStalePending(context.Background()); err != nil {
				t.Fatalf("SweepStalePending() error = %v", err)
			}
			if storeStub.staleListCalls != tt.wantListCalls {
				t.Fatalf("ListStalePendingSnapshots() calls = %d, want %d", storeStub.staleListCalls, tt.wantListCalls)
			}
			if len(storeStub.failedIDs) != len(tt.wantFailedIDs) {
				t.Fatalf("MarkSnapshotFailed() calls = %d, want %d", len(storeStub.failedIDs), len(tt.wantFailedIDs))
			}
			for i, wantID := range tt.wantFailedIDs {
				if storeStub.failedIDs[i] != wantID {
					t.Fatalf("MarkSnapshotFailed() id[%d] = %s, want %s", i, storeStub.failedIDs[i], wantID)
				}
			}
			if tt.wantListCalls > 0 && storeStub.staleLimit != batchSize {
				t.Fatalf("ListStalePendingSnapshots() limit = %d, want %d", storeStub.staleLimit, batchSize)
			}
		})
	}
}

func TestWorkerSweepStalePendingNilStore(t *testing.T) {
	worker := NewWorker(nil, nil, nil, nil, zerolog.New(io.Discard), Preset("envelope"), 10*time.Minute)
	if err := worker.SweepStalePending(context.Background()); err != nil {
		t.Fatalf("SweepStalePending() error = %v", err)
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func thinActionPtr(value ThinAction) *ThinAction {
	return &value
}

package retention

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type stubStore struct {
	expired        []dbgen.Snapshot
	archived       []dbgen.Snapshot
	snapshots      []dbgen.Snapshot
	keysByID       map[uuid.UUID][]string
	failResults    map[uuid.UUID]error
	archivedIDs    []uuid.UUID
	failedIDs      []uuid.UUID
	purgedIDs      []uuid.UUID
	staleBefore    time.Time
	staleLimit     int32
	staleListCalls int
}

func (s *stubStore) ListExpiredSnapshots(context.Context, time.Time, int32) ([]dbgen.Snapshot, error) {
	return s.expired, nil
}

func (s *stubStore) ListArchivedSnapshotsForPurge(context.Context, time.Time, int32) ([]dbgen.Snapshot, error) {
	return s.archived, nil
}

func (s *stubStore) ListStalePendingSnapshots(_ context.Context, before time.Time, limit int32) ([]dbgen.Snapshot, error) {
	s.staleBefore = before
	s.staleLimit = limit
	s.staleListCalls++
	result := make([]dbgen.Snapshot, 0, len(s.snapshots))
	for _, snapshot := range s.snapshots {
		if snapshot.Status != dbgen.SnapshotStatusPending {
			continue
		}
		if snapshot.CreatedAt.Before(before) {
			result = append(result, snapshot)
		}
	}
	if len(result) > int(limit) {
		result = result[:limit]
	}
	return result, nil
}

func (s *stubStore) ListSnapshotArtifactObjectKeys(_ context.Context, snapshotID uuid.UUID) ([]string, error) {
	return append([]string(nil), s.keysByID[snapshotID]...), nil
}

func (s *stubStore) ArchiveSnapshot(_ context.Context, id uuid.UUID) error {
	s.archivedIDs = append(s.archivedIDs, id)
	return nil
}

func (s *stubStore) MarkSnapshotFailed(_ context.Context, id uuid.UUID) error {
	s.failedIDs = append(s.failedIDs, id)
	if s.failResults != nil {
		if err, ok := s.failResults[id]; ok {
			return err
		}
	}
	return nil
}

func (s *stubStore) PurgeSnapshot(_ context.Context, id uuid.UUID) error {
	s.purgedIDs = append(s.purgedIDs, id)
	return nil
}

type stubObjStore struct {
	deleted []string
	err     error
}

func (s *stubObjStore) Put(context.Context, string, io.Reader, string) error { return nil }
func (s *stubObjStore) Get(context.Context, string) (io.ReadCloser, error)   { return nil, nil }
func (s *stubObjStore) Exists(context.Context, string) (bool, error)         { return false, nil }
func (s *stubObjStore) Delete(_ context.Context, key string) error {
	s.deleted = append(s.deleted, key)
	return s.err
}

func TestWorkerArchivesExpiredSnapshots(t *testing.T) {
	store := &stubStore{expired: []dbgen.Snapshot{{ID: uuid.New(), Status: dbgen.SnapshotStatusComplete}}}
	worker := NewWorker(store, nil, zerolog.New(io.Discard), DefaultPolicy(), 10*time.Minute)

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(store.archivedIDs) != 1 {
		t.Fatalf("ArchiveSnapshot() calls = %d, want 1", len(store.archivedIDs))
	}
	if len(store.purgedIDs) != 0 {
		t.Fatalf("PurgeSnapshot() calls = %d, want 0", len(store.purgedIDs))
	}
}

func TestWorkerPurgesArchivedSnapshotsAndArtifacts(t *testing.T) {
	snapshotID := uuid.New()
	store := &stubStore{
		expired:  []dbgen.Snapshot{},
		archived: []dbgen.Snapshot{{ID: snapshotID, Status: dbgen.SnapshotStatusArchived}},
		keysByID: map[uuid.UUID][]string{snapshotID: {"snapshots/a/key-1", "snapshots/a/key-2"}},
	}
	objStore := &stubObjStore{}
	policy := DefaultPolicy()
	policy.AutoPurge = true
	worker := NewWorker(store, objStore, zerolog.New(io.Discard), policy, 10*time.Minute)

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(objStore.deleted) != 2 {
		t.Fatalf("Delete() calls = %d, want 2", len(objStore.deleted))
	}
	if len(store.purgedIDs) != 1 {
		t.Fatalf("PurgeSnapshot() calls = %d, want 1", len(store.purgedIDs))
	}
}

func TestWorkerIgnoresMissingArtifacts(t *testing.T) {
	snapshotID := uuid.New()
	store := &stubStore{
		archived: []dbgen.Snapshot{{ID: snapshotID, Status: dbgen.SnapshotStatusArchived}},
		keysByID: map[uuid.UUID][]string{snapshotID: {"missing.json"}},
	}
	objStore, err := objstore.NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	policy := DefaultPolicy()
	policy.AutoPurge = true
	worker := NewWorker(store, objStore, zerolog.New(io.Discard), policy, 10*time.Minute)

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(store.purgedIDs) != 1 {
		t.Fatalf("PurgeSnapshot() calls = %d, want 1", len(store.purgedIDs))
	}
}

func TestWorkerSkipsPurgeWithoutObjectStore(t *testing.T) {
	snapshotID := uuid.New()
	store := &stubStore{
		expired:  []dbgen.Snapshot{},
		archived: []dbgen.Snapshot{{ID: snapshotID, Status: dbgen.SnapshotStatusArchived}},
		keysByID: map[uuid.UUID][]string{snapshotID: {"snapshots/a/key-1"}},
	}
	policy := DefaultPolicy()
	policy.AutoPurge = true
	worker := NewWorker(store, nil, zerolog.New(io.Discard), policy, 10*time.Minute)

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(store.purgedIDs) != 0 {
		t.Fatalf("PurgeSnapshot() calls = %d, want 0", len(store.purgedIDs))
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
			name:          "fails only stale pending snapshots",
			pendingWindow: 10 * time.Minute,
			snapshots: []dbgen.Snapshot{
				{ID: stalePendingID, Status: dbgen.SnapshotStatusPending, CreatedAt: now.Add(-11 * time.Minute)},
			},
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
			name:          "guarded no-op does not fail sweep",
			pendingWindow: 10 * time.Minute,
			snapshots: []dbgen.Snapshot{
				{ID: stalePendingID, Status: dbgen.SnapshotStatusPending, CreatedAt: now.Add(-11 * time.Minute)},
				{ID: completeID, Status: dbgen.SnapshotStatusPending, CreatedAt: now.Add(-12 * time.Minute)},
			},
			wantFailedIDs: []uuid.UUID{stalePendingID, completeID},
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
			store := &stubStore{snapshots: tt.snapshots}
			if tt.name == "guarded no-op does not fail sweep" {
				store.failResults = map[uuid.UUID]error{completeID: nil}
			}
			worker := NewWorker(store, nil, zerolog.New(io.Discard), DefaultPolicy(), tt.pendingWindow)

			if err := worker.SweepStalePending(context.Background()); err != nil {
				t.Fatalf("SweepStalePending() error = %v", err)
			}
			if store.staleListCalls != tt.wantListCalls {
				t.Fatalf("ListStalePendingSnapshots() calls = %d, want %d", store.staleListCalls, tt.wantListCalls)
			}
			if len(store.failedIDs) != len(tt.wantFailedIDs) {
				t.Fatalf("MarkSnapshotFailed() calls = %d, want %d", len(store.failedIDs), len(tt.wantFailedIDs))
			}
			for i, wantID := range tt.wantFailedIDs {
				if store.failedIDs[i] != wantID {
					t.Fatalf("MarkSnapshotFailed() id[%d] = %s, want %s", i, store.failedIDs[i], wantID)
				}
			}
			if tt.wantListCalls > 0 && !store.staleBefore.Before(time.Now()) {
				t.Fatalf("expected stale cutoff before now, got %s", store.staleBefore)
			}
			if tt.wantListCalls > 0 && store.staleLimit != batchSize {
				t.Fatalf("ListStalePendingSnapshots() limit = %d, want %d", store.staleLimit, batchSize)
			}
		})
	}
}

func TestWorkerSweepStalePendingNilStore(t *testing.T) {
	worker := NewWorker(nil, nil, zerolog.New(io.Discard), DefaultPolicy(), 10*time.Minute)

	if err := worker.SweepStalePending(context.Background()); err != nil {
		t.Fatalf("SweepStalePending() error = %v", err)
	}
}

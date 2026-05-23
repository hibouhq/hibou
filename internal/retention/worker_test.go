package retention

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
	"github.com/rs/zerolog"
)

type stubStore struct {
	expired     []dbgen.Snapshot
	archived    []dbgen.Snapshot
	archivedIDs []uuid.UUID
	purgedIDs   []uuid.UUID
}

func (s *stubStore) ListExpiredSnapshots(context.Context, time.Time, int32) ([]dbgen.Snapshot, error) {
	return s.expired, nil
}

func (s *stubStore) ListArchivedSnapshotsForPurge(context.Context, time.Time, int32) ([]dbgen.Snapshot, error) {
	return s.archived, nil
}

func (s *stubStore) ArchiveSnapshot(_ context.Context, id uuid.UUID) error {
	s.archivedIDs = append(s.archivedIDs, id)
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
	worker := NewWorker(store, nil, zerolog.New(io.Discard), DefaultPolicy())

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
	store := &stubStore{
		expired:  []dbgen.Snapshot{},
		archived: []dbgen.Snapshot{{ID: uuid.New(), Status: dbgen.SnapshotStatusArchived, ArtifactKey: "acme/repo/snapshot/sbom.json"}},
	}
	objStore := &stubObjStore{}
	policy := DefaultPolicy()
	policy.AutoPurge = true
	worker := NewWorker(store, objStore, zerolog.New(io.Discard), policy)

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(objStore.deleted) != 1 {
		t.Fatalf("Delete() calls = %d, want 1", len(objStore.deleted))
	}
	if len(store.purgedIDs) != 1 {
		t.Fatalf("PurgeSnapshot() calls = %d, want 1", len(store.purgedIDs))
	}
}

func TestWorkerIgnoresMissingArtifacts(t *testing.T) {
	store := &stubStore{archived: []dbgen.Snapshot{{ID: uuid.New(), Status: dbgen.SnapshotStatusArchived, ArtifactKey: "missing.json"}}}
	objStore := &stubObjStore{err: errors.New("boom")}
	policy := DefaultPolicy()
	policy.AutoPurge = true
	worker := NewWorker(store, objStore, zerolog.New(io.Discard), policy)

	if err := worker.Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want error")
	}
}

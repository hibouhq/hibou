package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/store"
)

func TestManagedCleanupReconcilesAlreadyDeletedPrivateArtifact(t *testing.T) {
	s, org, _, _, inventory := newSCAFixture(t)
	ctx := t.Context()
	repo, err := s.queries.CreateRepository(ctx, org.ID, nil, "app", "app", org.Provider, inventory.ProviderKey, "main", "enrolled")
	if err != nil {
		t.Fatal(err)
	}
	s.objStore, err = objstore.NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.queries.CreateRemediationJob(ctx, store.RemediationJob{
		ID: uuid.New(), RepoID: repo.ID, BaseSHA: strings.Repeat("a", 40), SourceRef: "main",
		Request: json.RawMessage(`{}`), ExpiresAt: time.Now().Add(time.Hour),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := "remediation/" + job.ID.String() + "/already-deleted.json"
	if err := s.queries.RegisterRemediationArtifact(ctx, key, job.ID, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.cleanupManagedArtifacts(ctx); err != nil {
			t.Fatalf("idempotent cleanup stopped the controller: %v", err)
		}
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM remediation_artifact_expiry WHERE artifact_key=$1`, key).Scan(&count); err != nil || count != 0 {
		t.Fatalf("private artifact cleanup was not acknowledged: count=%d err=%v", count, err)
	}
}

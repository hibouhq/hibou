package store

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestManagedArtifactExpiryTracksOrphansBeforeUpload(t *testing.T) {
	db := openSecretScanTestDB(t)
	q := NewQueries(db)
	ctx := t.Context()
	key := "remediation/orphan/" + uuid.NewString()
	t.Cleanup(func() { _ = q.ClearRemediationArtifactExpiry(context.Background(), key) })
	// No job foreign key: a deleted repository must not erase the pending
	// cleanup of its private object, even if upload/finalization crashed.
	if err := q.RegisterRemediationArtifact(ctx, key, uuid.New(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := q.ScheduleRemediationArtifactCleanup(ctx, key); err != nil {
		t.Fatal(err)
	}
	keys, err := q.ListExpiredRemediationArtifacts(ctx)
	if err != nil || !slices.Contains(keys, key) {
		t.Fatalf("unfinalized object was not tracked for expiry: %v %v", keys, err)
	}
	if err := q.ClearRemediationArtifactExpiry(ctx, key); err != nil {
		t.Fatal(err)
	}
	keys, err = q.ListExpiredRemediationArtifacts(ctx)
	if err != nil || slices.Contains(keys, key) {
		t.Fatalf("completed cleanup was not cleared: %v %v", keys, err)
	}
}

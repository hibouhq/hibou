package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestOneActiveScanPerSnapshot(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	queries := NewQueries(db)
	repoID := createRepoForSecretScanTest(t, ctx, queries)
	ref, err := queries.CreateRef(ctx, repoID, "main", RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := queries.CreateSnapshot(ctx, ref.ID, "fixture", SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for range cap(results) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := queries.CreateScan(ctx, dbgen.CreateScanParams{
				SnapshotID: snapshot.ID, Status: "pending", ProvidersRequested: []string{"osv"}, TriggeredBy: "system",
			})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	created, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			created++
		case errors.Is(err, sql.ErrNoRows):
			conflicts++
		default:
			t.Fatalf("unexpected create error: %v", err)
		}
	}
	if created != 1 || conflicts != 7 {
		t.Fatalf("created=%d conflicts=%d, want 1 and 7", created, conflicts)
	}
	scans, err := queries.ListScansBySnapshot(ctx, snapshot.ID)
	if err != nil || len(scans) != 1 {
		t.Fatalf("scans=%+v err=%v", scans, err)
	}
	provider, err := queries.CreateScanProvider(ctx, dbgen.CreateScanProviderParams{ScanID: scans[0].ID, Provider: "osv", Status: "running"})
	if err != nil {
		t.Fatal(err)
	}
	if err := queries.CancelUnfinishedScan(ctx, scans[0].ID, "fixture cancellation"); err != nil {
		t.Fatal(err)
	}
	providers, err := dbgen.New(db).ListScanProvidersByScan(ctx, scans[0].ID)
	if err != nil || len(providers) != 1 || providers[0].ID != provider.ID || providers[0].Status != "cancelled" || !providers[0].CompletedAt.Valid {
		t.Fatalf("providers=%+v err=%v", providers, err)
	}
	next, err := queries.CreateScan(ctx, dbgen.CreateScanParams{SnapshotID: snapshot.ID, Status: "running", ProvidersRequested: []string{"osv"}, TriggeredBy: "system"})
	if err != nil {
		t.Fatalf("terminal scan blocked next scan: %v", err)
	}
	if err := queries.FailUnfinishedScan(ctx, next.ID, "fixture failure"); err != nil {
		t.Fatal(err)
	}
	if err := queries.CancelUnfinishedScan(ctx, next.ID, "must not overwrite terminal status"); err != nil {
		t.Fatal(err)
	}
	stored, err := dbgen.New(db).GetScanByID(ctx, next.ID)
	if err != nil || stored.Status != "failed" || stored.ErrorMessage != "fixture failure" {
		t.Fatalf("terminal status overwritten: %+v err=%v", stored, err)
	}
}

func TestOneActiveScanMigration(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			t.Errorf("rollback migration transaction: %v", err)
		}
	}()
	if _, err := tx.ExecContext(ctx, `
		CREATE TEMP TABLE scans (
			id uuid PRIMARY KEY, snapshot_id uuid, status text,
			error_message text DEFAULT '', started_at timestamptz,
			completed_at timestamptz, created_at timestamptz
		) ON COMMIT DROP;
		CREATE TEMP TABLE scan_providers (
			scan_id uuid, status text, error_message text DEFAULT '', completed_at timestamptz
		) ON COMMIT DROP;
	`); err != nil {
		t.Fatal(err)
	}
	snapshotID, oldID, otherOldID, freshID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{oldID, otherOldID} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO scans VALUES ($1,$2,'running','',NULL,NULL,now()-interval '2 hours')`, id, snapshotID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO scan_providers (scan_id,status) VALUES ($1,'running')`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO scans VALUES ($1,$2,'pending','',NULL,NULL,now())`, freshID, snapshotID); err != nil {
		t.Fatal(err)
	}
	duplicateID := uuid.New()
	if _, err := tx.ExecContext(ctx, `INSERT INTO scans VALUES ($1,$2,'running','',now(),NULL,now())`, duplicateID, snapshotID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT recent_duplicates`); err != nil {
		t.Fatal(err)
	}
	up, err := migrationsFS.ReadFile("migrations/00083_one_active_scan_per_snapshot.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, string(up)); err == nil {
		t.Fatal("migration silently accepted recent duplicate active scans")
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT recent_duplicates`); err != nil {
		t.Fatal(err)
	}
	var recentActive int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scans WHERE id IN ($1,$2) AND status IN ('pending','running')`, freshID, duplicateID).Scan(&recentActive); err != nil {
		t.Fatal(err)
	}
	if recentActive != 2 {
		t.Fatal("migration cancelled recent duplicate writers")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scans WHERE id=$1`, duplicateID); err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"up", "down", "up"} {
		script, err := migrationsFS.ReadFile("migrations/00083_one_active_scan_per_snapshot." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(script)); err != nil {
			t.Fatalf("%s migration: %v", direction, err)
		}
	}
	var cancelled, active, providers int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scans WHERE status='cancelled' AND completed_at IS NOT NULL`).Scan(&cancelled); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scans WHERE status='pending' AND id=$1`, freshID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scan_providers WHERE status='cancelled' AND completed_at IS NOT NULL`).Scan(&providers); err != nil {
		t.Fatal(err)
	}
	if cancelled != 2 || active != 1 || providers != 2 {
		t.Fatalf("cancelled=%d active=%d providers=%d, want 2, 1, 2", cancelled, active, providers)
	}
}

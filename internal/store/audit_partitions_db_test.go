package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

func newAuditPartitionTestDB(t *testing.T) (*Queries, *sql.DB) {
	t.Helper()

	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://hibou:hibou@localhost:5432/hibou_test?sslmode=disable"
	}
	db, err := New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(db); err != nil {
		t.Skipf("database not available: %v", err)
	}
	return NewQueries(db), db
}

func auditPartitionExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()

	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM pg_inherits i
			JOIN pg_class c ON c.oid = i.inhrelid
			JOIN pg_class p ON p.oid = i.inhparent
			WHERE p.relname = 'audit_logs' AND c.relname = $1
		)`, name).Scan(&exists)
	if err != nil {
		t.Fatalf("check partition %s: %v", name, err)
	}
	return exists
}

func TestMaintainAuditLogPartitionsLive(t *testing.T) {
	queries, db := newAuditPartitionTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := queries.MaintainAuditLogPartitions(ctx, now, 0); err != nil {
		t.Fatalf("MaintainAuditLogPartitions: %v", err)
	}
	for _, month := range []time.Time{monthStartUTC(now), monthStartUTC(now).AddDate(0, 1, 0)} {
		if !auditPartitionExists(t, db, auditPartitionName(month)) {
			t.Fatalf("partition %s missing after maintenance", auditPartitionName(month))
		}
	}
	if !auditPartitionExists(t, db, "audit_logs_default") {
		t.Fatal("default partition missing")
	}

	// A replica that slept across a month boundary: rows for an unpartitioned
	// old month land in default; maintenance for that month must move them.
	oldMonth := monthStartUTC(now).AddDate(0, -13, 0)
	oldName := auditPartitionName(oldMonth)
	if auditPartitionExists(t, db, oldName) {
		if _, err := db.Exec(`DROP TABLE ` + oldName); err != nil {
			t.Fatalf("drop leftover partition: %v", err)
		}
	}
	if _, err := db.Exec(`
		INSERT INTO audit_logs (actor_type, actor_display, action, resource_type, resource_id, created_at)
		VALUES ('system', 'partition-test', 'test.event', 'test', 'stray', $1)`,
		oldMonth.Add(24*time.Hour),
	); err != nil {
		t.Fatalf("insert stray row: %v", err)
	}

	if err := queries.ensureAuditPartition(ctx, oldMonth); err != nil {
		t.Fatalf("ensureAuditPartition with strays in default: %v", err)
	}
	if !auditPartitionExists(t, db, oldName) {
		t.Fatalf("partition %s not created around default rows", oldName)
	}
	var moved int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + oldName + ` WHERE resource_id = 'stray'`).Scan(&moved); err != nil {
		t.Fatalf("count moved rows: %v", err)
	}
	if moved != 1 {
		t.Fatalf("stray rows moved = %d, want 1", moved)
	}

	// Retention: with a 12-month window the 13-month-old partition is dropped.
	if err := queries.MaintainAuditLogPartitions(ctx, now, 12); err != nil {
		t.Fatalf("MaintainAuditLogPartitions with retention: %v", err)
	}
	if auditPartitionExists(t, db, oldName) {
		t.Fatalf("partition %s should have been dropped by the 12-month window", oldName)
	}
	if !auditPartitionExists(t, db, auditPartitionName(monthStartUTC(now))) {
		t.Fatal("current month must survive retention")
	}
}

func TestLegacyUnscopedKeySemanticsLive(t *testing.T) {
	queries, db := newAuditPartitionTestDB(t)
	ctx := context.Background()

	// Migration 00011 made "legacy unscoped" real: the pre-ADR-020 array
	// sentinels ('[]', '["all"]') were normalized to the jsonb null document,
	// which the application reads as unscoped. Before it, those rows parsed as
	// scoped-but-malformed and DENIED EVERYTHING — an upgrade would have
	// bricked every existing token.
	var userID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO users (email, display_name, provider, provider_id)
		VALUES ('legacy-key@example.com', 'Legacy', 'github', 'legacy-key-test-' || gen_random_uuid())
		RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id = $1`, userID) })

	// Rely on the column DEFAULT ('null'::jsonb since 00011) — exactly what a
	// pre-scope INSERT produced with the old '[]' default.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO api_keys (user_id, name, key_hash)
		VALUES ($1, 'legacy', 'hash-legacy-semantics-test')`, userID); err != nil {
		t.Fatalf("insert default-scope key: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM api_keys WHERE key_hash = 'hash-legacy-semantics-test'`) })

	key, err := queries.GetAPIKeyByHash(ctx, "hash-legacy-semantics-test")
	if err != nil || key == nil {
		t.Fatalf("GetAPIKeyByHash: %v (key=%v)", err, key)
	}
	if key.HasScope() {
		t.Fatal("NULL scope must read as legacy-unscoped, not as a scoped document")
	}
	if scope, err := key.Scope(); err != nil || scope.HasPermissions() {
		t.Fatalf("legacy key scope = %+v err=%v, want zero scope and nil error", scope, err)
	}
}

func TestAuditLogWriteWithAPIKeyActorLive(t *testing.T) {
	queries, db := newAuditPartitionTestDB(t)
	ctx := context.Background()

	// The regression that motivated migration 00010: actor_id carried an FK to
	// users(id), so writing an API-key id violated it and the audit row was
	// silently dropped. This must never come back.
	var keyID string
	if err := db.QueryRow(`SELECT gen_random_uuid()`).Scan(&keyID); err != nil {
		t.Fatalf("generate key id: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO audit_logs (actor_id, actor_type, actor_display, action, resource_type, resource_id)
		VALUES ($1, 'api_key', 'token: regression-test', 'test.token_action', 'test', 'fk-regression')`,
		keyID,
	); err != nil {
		t.Fatalf("audit write with an API-key actor_id failed — the users(id) FK is back: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM audit_logs WHERE resource_id = 'fk-regression'`); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	_ = queries
}

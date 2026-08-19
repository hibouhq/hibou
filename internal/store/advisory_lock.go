package store

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
)

// Advisory-lock keys for singleton background loops. Each value must stay
// stable across releases — changing one lets two replicas run the same loop.
//
// #nosec G101 -- these are advisory-lock names, not credentials.
const (
	LockAdvisoryScanPass = "hibou:advisory-scan-pass"
	LockRetentionPass    = "hibou:retention-pass"
)

// WithLeaderLock runs fn only if this connection wins a Postgres session-level
// advisory lock, and reports whether it ran.
//
// This is leader election for loops that are *idempotent but wasteful* to run
// concurrently: N replicas each doing a full advisory-provider pass burns N×
// the API quota for the same result. It is deliberately not a correctness
// control — durable work claiming (FOR UPDATE SKIP LOCKED + leases) is what
// guarantees exactly-once processing.
//
// pg_try_advisory_lock never blocks: a replica that loses simply skips this
// tick and tries again on the next one. The lock is held on one dedicated
// connection and released in every path, including panic, so a crashed process
// drops it when its backend dies.
func WithLeaderLock(ctx context.Context, db *sql.DB, key string, fn func(context.Context) error) (bool, error) {
	if db == nil {
		// No database: run unguarded rather than silently skipping the work.
		return true, fn(ctx)
	}

	// A dedicated connection is required: session-level advisory locks belong to
	// a backend, and pooled queries could otherwise unlock from a different one.
	conn, err := db.Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("acquire connection for %s lock: %w", key, err)
	}
	defer func() { _ = conn.Close() }()

	lockID := advisoryLockID(key)
	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, lockID).Scan(&acquired); err != nil {
		return false, fmt.Errorf("try advisory lock %s: %w", key, err)
	}
	if !acquired {
		return false, nil
	}
	defer func() {
		// context.WithoutCancel: the unlock must still run when the caller's
		// context was cancelled mid-pass, otherwise the lock lingers until the
		// connection is reaped.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockID)
	}()

	return true, fn(ctx)
}

// advisoryLockID hashes a human-readable key into the bigint the advisory lock
// API takes. FNV-1a is enough: the key space is a handful of constants, and a
// collision between two of them would be visible immediately in testing.
func advisoryLockID(key string) int64 {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(key))
	return int64(hash.Sum64()) // #nosec G115 -- intentional wrap; only bit-identity matters
}

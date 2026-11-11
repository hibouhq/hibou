package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"hash/fnv"
	"time"
)

const AdvisoryLockCleanupTimeout = 5 * time.Second

// Advisory-lock keys for singleton background loops. Each value must stay
// stable across releases — changing one lets two replicas run the same loop.
//
// #nosec G101 -- these are advisory-lock names, not credentials.
const (
	LockAdvisoryScanPass = "hibou:advisory-scan-pass"
	LockRetentionPass    = "hibou:retention-pass"
	LockCVEFeedSweep     = "hibou:cve-feed-sweep"
	LockKEVSync          = "hibou:kev-sync"
	LockRatingsPass      = "hibou:ratings-pass"
	LockEPSSSync         = "hibou:epss-sync"
	LockPackageSignals   = "hibou:package-signals-sync"
	// LockDepExtractionUpgrade serialises the extractor-upgrade pass
	// (ADR-045 §4.3.1).
	LockDepExtractionUpgrade = "hibou:dep-extraction-upgrade"
	LockStorageUsage         = "hibou:storage-usage"
	LockDeviceAuthCleanup    = "hibou:device-auth-cleanup"
	// LockForgeConfinement runs the forge confinement check (ADR-052) on one
	// replica: it reads several rules per repository from the forge API.
	LockForgeConfinement = "hibou:forge-confinement"
	// LockIncidentSweep and LockIncidentClock run the incident rule sweep and
	// the deadline clock (ADR-053) on one replica.
	LockIncidentSweep = "hibou:incident-sweep"
	LockIncidentClock = "hibou:incident-clock"
)

// AdvisoryLockID exposes the key hashing for transaction-scoped locks taken
// with pg_advisory_xact_lock.
func AdvisoryLockID(key string) int64 {
	return advisoryLockID(key)
}

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
// drops it when its backend dies. TCP keepalives configured by New also bound
// dead-client detection when a pod disappears without closing its sockets.
func WithLeaderLock(ctx context.Context, db *sql.DB, key string, fn func(context.Context) error) (ran bool, err error) {
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
		// Cancellation may race successful acquisition on the server.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		return false, fmt.Errorf("try advisory lock %s: %w", key, err)
	}
	if !acquired {
		return false, nil
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), AdvisoryLockCleanupTimeout)
		defer cancel()
		var released bool
		unlockErr := conn.QueryRowContext(cleanup, `SELECT pg_advisory_unlock($1)`, lockID).Scan(&released)
		if unlockErr == nil && !released {
			unlockErr = errors.New("connection no longer owns advisory lock")
		}
		if unlockErr != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			err = errors.Join(err, fmt.Errorf("release advisory lock %s: %w", key, unlockErr))
		}
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

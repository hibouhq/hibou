package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestWithLeaderLockDiscardsUncertainSessions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		acquireErr  bool
		unlockError bool
		unlockFalse bool
	}{
		{name: "acquisition response lost", acquireErr: true},
		{name: "unlock fails", unlockError: true},
		{name: "ownership lost", unlockFalse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			key := "hibou:test:" + t.Name()
			failure := errors.New("connection response lost")
			acquire := mock.ExpectQuery("SELECT pg_try_advisory_lock($1)").WithArgs(advisoryLockID(key))
			if tc.acquireErr {
				acquire.WillReturnError(failure)
			} else {
				acquire.WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
				unlock := mock.ExpectQuery("SELECT pg_advisory_unlock($1)").WithArgs(advisoryLockID(key))
				if tc.unlockError {
					unlock.WillReturnError(failure)
				} else {
					unlock.WillReturnRows(sqlmock.NewRows([]string{"released"}).AddRow(false))
				}
			}
			mock.ExpectClose()
			workError := errors.New("work failed")
			ran, err := WithLeaderLock(context.Background(), db, key, func(context.Context) error { return workError })
			if ran == tc.acquireErr || err == nil {
				t.Fatalf("ran=%v err=%v", ran, err)
			}
			if !tc.acquireErr && !errors.Is(err, workError) {
				t.Fatalf("cleanup hid the work failure: %v", err)
			}
			if !tc.unlockFalse && !errors.Is(err, failure) {
				t.Fatalf("lock error was not surfaced: %v", err)
			}
			if db.Stats().OpenConnections != 0 {
				t.Fatal("uncertain lock connection was returned to the pool")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWithLeaderLockBoundsCleanupEvenWithoutParentDeadline(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	key := "hibou:test:" + t.Name()
	mock.ExpectQuery("SELECT pg_try_advisory_lock($1)").WithArgs(advisoryLockID(key)).
		WillReturnRows(sqlmock.NewRows([]string{"locked"}).AddRow(true))
	mock.ExpectQuery("SELECT pg_advisory_unlock($1)").WithArgs(advisoryLockID(key)).
		WillDelayFor(AdvisoryLockCleanupTimeout + 5*time.Second).
		WillReturnRows(sqlmock.NewRows([]string{"released"}).AddRow(true))
	mock.ExpectClose()
	started := time.Now()
	ran, err := WithLeaderLock(context.Background(), db, key, func(context.Context) error { return nil })
	if !ran || err == nil || time.Since(started) > AdvisoryLockCleanupTimeout+2*time.Second {
		t.Fatalf("cleanup was not bounded: ran=%v err=%v elapsed=%s", ran, err, time.Since(started))
	}
	if db.Stats().OpenConnections != 0 {
		t.Fatal("timed-out unlock returned its connection to the pool")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func openLockTestDB(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	db, err := New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// Leader election: exactly one holder at a time, and the loser skips rather
// than blocking — a blocked replica would stall its whole loop.
func TestWithLeaderLockExcludesConcurrentHolders(t *testing.T) {
	db := openLockTestDB(t)
	ctx := context.Background()
	key := "hibou:test:" + t.Name()

	inside := make(chan struct{})
	release := make(chan struct{})
	loserRan := true
	var loserAcquired bool

	go func() {
		_, _ = WithLeaderLock(ctx, db, key, func(context.Context) error {
			close(inside)
			<-release
			return nil
		})
	}()

	<-inside
	acquired, err := WithLeaderLock(ctx, db, key, func(context.Context) error {
		loserRan = true
		return nil
	})
	loserAcquired = acquired
	close(release)

	if err != nil {
		t.Fatalf("WithLeaderLock(loser) error = %v", err)
	}
	if loserAcquired {
		t.Fatal("two holders acquired the same lock")
	}
	_ = loserRan
}

// The lock must be released on every path, or one crashed pass wedges the loop
// until the connection is reaped.
func TestWithLeaderLockReleasesAfterErrorAndSuccess(t *testing.T) {
	db := openLockTestDB(t)
	ctx := context.Background()
	key := "hibou:test:" + t.Name()

	boom := errors.New("pass failed")
	if ran, err := WithLeaderLock(ctx, db, key, func(context.Context) error { return boom }); !ran || !errors.Is(err, boom) {
		t.Fatalf("ran=%v err=%v, want ran with the work error surfaced", ran, err)
	}
	// Immediately re-acquirable: proves the failed pass released it.
	if ran, err := WithLeaderLock(ctx, db, key, func(context.Context) error { return nil }); !ran || err != nil {
		t.Fatalf("re-acquire after error: ran=%v err=%v", ran, err)
	}
	if ran, err := WithLeaderLock(ctx, db, key, func(context.Context) error { return nil }); !ran || err != nil {
		t.Fatalf("re-acquire after success: ran=%v err=%v", ran, err)
	}
}

// A cancelled context must still unlock, so the next tick is not locked out.
func TestWithLeaderLockUnlocksAfterContextCancellation(t *testing.T) {
	db := openLockTestDB(t)
	key := "hibou:test:" + t.Name()

	ctx, cancel := context.WithCancel(context.Background())
	ran, err := WithLeaderLock(ctx, db, key, func(context.Context) error {
		cancel()
		return context.Canceled
	})
	if !ran || !errors.Is(err, context.Canceled) {
		t.Fatalf("ran=%v err=%v", ran, err)
	}

	done := make(chan bool, 1)
	go func() {
		acquired, _ := WithLeaderLock(context.Background(), db, key, func(context.Context) error { return nil })
		done <- acquired
	}()
	select {
	case acquired := <-done:
		if !acquired {
			t.Fatal("lock still held after the cancelled pass returned")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting to re-acquire; the unlock did not run")
	}
}

// Nil database must run the work rather than silently skipping it.
func TestWithLeaderLockRunsUnguardedWithoutDatabase(t *testing.T) {
	called := false
	ran, err := WithLeaderLock(context.Background(), nil, "k", func(context.Context) error {
		called = true
		return nil
	})
	if !ran || err != nil || !called {
		t.Fatalf("ran=%v err=%v called=%v", ran, err, called)
	}
}

// Golden ids. Stability is the property that matters: if a key or the hash
// changes, a rolling deploy would have old and new replicas holding *different*
// locks for the same loop and both would run it. Pinning the values makes that
// change fail here instead of in production.
func TestAdvisoryLockIDIsStableAndDistinct(t *testing.T) {
	golden := map[string]int64{
		LockAdvisoryScanPass: 7886587607923438617,
		LockRetentionPass:    -396466317764580706,
	}
	for key, want := range golden {
		if got := advisoryLockID(key); got != want {
			t.Fatalf("advisoryLockID(%q) = %d, want %d — changing this splits the lock across a rolling deploy", key, got, want)
		}
	}
	if golden[LockAdvisoryScanPass] == golden[LockRetentionPass] {
		t.Fatal("distinct loops collide on one lock id")
	}
}

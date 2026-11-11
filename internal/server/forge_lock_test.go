package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/config"
)

func TestForgeDeliveryLockDiscardsUncertainAcquisitionAndUnlock(t *testing.T) {
	for _, acquireFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "unlock ownership lost", true: "acquisition response lost"}[acquireFails], func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			s := &Server{db: db, cfg: config.Config{Forges: []config.ForgeConfig{{ID: "test", EventMode: "poll"}}}, log: zerolog.Nop()}
			acquire := mock.ExpectExec("SELECT pg_advisory_lock(hashtextextended($1,0))").WithArgs("forge-delivery:test")
			if acquireFails {
				acquire.WillReturnError(errors.New("response lost"))
			} else {
				acquire.WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectQuery("SELECT pg_advisory_unlock(hashtextextended($1,0))").WithArgs("forge-delivery:test").
					WillReturnRows(sqlmock.NewRows([]string{"released"}).AddRow(false))
			}
			mock.ExpectClose()
			release, err := s.lockForgeDelivery(context.Background(), "test", false)
			if acquireFails {
				if err == nil {
					t.Fatal("ambiguous acquisition succeeded")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				release()
			}
			if db.Stats().OpenConnections != 0 {
				t.Fatal("uncertain provider lock returned to the pool")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestForgeDeliveryLockWaitIsBounded(t *testing.T) {
	s, repo, _ := newReconciliationFixture(t)
	release, err := s.lockForgeDelivery(context.Background(), repo.Provider, true)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	started := time.Now()
	second, err := s.lockForgeDelivery(context.Background(), repo.Provider, false)
	if err == nil {
		second()
		t.Fatal("contending delivery acquired the provider lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > forgeDeliveryLockTimeout+2*time.Second {
		t.Fatalf("provider lock wait was not bounded: %v elapsed=%s", err, time.Since(started))
	}
}

func TestForgeDeliveryLockReleasesAfterCallerCancellation(t *testing.T) {
	s, repo, _ := newReconciliationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	release, err := s.lockForgeDelivery(ctx, repo.Provider, true)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	release()
	next, err := s.lockForgeDelivery(context.Background(), repo.Provider, true)
	if err != nil {
		t.Fatalf("cancelled caller left the provider locked: %v", err)
	}
	next()
}

func TestForgePollingDefersBusyProviderWithoutWaiting(t *testing.T) {
	s, repo, _ := newReconciliationFixture(t)
	ctx := context.Background()
	release, err := s.lockForgeDelivery(ctx, repo.Provider, true)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := s.queries.EnsureForgeReconciliation(ctx, repo.Provider, "busy", "refs", uuid.NullUUID{UUID: repo.ID, Valid: true}); err != nil {
		t.Fatal(err)
	}
	job, err := s.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now())
	if err != nil || job == nil {
		t.Fatalf("claim=%+v err=%v", job, err)
	}
	started := time.Now()
	s.processForgeReconciliation(ctx, job)
	if time.Since(started) > 2*time.Second {
		t.Fatal("polling waited on a busy provider lock")
	}
	jobs, err := s.queries.ListForgeReconciliation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range jobs {
		if row.ID == job.ID {
			if row.LastError == "" || !row.NextDueAt.After(time.Now()) {
				t.Fatalf("busy poll was not recorded and deferred: %+v", row)
			}
			return
		}
	}
	t.Fatal("reconciliation job disappeared")
}

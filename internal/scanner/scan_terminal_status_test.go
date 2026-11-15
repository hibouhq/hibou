package scanner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/provider"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestScanTerminalStatus(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status string
		prefix string
	}{
		{context.Canceled, "cancelled", "cancelled: caller went away"},
		{fmt.Errorf("query: %w", context.Canceled), "cancelled", "cancelled: caller went away"},
		{context.DeadlineExceeded, "cancelled", "cancelled: deadline exceeded"},
		{errors.New("provider failed"), "failed", "provider failed"},
	} {
		status, reason := scanTerminalStatus(tc.err)
		if status != tc.status || !strings.HasPrefix(reason, tc.prefix) {
			t.Errorf("scanTerminalStatus(%v) = %q, %q", tc.err, status, reason)
		}
	}
}

func TestTerminalWriteContextSurvivesCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, done := terminalWriteContext(parent)
	defer done()
	deadline, ok := ctx.Deadline()
	if ctx.Err() != nil || !ok || time.Until(deadline) > 10*time.Second {
		t.Fatalf("terminal write context: err=%v deadline=%v", ctx.Err(), deadline)
	}
}

type lifecycleStore struct {
	*mockScannerStore
	createErr     error
	componentsErr error
	auditErr      error
	startErr      error
}

func (m *lifecycleStore) CreateScan(ctx context.Context, arg dbgen.CreateScanParams) (dbgen.Scan, error) {
	if m.createErr != nil {
		return dbgen.Scan{}, m.createErr
	}
	return m.mockScannerStore.CreateScan(ctx, arg)
}

func (m *lifecycleStore) ListComponentsBySnapshot(ctx context.Context, id uuid.UUID) ([]dbgen.Component, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.componentsErr != nil {
		return nil, m.componentsErr
	}
	return m.mockScannerStore.ListComponentsBySnapshot(ctx, id)
}

func (m *lifecycleStore) UpdateScanStatus(ctx context.Context, arg dbgen.UpdateScanStatusParams) (dbgen.Scan, error) {
	if err := ctx.Err(); err != nil {
		return dbgen.Scan{}, err
	}
	if arg.Status == "running" && m.startErr != nil {
		return dbgen.Scan{}, m.startErr
	}
	return m.mockScannerStore.UpdateScanStatus(ctx, arg)
}

func (m *lifecycleStore) UpdateScanProvider(ctx context.Context, arg dbgen.UpdateScanProviderParams) (dbgen.ScanProvider, error) {
	if err := ctx.Err(); err != nil {
		return dbgen.ScanProvider{}, err
	}
	return m.mockScannerStore.UpdateScanProvider(ctx, arg)
}

func (m *lifecycleStore) CreateAuditLog(ctx context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error) {
	if m.auditErr != nil {
		return dbgen.AuditLog{}, m.auditErr
	}
	return m.mockScannerStore.CreateAuditLog(ctx, arg)
}

func TestQueueRescanConflictAndAuditFailure(t *testing.T) {
	for _, err := range []error{sql.ErrNoRows, errors.New("database unavailable")} {
		mock := &lifecycleStore{mockScannerStore: newMockScannerStore(), createErr: err}
		service := New(mock, newMockCache(), newMockIngester(), &mockBus{}, nil, zerolog.Nop())
		_, got := service.QueueRescan(context.Background(), uuid.New(), []string{"osv"}, audit.Entry{})
		want := err
		if errors.Is(err, sql.ErrNoRows) {
			want = ErrScanInProgress
		}
		if !errors.Is(got, want) || len(mock.auditLogs) != 0 {
			t.Fatalf("queue error=%v, want %v; audit logs=%d", got, want, len(mock.auditLogs))
		}
	}
	mock := &lifecycleStore{mockScannerStore: newMockScannerStore(), auditErr: errors.New("audit unavailable")}
	service := New(mock, newMockCache(), newMockIngester(), &mockBus{}, nil, zerolog.Nop())
	queued, err := service.QueueRescan(context.Background(), uuid.New(), []string{"osv"}, audit.Entry{})
	if err == nil || queued.ID == uuid.Nil || len(mock.scanStatuses) != 1 || mock.scanStatuses[0].Status != "failed" {
		t.Fatalf("audit failure left pending scan: queued=%+v err=%v statuses=%+v", queued, err, mock.scanStatuses)
	}
}

func TestRunRescanEarlyFailureClosesQueuedScan(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, errors.New("component query failed")} {
		t.Run(cause.Error(), func(t *testing.T) {
			mock := &lifecycleStore{mockScannerStore: newMockScannerStore(), componentsErr: cause}
			cache := newMockCache()
			service := New(mock, cache, newMockIngester(), &mockBus{}, nil, zerolog.Nop())
			ctx := context.Background()
			queued, err := service.QueueRescan(ctx, uuid.New(), []string{"osv"}, audit.Entry{})
			if err != nil {
				t.Fatal(err)
			}
			if errors.Is(cause, context.Canceled) {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			id, err := service.RunRescan(ctx, queued, audit.Entry{})
			want, _ := scanTerminalStatus(cause)
			if id != queued.ID || !errors.Is(err, cause) || len(mock.scanStatuses) != 1 || mock.scanStatuses[0].Status != want {
				t.Fatalf("id=%v err=%v statuses=%+v, want %s", id, err, mock.scanStatuses, want)
			}
			if len(cache.invalidated) != 0 || len(mock.markStaleCalls) != 0 || len(mock.auditLogs) != 1 {
				t.Fatal("queueing or early failure performed matching or duplicated the audit entry")
			}
		})
	}
}

func TestRunScanStartFailureClosesPersistedScan(t *testing.T) {
	mock := &lifecycleStore{mockScannerStore: newMockScannerStore(), startErr: context.Canceled}
	service := New(mock, newMockCache(), newMockIngester(), &mockBus{}, nil, zerolog.Nop())
	id, err := service.RunScan(context.Background(), uuid.New(), []string{"osv"}, "system")
	if id == uuid.Nil || !errors.Is(err, context.Canceled) || len(mock.scanStatuses) != 1 || mock.scanStatuses[0].Status != "cancelled" {
		t.Fatalf("id=%v err=%v statuses=%+v", id, err, mock.scanStatuses)
	}
}

type cancellingCache struct {
	*mockCache
	cancel context.CancelFunc
}

func (m *cancellingCache) QueryWithCache(context.Context, provider.AdvisoryProvider, []provider.PackageQuery) ([]provider.AdvisoryResult, error) {
	m.cancel()
	return nil, context.Canceled
}

func TestCancelledProviderAndScanAreFinalizedWithoutStaleMarking(t *testing.T) {
	mock := &lifecycleStore{mockScannerStore: newMockScannerStore()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache := &cancellingCache{mockCache: newMockCache(), cancel: cancel}
	service := New(mock, cache, newMockIngester(), &mockBus{}, map[string]provider.AdvisoryProvider{"osv": mockProvider{name: "osv"}}, zerolog.Nop())
	_, err := service.RunScan(ctx, uuid.New(), []string{"osv"}, "system")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("scan error=%v", err)
	}
	last := mock.scanStatuses[len(mock.scanStatuses)-1]
	if last.Status != "cancelled" || !last.CompletedAt.Valid || mock.providerStatuses["osv"].Status != "cancelled" || len(mock.markStaleCalls) != 0 {
		t.Fatalf("scan=%+v provider=%+v stale calls=%d", last, mock.providerStatuses["osv"], len(mock.markStaleCalls))
	}
}

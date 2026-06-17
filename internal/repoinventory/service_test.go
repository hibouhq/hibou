package repoinventory

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestSeedInstallationReconcilesRemovedRepositories(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", InstallationID: int64Ptr(10), AccountLogin: "acme", Owner: "acme", Name: "old", FullName: "acme/old"}); err != nil {
		t.Fatalf("seed old repo: %v", err)
	}

	err := service.SeedInstallation(ctx, "github", forge.Installation{ID: 10, AccountName: "acme"}, []forge.Repository{{Owner: "acme", Name: "api", FullName: "acme/api"}})
	if err != nil {
		t.Fatalf("SeedInstallation() error = %v", err)
	}

	if repo := fakeStore.byKey("github", "acme/api"); repo == nil || repo.RemovedAt != nil {
		t.Fatalf("expected acme/api active after seed, got %#v", repo)
	}
	if repo := fakeStore.byKey("github", "acme/old"); repo == nil || repo.RemovedAt == nil {
		t.Fatalf("expected acme/old removed after reconcile, got %#v", repo)
	}
}

func TestSeedInstallationIdenticalSetEmitsNoDetectOrDeleteAudits(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()
	inst := forge.Installation{ID: 10, AccountName: "acme"}

	for _, repo := range []store.ForgeRepository{
		{Provider: "github", InstallationID: int64Ptr(10), AccountLogin: "acme", Owner: "acme", Name: "api", FullName: "acme/api"},
		{Provider: "github", InstallationID: int64Ptr(10), AccountLogin: "acme", Owner: "acme", Name: "web", FullName: "acme/web"},
	} {
		if _, err := fakeStore.UpsertForgeRepository(ctx, repo); err != nil {
			t.Fatalf("seed repo %s: %v", repo.FullName, err)
		}
	}
	fakeStore.resetAuditLogs()

	err := service.SeedInstallation(ctx, "github", inst, []forge.Repository{{Owner: "acme", Name: "api", FullName: "acme/api"}, {Owner: "acme", Name: "web", FullName: "acme/web"}})
	if err != nil {
		t.Fatalf("SeedInstallation() error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions())
}

func TestSeedInstallationAddedRepoEmitsSingleDetectedAudit(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()
	inst := forge.Installation{ID: 10, AccountName: "acme"}

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", InstallationID: int64Ptr(10), AccountLogin: "acme", Owner: "acme", Name: "api", FullName: "acme/api"}); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	fakeStore.resetAuditLogs()

	err := service.SeedInstallation(ctx, "github", inst, []forge.Repository{{Owner: "acme", Name: "api", FullName: "acme/api"}, {Owner: "acme", Name: "web", FullName: "acme/web"}})
	if err != nil {
		t.Fatalf("SeedInstallation() error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions(), audit.ActionRepoDetected)
}

func TestSeedInstallationRemovedRepoEmitsSingleDeletedAudit(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()
	inst := forge.Installation{ID: 10, AccountName: "acme"}

	for _, repo := range []store.ForgeRepository{
		{Provider: "github", InstallationID: int64Ptr(10), AccountLogin: "acme", Owner: "acme", Name: "api", FullName: "acme/api"},
		{Provider: "github", InstallationID: int64Ptr(10), AccountLogin: "acme", Owner: "acme", Name: "web", FullName: "acme/web"},
	} {
		if _, err := fakeStore.UpsertForgeRepository(ctx, repo); err != nil {
			t.Fatalf("seed repo %s: %v", repo.FullName, err)
		}
	}
	fakeStore.resetAuditLogs()

	err := service.SeedInstallation(ctx, "github", inst, []forge.Repository{{Owner: "acme", Name: "api", FullName: "acme/api"}})
	if err != nil {
		t.Fatalf("SeedInstallation() error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions(), audit.ActionRepoDeleted)
	assertAuditReason(t, fakeStore.auditLogs[0], "reconcile_removed")
}

func TestSeedInstallationSnapshotErrorSkipsDiffAuditButWritesContinue(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	fakeStore.listForgeRepositoriesByAccountErr = errors.New("snapshot failed")
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	err := service.SeedInstallation(ctx, "github", forge.Installation{ID: 10, AccountName: "acme"}, []forge.Repository{{Owner: "acme", Name: "api", FullName: "acme/api"}})
	if err != nil {
		t.Fatalf("SeedInstallation() error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions())
	if repo := fakeStore.byKey("github", "acme/api"); repo == nil || repo.RemovedAt != nil {
		t.Fatalf("expected acme/api written despite snapshot error, got %#v", repo)
	}
}

func TestApplyInstallationRepositoriesAddsAndRemoves(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", InstallationID: int64Ptr(11), AccountLogin: "acme", Owner: "acme", Name: "old", FullName: "acme/old"}); err != nil {
		t.Fatalf("seed old repo: %v", err)
	}

	err := service.ApplyInstallationRepositories(ctx, "github", forge.InstallationRepositoriesEvent{
		Installation:        forge.Installation{ID: 11, AccountName: "acme"},
		RepositoriesAdded:   []forge.Repository{{Owner: "acme", Name: "new", FullName: "acme/new"}},
		RepositoriesRemoved: []forge.Repository{{Owner: "acme", Name: "old", FullName: "acme/old"}},
	})
	if err != nil {
		t.Fatalf("ApplyInstallationRepositories() error = %v", err)
	}

	if repo := fakeStore.byKey("github", "acme/new"); repo == nil || repo.RemovedAt != nil {
		t.Fatalf("expected acme/new active, got %#v", repo)
	}
	if repo := fakeStore.byKey("github", "acme/old"); repo == nil || repo.RemovedAt == nil {
		t.Fatalf("expected acme/old removed, got %#v", repo)
	}
}

func TestApplyRepositoryRenameIsIdempotent(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", ProviderRepoID: stringPtr("42"), AccountLogin: "acme", Owner: "acme", Name: "old", FullName: "acme/old"}); err != nil {
		t.Fatalf("seed old repo: %v", err)
	}

	renameEvent := forge.RepositoryEvent{Action: "renamed", Repo: forge.Repository{ProviderRepoID: "42", Owner: "acme", Name: "new", FullName: "acme/new"}}
	for range 2 {
		if err := service.ApplyRepository(ctx, "github", renameEvent); err != nil {
			t.Fatalf("ApplyRepository(rename) error = %v", err)
		}
	}
	if repo := fakeStore.byKey("github", "acme/new"); repo == nil || repo.RemovedAt != nil {
		t.Fatalf("expected acme/new active after rename, got %#v", repo)
	}
	if repo := fakeStore.byKey("github", "acme/old"); repo == nil || repo.RemovedAt == nil {
		t.Fatalf("expected acme/old removed after rename, got %#v", repo)
	}
	assertAuditActions(t, fakeStore.auditActions(), audit.ActionRepoDetected, audit.ActionRepoRenamed)
}

func TestApplyRepositoryArchiveAndDeleteAreIdempotent(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", ProviderRepoID: stringPtr("42"), AccountLogin: "acme", Owner: "acme", Name: "new", FullName: "acme/new"}); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	fakeStore.resetAuditLogs()

	archiveEvent := forge.RepositoryEvent{Action: "archived", Repo: forge.Repository{FullName: "acme/new"}}
	if err := service.ApplyRepository(ctx, "github", archiveEvent); err != nil {
		t.Fatalf("ApplyRepository(archived) error = %v", err)
	}
	if repo := fakeStore.byKey("github", "acme/new"); repo == nil || !repo.Archived {
		t.Fatalf("expected acme/new archived, got %#v", repo)
	}
	if actions := fakeStore.auditActions(); len(actions) != 1 || actions[0] != audit.ActionRepoArchived {
		t.Fatalf("archive audit actions = %#v, want [%q]", actions, audit.ActionRepoArchived)
	}
	fakeStore.resetAuditLogs()

	deleteEvent := forge.RepositoryEvent{Action: "deleted", Repo: forge.Repository{FullName: "acme/new"}}
	for range 2 {
		if err := service.ApplyRepository(ctx, "github", deleteEvent); err != nil {
			t.Fatalf("ApplyRepository(deleted) error = %v", err)
		}
	}
	if repo := fakeStore.byKey("github", "acme/new"); repo == nil || repo.RemovedAt == nil {
		t.Fatalf("expected acme/new removed after delete, got %#v", repo)
	}
	if actions := fakeStore.auditActions(); len(actions) != 1 || actions[0] != audit.ActionRepoDeleted {
		t.Fatalf("delete audit actions = %#v, want [%q]", actions, audit.ActionRepoDeleted)
	}
}

func TestApplyRepositoryTransferRetiresPreviousTenantKey(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", ProviderRepoID: stringPtr("77"), AccountLogin: "old-org", Owner: "old-org", Name: "api", FullName: "old-org/api"}); err != nil {
		t.Fatalf("seed old repo: %v", err)
	}

	transferEvent := forge.RepositoryEvent{Action: "transferred", Repo: forge.Repository{ProviderRepoID: "77", Owner: "new-org", Name: "api", FullName: "new-org/api"}}
	if err := service.ApplyRepository(ctx, "github", transferEvent); err != nil {
		t.Fatalf("ApplyRepository(transferred) error = %v", err)
	}

	if repo := fakeStore.byKey("github", "new-org/api"); repo == nil || repo.RemovedAt != nil {
		t.Fatalf("expected new-org/api active after transfer, got %#v", repo)
	}
	if repo := fakeStore.byKey("github", "old-org/api"); repo == nil || repo.RemovedAt == nil {
		t.Fatalf("expected old-org/api removed after transfer, got %#v", repo)
	}
	active, err := fakeStore.ListForgeRepositoriesByAccount(ctx, "github", "old-org")
	if err != nil {
		t.Fatalf("ListForgeRepositoriesByAccount(old-org) error = %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active old-org repos after transfer, got %#v", active)
	}
	active, err = fakeStore.ListForgeRepositoriesByAccount(ctx, "github", "new-org")
	if err != nil {
		t.Fatalf("ListForgeRepositoriesByAccount(new-org) error = %v", err)
	}
	if len(active) != 1 || active[0].FullName != "new-org/api" {
		t.Fatalf("expected only new-org/api active after transfer, got %#v", active)
	}
}

func TestApplyRepositoryTransferChainKeepsSingleActiveTenantKey(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", ProviderRepoID: stringPtr("77"), AccountLogin: "old-org", Owner: "old-org", Name: "api", FullName: "old-org/api"}); err != nil {
		t.Fatalf("seed old repo: %v", err)
	}

	if err := service.ApplyRepository(ctx, "github", forge.RepositoryEvent{Action: "transferred", Repo: forge.Repository{ProviderRepoID: "77", Owner: "new-org", Name: "api", FullName: "new-org/api"}}); err != nil {
		t.Fatalf("ApplyRepository(first transfer) error = %v", err)
	}

	assertTransferState(t, fakeStore, ctx, "github", "77", "old-org/api", true)
	assertTransferState(t, fakeStore, ctx, "github", "77", "new-org/api", false)
	assertSingleActiveRepoForProviderRepoID(t, fakeStore, "github", "77", "new-org/api")

	if err := service.ApplyRepository(ctx, "github", forge.RepositoryEvent{Action: "transferred", Repo: forge.Repository{ProviderRepoID: "77", Owner: "final-org", Name: "api", FullName: "final-org/api"}}); err != nil {
		t.Fatalf("ApplyRepository(second transfer) error = %v", err)
	}

	assertTransferState(t, fakeStore, ctx, "github", "77", "old-org/api", true)
	assertTransferState(t, fakeStore, ctx, "github", "77", "new-org/api", true)
	assertTransferState(t, fakeStore, ctx, "github", "77", "final-org/api", false)
	assertSingleActiveRepoForProviderRepoID(t, fakeStore, "github", "77", "final-org/api")
}

func TestSyncMakesArchivedAuthoritativeForMatchedRepositories(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fakeStore := newFakeStore()
	provider := &stubProvider{
		installations: []forge.Installation{{ID: 12, AccountName: "acme"}},
		repositories: []forge.Repository{
			{Owner: "acme", Name: "api", FullName: "acme/api", Archived: true},
			{Owner: "acme", Name: "web", FullName: "acme/web", Archived: false},
			{Owner: "other", Name: "skip", FullName: "other/skip", Archived: true},
		},
	}
	service := NewService(fakeStore, map[string]forge.Provider{"github": provider}, zerolog.New(io.Discard))

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", InstallationID: int64Ptr(12), AccountLogin: "acme", Owner: "acme", Name: "api", FullName: "acme/api", Archived: false}); err != nil {
		t.Fatalf("seed api: %v", err)
	}
	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", InstallationID: int64Ptr(12), AccountLogin: "acme", Owner: "acme", Name: "web", FullName: "acme/web", Archived: true}); err != nil {
		t.Fatalf("seed web: %v", err)
	}

	if err := service.Sync(ctx, "github", "acme"); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	if repo := fakeStore.byKey("github", "acme/api"); repo == nil || !repo.Archived {
		t.Fatalf("expected acme/api archived after sync, got %#v", repo)
	}
	if repo := fakeStore.byKey("github", "acme/web"); repo == nil || repo.Archived {
		t.Fatalf("expected acme/web unarchived after sync, got %#v", repo)
	}
	if repo := fakeStore.byKey("github", "other/skip"); repo != nil {
		t.Fatalf("expected other tenant repo not to be synced, got %#v", repo)
	}
}

func TestUpsertRepositoryDetectedAuditOnlyOnTransition(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()
	repo := forge.Repository{Owner: "acme", Name: "api", FullName: "acme/api"}

	if _, err := service.upsertRepository(ctx, "github", nil, repo, false); err != nil {
		t.Fatalf("first upsert error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions(), audit.ActionRepoDetected)

	fakeStore.resetAuditLogs()
	if _, err := service.upsertRepository(ctx, "github", nil, repo, false); err != nil {
		t.Fatalf("second upsert error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions())
}

func TestUpsertRepositoryRedetectedAuditAfterRemoval(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", AccountLogin: "acme", Owner: "acme", Name: "api", FullName: "acme/api"}); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	if _, err := fakeStore.SoftDeleteForgeRepository(ctx, "github", "acme/api"); err != nil {
		t.Fatalf("soft delete repo: %v", err)
	}
	fakeStore.resetAuditLogs()

	if _, err := service.upsertRepository(ctx, "github", nil, forge.Repository{Owner: "acme", Name: "api", FullName: "acme/api"}, false); err != nil {
		t.Fatalf("upsert removed repo error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions(), audit.ActionRepoDetected)
}

func TestApplyRepositoryArchivedAuditOnlyOnChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		action         string
		initialArchive bool
		wantActions    []string
		wantArchived   bool
	}{
		{name: "archive transition", action: "archived", initialArchive: false, wantActions: []string{audit.ActionRepoArchived}, wantArchived: true},
		{name: "archive no-op", action: "archived", initialArchive: true, wantArchived: true},
		{name: "unarchive transition", action: "unarchived", initialArchive: true, wantActions: []string{audit.ActionRepoUnarchived}, wantArchived: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakeStore := newFakeStore()
			service := NewService(fakeStore, nil, zerolog.New(io.Discard))
			ctx := context.Background()

			if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", AccountLogin: "acme", Owner: "acme", Name: "api", FullName: "acme/api", Archived: tt.initialArchive}); err != nil {
				t.Fatalf("seed repo: %v", err)
			}
			fakeStore.resetAuditLogs()

			if err := service.ApplyRepository(ctx, "github", forge.RepositoryEvent{Action: tt.action, Repo: forge.Repository{Owner: "acme", FullName: "acme/api"}}); err != nil {
				t.Fatalf("ApplyRepository(%s) error = %v", tt.action, err)
			}
			assertAuditActions(t, fakeStore.auditActions(), tt.wantActions...)
			if repo := fakeStore.byKey("github", "acme/api"); repo == nil || repo.Archived != tt.wantArchived {
				t.Fatalf("archived state = %#v, want archived=%t", repo, tt.wantArchived)
			}
		})
	}
}

func TestApplyRepositoryDeletedAuditOnlyOnChange(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", AccountLogin: "acme", Owner: "acme", Name: "api", FullName: "acme/api"}); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	fakeStore.resetAuditLogs()

	if err := service.ApplyRepository(ctx, "github", forge.RepositoryEvent{Action: "deleted", Repo: forge.Repository{Owner: "acme", FullName: "acme/api"}}); err != nil {
		t.Fatalf("ApplyRepository(deleted) error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions(), audit.ActionRepoDeleted)
	assertAuditReason(t, fakeStore.auditLogs[0], "repository_deleted")

	fakeStore.resetAuditLogs()
	if err := service.ApplyRepository(ctx, "github", forge.RepositoryEvent{Action: "deleted", Repo: forge.Repository{Owner: "acme", FullName: "acme/api"}}); err != nil {
		t.Fatalf("ApplyRepository(deleted second) error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions())
}

func TestApplyInstallationDeletedLogsPerRemovedRepository(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	for _, repo := range []store.ForgeRepository{
		{Provider: "github", InstallationID: int64Ptr(10), AccountLogin: "acme", Owner: "acme", Name: "api", FullName: "acme/api"},
		{Provider: "github", InstallationID: int64Ptr(10), AccountLogin: "acme", Owner: "acme", Name: "web", FullName: "acme/web"},
	} {
		if _, err := fakeStore.UpsertForgeRepository(ctx, repo); err != nil {
			t.Fatalf("seed repo %s: %v", repo.FullName, err)
		}
	}
	fakeStore.resetAuditLogs()

	if err := service.ApplyInstallation(ctx, "github", forge.InstallationEvent{Action: "deleted", Installation: forge.Installation{ID: 10, AccountName: "acme"}}); err != nil {
		t.Fatalf("ApplyInstallation(deleted) error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions(), audit.ActionRepoDeleted, audit.ActionRepoDeleted)
	for _, entry := range fakeStore.auditLogs {
		assertAuditReason(t, entry, "installation_removed")
	}
}

func TestApplyInstallationRepositoriesRemovedLogsDeletedAudit(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", InstallationID: int64Ptr(11), AccountLogin: "acme", Owner: "acme", Name: "old", FullName: "acme/old"}); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	fakeStore.resetAuditLogs()

	if err := service.ApplyInstallationRepositories(ctx, "github", forge.InstallationRepositoriesEvent{Installation: forge.Installation{ID: 11, AccountName: "acme"}, RepositoriesRemoved: []forge.Repository{{Owner: "acme", Name: "old", FullName: "acme/old"}}}); err != nil {
		t.Fatalf("ApplyInstallationRepositories() error = %v", err)
	}
	assertAuditActions(t, fakeStore.auditActions(), audit.ActionRepoDeleted)
	assertAuditReason(t, fakeStore.auditLogs[0], "installation_repositories_removed")
}

func TestApplyRepositoryRenameLogsOldFullName(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	if _, err := fakeStore.UpsertForgeRepository(ctx, store.ForgeRepository{Provider: "github", ProviderRepoID: stringPtr("42"), AccountLogin: "acme", Owner: "acme", Name: "old", FullName: "acme/old"}); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	fakeStore.resetAuditLogs()

	if err := service.ApplyRepository(ctx, "github", forge.RepositoryEvent{Action: "renamed", Repo: forge.Repository{ProviderRepoID: "42", Owner: "acme", Name: "new", FullName: "acme/new"}}); err != nil {
		t.Fatalf("ApplyRepository(renamed) error = %v", err)
	}
	renameAudit := auditLogByAction(t, fakeStore.auditLogs, audit.ActionRepoRenamed)
	contextMap := auditContextMap(t, renameAudit)
	if got := contextMap["old_full_name"]; got != "acme/old" {
		t.Fatalf("rename audit old_full_name = %#v, want %q", got, "acme/old")
	}
}

func TestAuditFailureDoesNotFailInventoryWrite(t *testing.T) {
	t.Parallel()

	fakeStore := newFakeStore()
	fakeStore.createAuditErr = errors.New("boom")
	service := NewService(fakeStore, nil, zerolog.New(io.Discard))
	ctx := context.Background()

	err := service.ApplyRepository(ctx, "github", forge.RepositoryEvent{Action: "created", Repo: forge.Repository{Owner: "acme", Name: "api", FullName: "acme/api"}})
	if err != nil {
		t.Fatalf("ApplyRepository(created) error = %v", err)
	}
	if repo := fakeStore.byKey("github", "acme/api"); repo == nil || repo.RemovedAt != nil {
		t.Fatalf("expected acme/api persisted despite audit failure, got %#v", repo)
	}
}

type fakeStore struct {
	repos                             map[string]store.ForgeRepository
	orgs                              map[string]*store.Organization
	listForgeRepositoriesByAccount    map[string][]store.ForgeRepository
	listForgeRepositoriesByAccountErr error
	auditLogs                         []dbgen.CreateAuditLogParams
	createAuditErr                    error
	clock                             int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		repos:                          map[string]store.ForgeRepository{},
		orgs:                           map[string]*store.Organization{},
		listForgeRepositoriesByAccount: map[string][]store.ForgeRepository{},
	}
}

func (f *fakeStore) UpsertForgeRepository(_ context.Context, repository store.ForgeRepository) (*store.ForgeRepositoryUpsertResult, error) {
	key := fakeKey(repository.Provider, repository.FullName)
	existing, ok := f.repos[key]
	inserted := !ok
	previouslyRemoved := ok && existing.RemovedAt != nil
	if ok {
		repository.ID = existing.ID
		repository.CreatedAt = existing.CreatedAt
		repository.Archived = existing.Archived
		if repository.InstallationID == nil {
			repository.InstallationID = existing.InstallationID
		}
		if repository.ProviderRepoID == nil {
			repository.ProviderRepoID = existing.ProviderRepoID
		}
		if strings.TrimSpace(repository.DefaultBranch) == "" {
			repository.DefaultBranch = existing.DefaultBranch
		}
		if strings.TrimSpace(repository.HTMLURL) == "" {
			repository.HTMLURL = existing.HTMLURL
		}
	} else {
		repository.ID = uuid.New()
		repository.CreatedAt = fakeTime(&f.clock)
	}
	repository.ProviderKey = stringsToLowerTrim(repository.FullName)
	repository.LastSeenAt = fakeTime(&f.clock)
	repository.UpdatedAt = fakeTime(&f.clock)
	repository.RemovedAt = nil
	f.repos[key] = repository
	result := repository
	return &store.ForgeRepositoryUpsertResult{Repository: &result, Inserted: inserted, PreviouslyRemoved: previouslyRemoved}, nil
}

func (f *fakeStore) SoftDeleteForgeRepository(_ context.Context, provider, providerKey string) (*store.ForgeRepositoryChange, error) {
	key := fakeKey(provider, providerKey)
	repo, ok := f.repos[key]
	if !ok || repo.RemovedAt != nil {
		return nil, nil
	}
	removedAt := fakeTime(&f.clock)
	repo.RemovedAt = &removedAt
	repo.UpdatedAt = fakeTime(&f.clock)
	f.repos[key] = repo
	return &store.ForgeRepositoryChange{ID: repo.ID, FullName: repo.FullName, ProviderKey: repo.ProviderKey}, nil
}

func (f *fakeStore) MarkInstallationRepositoriesRemoved(_ context.Context, provider string, installationID int64) ([]store.ForgeRepositoryChange, error) {
	changes := make([]store.ForgeRepositoryChange, 0)
	for key, repo := range f.repos {
		if repo.Provider == provider && repo.InstallationID != nil && *repo.InstallationID == installationID && repo.RemovedAt == nil {
			removedAt := fakeTime(&f.clock)
			repo.RemovedAt = &removedAt
			repo.UpdatedAt = fakeTime(&f.clock)
			f.repos[key] = repo
			changes = append(changes, store.ForgeRepositoryChange{ID: repo.ID, FullName: repo.FullName, ProviderKey: repo.ProviderKey})
		}
	}
	return changes, nil
}

func (f *fakeStore) SetForgeRepositoryArchived(_ context.Context, provider, providerKey string, archived bool) (*store.ForgeRepositoryChange, error) {
	key := fakeKey(provider, providerKey)
	repo, ok := f.repos[key]
	if !ok || repo.Archived == archived {
		return nil, nil
	}
	repo.Archived = archived
	repo.UpdatedAt = fakeTime(&f.clock)
	f.repos[key] = repo
	return &store.ForgeRepositoryChange{ID: repo.ID, FullName: repo.FullName, ProviderKey: repo.ProviderKey}, nil
}

func (f *fakeStore) SetForgeRepositoryPrivate(_ context.Context, provider, providerKey string, private bool) error {
	key := fakeKey(provider, providerKey)
	repo, ok := f.repos[key]
	if !ok {
		return nil
	}
	repo.Private = private
	repo.UpdatedAt = fakeTime(&f.clock)
	f.repos[key] = repo
	return nil
}

func (f *fakeStore) CreateAuditLog(_ context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error) {
	f.auditLogs = append(f.auditLogs, arg)
	if f.createAuditErr != nil {
		return dbgen.AuditLog{}, f.createAuditErr
	}
	return dbgen.AuditLog{ID: uuid.New()}, nil
}

func (f *fakeStore) GetOrganizationByProviderAndSlug(_ context.Context, provider, slug string) (*store.Organization, error) {
	org, ok := f.orgs[fakeKey(provider, slug)]
	if !ok {
		return nil, nil
	}
	result := *org
	return &result, nil
}

func (f *fakeStore) ListForgeRepositoriesByAccount(_ context.Context, provider, account string) ([]store.ForgeRepository, error) {
	if f.listForgeRepositoriesByAccountErr != nil {
		return nil, f.listForgeRepositoriesByAccountErr
	}
	if configured, ok := f.listForgeRepositoriesByAccount[fakeKey(provider, account)]; ok {
		result := make([]store.ForgeRepository, len(configured))
		copy(result, configured)
		return result, nil
	}
	result := make([]store.ForgeRepository, 0)
	for _, repo := range f.repos {
		if repo.Provider == provider && equalAccount(repo.AccountLogin, account) && repo.RemovedAt == nil {
			result = append(result, repo)
		}
	}
	return result, nil
}

func (f *fakeStore) GetForgeRepositoryByProviderRepoID(_ context.Context, provider, id string) (*store.ForgeRepository, error) {
	var current *store.ForgeRepository
	for _, repo := range f.repos {
		if repo.Provider != provider || repo.ProviderRepoID == nil || *repo.ProviderRepoID != id || repo.RemovedAt != nil {
			continue
		}
		if current == nil || repo.UpdatedAt.After(current.UpdatedAt) {
			candidate := repo
			current = &candidate
		}
	}
	if current != nil {
		result := *current
		return &result, nil
	}
	return nil, nil
}

func (f *fakeStore) byKey(provider, fullName string) *store.ForgeRepository {
	repo, ok := f.repos[fakeKey(provider, fullName)]
	if !ok {
		return nil
	}
	result := repo
	return &result
}

func (f *fakeStore) resetAuditLogs() {
	f.auditLogs = nil
}

func (f *fakeStore) auditActions() []string {
	actions := make([]string, len(f.auditLogs))
	for i, entry := range f.auditLogs {
		actions[i] = entry.Action
	}
	return actions
}

func fakeKey(provider, fullName string) string {
	return provider + ":" + stringsToLowerTrim(fullName)
}

func stringsToLowerTrim(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func int64Ptr(value int64) *int64 {
	return &value
}

type stubProvider struct {
	installations []forge.Installation
	repositories  []forge.Repository
}

func (s *stubProvider) ID() string { return "github" }

func (s *stubProvider) Installations(context.Context) ([]forge.Installation, error) {
	return append([]forge.Installation(nil), s.installations...), nil
}

func (s *stubProvider) ListRepositories(context.Context, forge.ListReposOptions) ([]forge.Repository, error) {
	return append([]forge.Repository(nil), s.repositories...), nil
}

func (s *stubProvider) GetRepository(context.Context, string, string) (*forge.Repository, error) {
	return nil, forge.ErrNotImplemented
}

func (s *stubProvider) ListBranches(context.Context, string, string) ([]forge.Branch, error) {
	return nil, forge.ErrNotImplemented
}

func (s *stubProvider) GetBranch(context.Context, string, string, string) (*forge.Branch, error) {
	return nil, forge.ErrNotImplemented
}

func (s *stubProvider) GetFileContent(context.Context, string, string, string, string) ([]byte, error) {
	return nil, forge.ErrNotImplemented
}

func (s *stubProvider) CreateOrUpdateFile(context.Context, string, string, string, string, string, []byte) error {
	return forge.ErrNotImplemented
}

func (s *stubProvider) CreateBranch(context.Context, string, string, string, string) error {
	return forge.ErrNotImplemented
}

func (s *stubProvider) CreatePullRequest(context.Context, string, string, forge.CreatePROptions) (*forge.PullRequest, error) {
	return nil, forge.ErrNotImplemented
}

func (s *stubProvider) CreateCommitStatus(context.Context, string, string, string, forge.CommitStatus) error {
	return forge.ErrNotImplemented
}

func (s *stubProvider) ValidateWebhookPayload(*http.Request, string) ([]byte, error) {
	return nil, forge.ErrNotImplemented
}

func (s *stubProvider) ParseWebhookEvent(string, []byte) (forge.WebhookEvent, error) {
	return nil, forge.ErrUnsupportedWebhookEvent
}

func (s *stubProvider) OAuth2Config(string) *oauth2.Config {
	return nil
}

func (s *stubProvider) UserInfo(context.Context, *oauth2.Token) (*forge.UserInfo, error) {
	return nil, forge.ErrNotImplemented
}

func assertTransferState(t *testing.T, fakeStore *fakeStore, ctx context.Context, provider, providerRepoID, fullName string, removed bool) {
	t.Helper()

	repo := fakeStore.byKey(provider, fullName)
	if repo == nil {
		t.Fatalf("expected %s to exist", fullName)
	}
	if gotRemoved := repo.RemovedAt != nil; gotRemoved != removed {
		t.Fatalf("expected %s removed=%t, got %#v", fullName, removed, repo)
	}
	if repo.ProviderRepoID == nil || *repo.ProviderRepoID != providerRepoID {
		t.Fatalf("expected %s provider_repo_id=%s, got %#v", fullName, providerRepoID, repo)
	}
	active, err := fakeStore.ListForgeRepositoriesByAccount(ctx, provider, repo.AccountLogin)
	if err != nil {
		t.Fatalf("ListForgeRepositoriesByAccount(%s) error = %v", repo.AccountLogin, err)
	}
	if removed && len(active) != 0 {
		t.Fatalf("expected no active repos for %s, got %#v", repo.AccountLogin, active)
	}
	if !removed && (len(active) != 1 || active[0].FullName != fullName) {
		t.Fatalf("expected only %s active for %s, got %#v", fullName, repo.AccountLogin, active)
	}
}

func assertSingleActiveRepoForProviderRepoID(t *testing.T, fakeStore *fakeStore, provider, providerRepoID, fullName string) {
	t.Helper()

	active := make([]store.ForgeRepository, 0, 1)
	for _, repo := range fakeStore.repos {
		if repo.Provider == provider && repo.ProviderRepoID != nil && *repo.ProviderRepoID == providerRepoID && repo.RemovedAt == nil {
			active = append(active, repo)
		}
	}
	if len(active) != 1 || active[0].FullName != fullName {
		t.Fatalf("expected only %s active for provider_repo_id %s, got %#v", fullName, providerRepoID, active)
	}
}

func assertAuditActions(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("audit actions len = %d, want %d (%#v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audit actions = %#v, want %#v", got, want)
		}
	}
}

func assertAuditReason(t *testing.T, entry dbgen.CreateAuditLogParams, want string) {
	t.Helper()
	contextMap := auditContextMap(t, entry)
	if got := contextMap["reason"]; got != want {
		t.Fatalf("audit reason = %#v, want %q", got, want)
	}
}

func auditContextMap(t *testing.T, entry dbgen.CreateAuditLogParams) map[string]any {
	t.Helper()
	contextMap := map[string]any{}
	if err := json.Unmarshal(entry.Context, &contextMap); err != nil {
		t.Fatalf("unmarshal audit context: %v", err)
	}
	return contextMap
}

func auditLogByAction(t *testing.T, entries []dbgen.CreateAuditLogParams, action string) dbgen.CreateAuditLogParams {
	t.Helper()
	for _, entry := range entries {
		if entry.Action == action {
			return entry
		}
	}
	t.Fatalf("missing audit action %q in %#v", action, entries)
	return dbgen.CreateAuditLogParams{}
}

func fakeTime(counter *int64) time.Time {
	(*counter)++
	return time.Unix(*counter, 0).UTC()
}

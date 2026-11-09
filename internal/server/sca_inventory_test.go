package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
)

type scaMetadataForge struct {
	discoveryTestForgeProvider
	live         forge.Repository
	err          error
	calls        atomic.Int32
	beforeReturn func()
}

func (p *scaMetadataForge) GetRepository(context.Context, string, string) (*forge.Repository, error) {
	p.calls.Add(1)
	if p.beforeReturn != nil {
		p.beforeReturn()
	}
	return &p.live, p.err
}

func TestEnableSCARefreshesMissingDiscoveryMetadata(t *testing.T) {
	for _, missing := range []string{"account", "default branch", "both"} {
		t.Run(missing, func(t *testing.T) {
			s, org, admin, _, inv := newSCAFixture(t)
			ctx := context.Background()
			account, branch := org.ForgeAccountID, "main"
			if missing != "default branch" {
				account = ""
			}
			if missing != "account" {
				branch = ""
			}
			if _, err := s.db.Exec(`UPDATE forge_repositories SET account_id=$2,default_branch=$3 WHERE id=$1`,
				inv.ID, account, branch); err != nil {
				t.Fatal(err)
			}
			provider := &scaMetadataForge{live: forge.Repository{
				Owner: inv.Owner, OwnerID: org.ForgeAccountID, Name: inv.Name, FullName: inv.FullName,
				ProviderRepoID: *inv.ProviderRepoID, DefaultBranch: "main",
			}}
			s.forges[org.Provider] = provider
			response := httptest.NewRecorder()
			s.handleEnableSCA(response, newEnrollRequest(t, admin, org.Provider, org.Slug,
				map[string]any{"provider_ids": []string{inv.ProviderKey}}))
			if response.Code != http.StatusAccepted || strings.Contains(response.Body.String(), `"failed"`) {
				t.Fatalf("legacy discovery still cannot enable SCA: status=%d body=%s", response.Code, response.Body)
			}
			repo, err := s.queries.GetRepositoryByProviderID(ctx, org.ID, org.Provider, inv.ProviderKey)
			if err != nil || repo == nil {
				t.Fatalf("repository not enrolled: repo=%v err=%v", repo, err)
			}
			if _, err := s.queries.VerifiedForgeRepositoryTarget(ctx, repo.ID); err != nil {
				t.Fatalf("verified identity not captured: %v", err)
			}
			job, err := s.queries.GetLatestDepExtractionJobForRef(ctx, repo.ID, "main")
			if err != nil || job == nil {
				t.Fatalf("initial extraction not queued: job=%v err=%v", job, err)
			}
			if _, _, _, err := s.enableSCA(ctx, org, inv.ProviderKey); err != nil {
				t.Fatal(err)
			}
			if provider.calls.Load() != 1 {
				t.Fatalf("complete metadata should not need another live refresh: calls=%d", provider.calls.Load())
			}
			var secrets int
			if err := s.db.QueryRow(`SELECT count(*) FROM secret_scan_jobs WHERE repo_id=$1`, repo.ID).Scan(&secrets); err != nil || secrets != 0 {
				t.Fatalf("SCA recovery triggered secret scans: count=%d err=%v", secrets, err)
			}
		})
	}
}

func TestSCARefreshRejectsChangedLiveIdentityAndAccess(t *testing.T) {
	for _, failure := range []string{"account reuse", "repository reuse", "namespace change", "revoked access", "archived", "no branch"} {
		t.Run(failure, func(t *testing.T) {
			s, org, _, _, inv := newSCAFixture(t)
			ctx := context.Background()
			if _, err := s.db.Exec(`UPDATE forge_repositories SET account_id='' WHERE id=$1`, inv.ID); err != nil {
				t.Fatal(err)
			}
			provider := &scaMetadataForge{live: forge.Repository{
				Owner: inv.Owner, OwnerID: org.ForgeAccountID, Name: inv.Name, FullName: inv.FullName,
				ProviderRepoID: *inv.ProviderRepoID, DefaultBranch: "main",
			}}
			switch failure {
			case "account reuse":
				provider.live.OwnerID = uuid.NewString()
			case "repository reuse":
				provider.live.ProviderRepoID = uuid.NewString()
			case "namespace change":
				provider.live.FullName = "another-account/app"
			case "revoked access":
				provider.err = forge.ErrRepositoryNotFound
			case "archived":
				provider.live.Archived = true
			case "no branch":
				provider.live.DefaultBranch = ""
			}
			s.forges[org.Provider] = provider
			if _, _, _, err := s.enableSCA(ctx, org, inv.ProviderKey); err == nil {
				t.Fatal("unverified repository was enabled")
			}
			current, err := s.queries.GetForgeRepositoryForAccount(ctx, org.Provider, org.Slug, inv.ProviderKey)
			if err != nil || current == nil || current.AccountID != "" {
				t.Fatalf("failed verification rewrote metadata: current=%+v err=%v", current, err)
			}
			repo, err := s.queries.GetRepositoryByProviderID(ctx, org.ID, org.Provider, inv.ProviderKey)
			if err != nil || repo != nil {
				t.Fatalf("failed verification enrolled repository: repo=%v err=%v", repo, err)
			}
		})
	}
}

func TestSCARefreshDoesNotReviveOrOverwriteNewerInventory(t *testing.T) {
	for _, change := range []string{"removed", "archived", "repository replaced", "verified concurrently"} {
		t.Run(change, func(t *testing.T) {
			s, org, _, _, inv := newSCAFixture(t)
			ctx := context.Background()
			if _, err := s.db.Exec(`UPDATE forge_repositories SET account_id='' WHERE id=$1`, inv.ID); err != nil {
				t.Fatal(err)
			}
			provider := &scaMetadataForge{live: forge.Repository{
				Owner: inv.Owner, OwnerID: org.ForgeAccountID, Name: inv.Name, FullName: inv.FullName,
				ProviderRepoID: *inv.ProviderRepoID, DefaultBranch: "main",
			}}
			provider.beforeReturn = func() {
				var err error
				switch change {
				case "removed":
					_, err = s.queries.SoftDeleteForgeRepository(ctx, org.Provider, inv.ProviderKey)
				case "archived":
					_, err = s.queries.SetForgeRepositoryArchived(ctx, org.Provider, inv.ProviderKey, true)
				case "repository replaced":
					_, err = s.db.Exec(`UPDATE forge_repositories SET provider_repo_id=$2,updated_at=now() WHERE id=$1`, inv.ID, uuid.NewString())
				case "verified concurrently":
					_, err = s.db.Exec(`UPDATE forge_repositories SET account_id=$2,updated_at=now() WHERE id=$1`, inv.ID, org.ForgeAccountID)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			s.forges[org.Provider] = provider
			_, _, _, err := s.enableSCA(ctx, org, inv.ProviderKey)
			if change == "verified concurrently" {
				if err != nil {
					t.Fatalf("equivalent verified refresh should be adopted: %v", err)
				}
			} else if err == nil {
				t.Fatal("a newer access/identity observation was overwritten")
			}
		})
	}
}

func TestSCARefreshRequiresBoundOrganizationAndAuthorizedCaller(t *testing.T) {
	s, org, _, viewer, inv := newSCAFixture(t)
	ctx := context.Background()
	provider := &scaMetadataForge{}
	s.forges[org.Provider] = provider
	if _, err := s.db.Exec(`UPDATE forge_repositories SET account_id='' WHERE id=$1`, inv.ID); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.handleEnableSCA(response, newEnrollRequest(t, viewer, org.Provider, org.Slug,
		map[string]any{"provider_ids": []string{inv.ProviderKey}}))
	if response.Code != http.StatusForbidden || provider.calls.Load() != 0 {
		t.Fatalf("unauthorized caller reached forge: status=%d calls=%d", response.Code, provider.calls.Load())
	}
	if err := s.refreshSCAInventoryMetadata(ctx, org, "another-account/app"); err == nil || provider.calls.Load() != 0 {
		t.Fatalf("foreign repository triggered a forge request: err=%v calls=%d", err, provider.calls.Load())
	}
	if _, err := s.db.Exec(`UPDATE forge_repositories SET account_id=$2 WHERE id=$1`, inv.ID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if err := s.refreshSCAInventoryMetadata(ctx, org, inv.ProviderKey); err == nil || provider.calls.Load() != 0 {
		t.Fatalf("known account mismatch was refreshed by name: err=%v calls=%d", err, provider.calls.Load())
	}
	copy := *org
	copy.ForgeAccountID = ""
	err := s.refreshSCAInventoryMetadata(ctx, &copy, inv.ProviderKey)
	var public *scaEnableError
	if !errors.As(err, &public) || !strings.Contains(public.Error(), "account binding") || provider.calls.Load() != 0 {
		t.Fatalf("organization was bound by mutable name: err=%v calls=%d", err, provider.calls.Load())
	}
}

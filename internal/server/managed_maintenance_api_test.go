package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type managedMaintenanceTestForge struct {
	managedHeadTestForge
	exists bool
	writes int
}

func (f *managedMaintenanceTestForge) CheckMaintenanceCreation(context.Context, string, string) error {
	return nil
}
func (f *managedMaintenanceTestForge) InspectMaintenanceTarget(_ context.Context, _, _, tag, sha, target string) (*forge.MaintenanceEvidence, error) {
	return &forge.MaintenanceEvidence{SourceTag: tag, SourceSHA: sha, TagSHA: sha, TagConfirmed: true, TargetBranch: target, Exists: f.exists, HeadSHA: sha, SourceAncestor: f.exists}, nil
}
func (f *managedMaintenanceTestForge) CreateApprovedMaintenanceTarget(_ context.Context, _, _ string, r forge.MaintenanceCreation) (*forge.MaintenanceCreated, error) {
	if err := forge.CheckMaintenanceBranch(r.TargetBranch, r.ApprovedPatterns); err != nil {
		return nil, err
	}
	result := &forge.MaintenanceCreated{TargetBranch: r.TargetBranch, SourceTag: r.SourceTag, SourceSHA: r.SourceSHA}
	if f.exists {
		if !r.ReconcileExisting {
			return nil, forge.ErrMaintenanceTargetCollision
		}
		result.Reconciled = true
		return result, r.Audit("reconciled", result)
	}
	if err := r.Audit("ref_intent", result); err != nil {
		return nil, err
	}
	f.exists = true
	f.writes++
	result.Created = true
	return result, r.Audit("created", result)
}

func TestManagedMaintenanceCreationRequiresMappingConsentAndOperatorPolicy(t *testing.T) {
	s, org, admin, viewer, inventory := newSCAFixture(t)
	ctx := t.Context()
	repo, err := s.queries.CreateRepository(ctx, org.ID, nil, "app", "app", org.Provider, inventory.ProviderKey, "main", "enrolled")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.queries.CaptureForgeRepositoryBinding(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	source := strings.Repeat("a", 40)
	ref, err := s.queries.UpsertRef(ctx, repo.ID, "v1.2.3", store.RefTypeTag, store.UpsertRefOptions{LatestCommitSHA: &source})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.queries.CreatePlaceholderSnapshot(ctx, ref.ID, source)
	if err != nil {
		t.Fatal(err)
	}
	release, err := s.queries.UpsertRelease(ctx, store.UpsertReleaseParams{RepoID: repo.ID, RefID: ref.ID, SnapshotID: &snapshot.ID, Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.queries.UpdateOrganizationSettings(ctx, org.ID, json.RawMessage(`{"keep":true,"managed_remediation_pr_consent":true}`)); err != nil {
		t.Fatal(err)
	}
	settings := managedMaintenanceSettings{AllowCreation: true, Mappings: []managedMaintenanceMapping{{ID: "line-1-2", TagPattern: "v1.2.*", TargetTemplate: "release/{major}.{minor}"}}}
	body, _ := json.Marshal(settings)
	if err := s.queries.SetManagedMaintenanceSettings(ctx, org.ID, body); err != nil {
		t.Fatal(err)
	}
	remote := &managedMaintenanceTestForge{managedHeadTestForge: managedHeadTestForge{
		repository: forge.Repository{Owner: inventory.Owner, Name: inventory.Name, OwnerID: org.ForgeAccountID, ProviderRepoID: *inventory.ProviderRepoID, DefaultBranch: "main"}, head: source,
	}}
	s.forges = map[string]forge.Provider{org.Provider: remote}
	request := func(user *store.User, payload map[string]any) *http.Request {
		r := newEnrollRequest(t, user, org.Provider, org.Slug, payload)
		chi.RouteContext(r.Context()).URLParams.Add("repoSlug", repo.Slug)
		return r
	}
	payload := func() map[string]any {
		return map[string]any{"release_id": release.ID, "mapping_id": "line-1-2", "target_branch": "release/1.2", "source_tag": "v1.2.3", "source_sha": source}
	}
	t.Setenv("HIBOU_REMEDIATION_MAINTENANCE_BRANCH_ALLOWLIST", "")
	w := httptest.NewRecorder()
	s.handleManagedMaintenanceCreate(w, request(admin, payload()))
	if w.Code != http.StatusConflict || remote.writes != 0 {
		t.Fatalf("default policy allowed creation: %d %s", w.Code, w.Body.String())
	}
	t.Setenv("HIBOU_REMEDIATION_MAINTENANCE_BRANCH_ALLOWLIST", "release/*")
	for _, tt := range []struct {
		name   string
		user   *store.User
		mutate func(map[string]any)
		status int
	}{
		{"viewer", viewer, func(map[string]any) {}, http.StatusForbidden},
		{"stale confirmed source", admin, func(p map[string]any) { p["source_sha"] = strings.Repeat("b", 40) }, http.StatusConflict},
		{"unmapped target", admin, func(p map[string]any) { p["target_branch"] = "release/9.9" }, http.StatusConflict},
		{"unconfirmed tag", admin, func(p map[string]any) { p["source_tag"] = "v9.9.9" }, http.StatusConflict},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := payload()
			tt.mutate(p)
			w := httptest.NewRecorder()
			s.handleManagedMaintenanceCreate(w, request(tt.user, p))
			if w.Code != tt.status || remote.writes != 0 {
				t.Fatalf("unsafe creation: %d %s writes=%d", w.Code, w.Body.String(), remote.writes)
			}
		})
	}
	for attempt := 0; attempt < 2; attempt++ {
		w := httptest.NewRecorder()
		s.handleManagedMaintenanceCreate(w, request(admin, payload()))
		if w.Code != http.StatusOK || remote.writes != 1 {
			t.Fatalf("create/reconcile: %d %s writes=%d", w.Code, w.Body.String(), remote.writes)
		}
		var response struct {
			Data forge.MaintenanceCreated `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Data.Reconciled != (attempt == 1) {
			t.Fatalf("retry was not reconciled: %+v", response.Data)
		}
	}
	var intents int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='remediation.maintenance.intent'`, org.ID).Scan(&intents); err != nil || intents != 1 {
		t.Fatalf("durable creation intent missing/duplicated: %d %v", intents, err)
	}
	configurationRequest := request(admin, map[string]any{"allow_creation": true, "mappings": settings.Mappings})
	configurationRequest = configurationRequest.WithContext(auth.WithTokenAuth(configurationRequest.Context(), &auth.TokenAuth{Scoped: true, Scope: apitoken.Scope{
		Org: org.Slug, Repos: apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{repo.Slug}},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapAdmin: apitoken.AccessWrite},
	}}))
	w = httptest.NewRecorder()
	s.handleManagedMaintenanceSettingsUpdate(w, configurationRequest)
	if w.Code != http.StatusForbidden {
		t.Fatalf("repo-scoped admin changed organization mappings: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleManagedMaintenanceSettingsUpdate(w, request(admin, map[string]any{"allow_creation": false, "mappings": settings.Mappings}))
	if w.Code != http.StatusOK {
		t.Fatalf("organization admin could not save mappings: %d %s", w.Code, w.Body.String())
	}
	stored, err := s.queries.GetOrganizationByID(ctx, org.ID)
	if err != nil || !strings.Contains(string(stored.Settings), `"keep": true`) {
		t.Fatalf("mapping update overwrote unrelated settings: %v %v", stored, err)
	}
}

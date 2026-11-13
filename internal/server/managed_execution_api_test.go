package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/remediation"
	"github.com/hibouhq/hibou/internal/store"
)

func TestManagedKubernetesAPIRequiresMatchingProfileAndPinsDraft(t *testing.T) {
	for name, value := range map[string]string{
		"HIBOU_REMEDIATION_ENABLED": "true", "HIBOU_WORKLOAD_IMAGE": "registry.internal/workload@sha256:" + strings.Repeat("a", 64),
		"HIBOU_REMEDIATION_NPM_REGISTRY": "https://mirror.internal/npm",
		"HIBOU_REMEDIATION_NPM_PATH":     "/usr/local/bin/npm", "HIBOU_REMEDIATION_NPM_VERSION": "10.9.4",
		"HIBOU_REMEDIATION_NODE_PATH": "/usr/local/bin/node", "HIBOU_REMEDIATION_NODE_VERSION": "v22.16.0",
		"HIBOU_REMEDIATION_TOOL_PATH": "/usr/local/bin:/usr/bin:/bin",
	} {
		t.Setenv(name, value)
	}
	cfg, err := config.ManagedExecutionFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	s, org, admin, viewer, inventory := newSCAFixture(t)
	ctx := t.Context()
	repo, err := s.queries.CreateRepository(ctx, org.ID, nil, "app", "app", org.Provider, inventory.ProviderKey, "main", "enrolled")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.queries.CaptureForgeRepositoryBinding(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	head := strings.Repeat("a", 40)
	s.forges = map[string]forge.Provider{org.Provider: managedHeadTestForge{
		repository: forge.Repository{Owner: inventory.Owner, Name: inventory.Name, OwnerID: org.ForgeAccountID, ProviderRepoID: *inventory.ProviderRepoID, DefaultBranch: "main"},
		head:       head,
	}}
	controller := uuid.New()
	t.Cleanup(func() { _ = s.queries.RemoveRemediationController(context.Background(), controller) })
	if err := s.queries.HeartbeatRemediationController(ctx, controller, "retired-profile"); err != nil {
		t.Fatal(err)
	}
	if ready, _ := s.managedExecutionReady(ctx); ready {
		t.Fatal("historical heartbeat enabled configured Kubernetes execution")
	}
	if err := s.queries.HeartbeatRemediationController(ctx, controller, cfg.Profile()); err != nil {
		t.Fatal(err)
	}
	if ready, reason := s.managedExecutionReady(ctx); !ready {
		t.Fatalf("matching controller not ready: %s", reason)
	}
	for _, caller := range []struct {
		user   *store.User
		status int
	}{{viewer, http.StatusForbidden}, {admin, http.StatusAccepted}} {
		request := newEnrollRequest(t, caller.user, org.Provider, org.Slug, map[string]any{"target_branch": "main", "expected_head_sha": head})
		chi.RouteContext(request.Context()).URLParams.Add("repoSlug", repo.Slug)
		w := httptest.NewRecorder()
		s.handleRemediationPrepare(w, request)
		if w.Code != caller.status {
			t.Fatalf("prepare authorization: status=%d want=%d body=%s", w.Code, caller.status, w.Body.String())
		}
		if caller.user != admin {
			continue
		}
		var response struct {
			Data store.RemediationJob `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		job, err := s.queries.GetRemediationJob(ctx, repo.ID, response.Data.ID)
		if err != nil || job == nil {
			t.Fatalf("queued job unavailable: %v", err)
		}
		var input remediation.ManagedInput
		if err := json.Unmarshal(job.Request, &input); err != nil || input.Profile != cfg.Profile() || input.BaseSHA != head {
			t.Fatalf("draft source/profile not pinned: %+v %v", input, err)
		}
		unit := remediation.Unit{ID: ".", Manager: "npm", Manifest: "package.json", Lockfile: "package-lock.json",
			RequiredFiles: []string{"package.json", "package-lock.json"}, WritableFiles: []string{"package.json", "package-lock.json"}, Vulns: []string{"TEST-1"}}
		result, err := json.Marshal(remediation.ManagedResult{Modules: []remediation.ManagedModule{{Manifest: unit.Manifest, Unit: &unit}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE remediation_jobs SET state='awaiting_selection',result=$2 WHERE id=$1`, job.ID, result); err != nil {
			t.Fatal(err)
		}
		t.Setenv("HIBOU_REMEDIATION_NPM_VERSION", "11.0.0")
		newProfile, err := config.ManagedExecutionFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.queries.HeartbeatRemediationController(ctx, controller, newProfile.Profile()); err != nil {
			t.Fatal(err)
		}
		generate := newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{"revision": job.Revision, "units": []map[string]string{{"id": ".", "upgrade_level": "patch"}}})
		chi.RouteContext(generate.Context()).URLParams.Add("repoSlug", repo.Slug)
		chi.RouteContext(generate.Context()).URLParams.Add("jobID", job.ID.String())
		w = httptest.NewRecorder()
		s.handleRemediationGenerate(w, generate)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "profile changed") {
			t.Fatalf("draft silently changed workload profiles: %d %s", w.Code, w.Body.String())
		}
	}
}

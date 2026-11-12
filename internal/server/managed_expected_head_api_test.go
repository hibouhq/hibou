package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type managedHeadTestForge struct {
	forge.Provider
	repository forge.Repository
	head       string
}

func (f managedHeadTestForge) GetRepository(context.Context, string, string) (*forge.Repository, error) {
	return &f.repository, nil
}

func (f managedHeadTestForge) GetBranch(_ context.Context, _, _, name string) (*forge.Branch, error) {
	return &forge.Branch{Name: name, SHA: f.head}, nil
}

func TestRetiredControllerCannotEnableManagedExecution(t *testing.T) {
	s, org, admin, _, inventory := newSCAFixture(t)
	ctx := t.Context()
	repo, err := s.queries.CreateRepository(ctx, org.ID, nil, "app", "app", org.Provider, inventory.ProviderKey, "main", "enrolled")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.queries.CaptureForgeRepositoryBinding(ctx, repo.ID); err != nil {
		t.Fatal(err)
	}
	controller := uuid.New()
	if err := s.queries.HeartbeatRemediationController(ctx, controller, "approved-test-profile"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.queries.RemoveRemediationController(context.Background(), controller) })
	head := strings.Repeat("a", 40)
	s.forges = map[string]forge.Provider{org.Provider: managedHeadTestForge{
		repository: forge.Repository{Owner: inventory.Owner, Name: inventory.Name, OwnerID: org.ForgeAccountID, ProviderRepoID: *inventory.ProviderRepoID, DefaultBranch: "main"},
		head:       head,
	}}
	for _, tt := range []struct {
		name, expected string
		status         int
	}{
		{"stale", strings.Repeat("b", 40), http.StatusServiceUnavailable},
		{"abbreviated", "abcdef", http.StatusServiceUnavailable},
		{"exact", head, http.StatusServiceUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var before int
			if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM remediation_jobs WHERE repo_id=$1`, repo.ID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			request := newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{"target_branch": "main", "expected_head_sha": tt.expected})
			chi.RouteContext(request.Context()).URLParams.Add("repoSlug", repo.Slug)
			w := httptest.NewRecorder()
			s.handleRemediationPrepare(w, request)
			if w.Code != tt.status {
				t.Fatalf("prepare status=%d want=%d body=%s", w.Code, tt.status, w.Body.String())
			}
			var after int
			if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM remediation_jobs WHERE repo_id=$1`, repo.ID).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != before || !strings.Contains(w.Body.String(), "ADR-056") {
				t.Fatalf("unapproved backend enqueued work: before=%d after=%d body=%s", before, after, w.Body.String())
			}
		})
	}
	t.Run("capabilities", func(t *testing.T) {
		request := newEnrollRequest(t, admin, org.Provider, org.Slug, nil)
		chi.RouteContext(request.Context()).URLParams.Add("repoSlug", repo.Slug)
		w := httptest.NewRecorder()
		s.handleRemediationCapabilities(w, request)
		var response struct {
			Data struct {
				Available   bool   `json:"available"`
				CanGenerate bool   `json:"can_generate"`
				Reason      string `json:"reason"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusOK || response.Data.Available || response.Data.CanGenerate || !strings.Contains(response.Data.Reason, "ADR-056") {
			t.Fatalf("retired controller advertised an available backend: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("generate", func(t *testing.T) {
		job, err := s.queries.CreateRemediationJob(ctx, store.RemediationJob{
			ID: uuid.New(), RepoID: repo.ID, BaseSHA: head, SourceRef: "main", TargetBranch: "main",
			Request: json.RawMessage(`{}`), ExpiresAt: time.Now().Add(time.Hour),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE remediation_jobs SET state='awaiting_selection' WHERE id=$1`, job.ID); err != nil {
			t.Fatal(err)
		}
		request := newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{"revision": job.Revision, "units": []any{}})
		chi.RouteContext(request.Context()).URLParams.Add("repoSlug", repo.Slug)
		chi.RouteContext(request.Context()).URLParams.Add("jobID", job.ID.String())
		w := httptest.NewRecorder()
		s.handleRemediationGenerate(w, request)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "ADR-056") {
			t.Fatalf("generation did not fail explicitly: %d %s", w.Code, w.Body.String())
		}
		after, err := s.queries.GetRemediationJob(ctx, repo.ID, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if after == nil || after.State != "awaiting_selection" || after.Revision != job.Revision {
			t.Fatalf("unapproved backend changed draft state: %+v", after)
		}
	})
}

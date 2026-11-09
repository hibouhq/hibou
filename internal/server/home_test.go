package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

// Home lists the repositories a person opens most, ahead of the recently
// analysed ones; opening a repository in the UI is a visit, an API token
// call is not.
func TestHomeReposRankVisitsFirst(t *testing.T) {
	t.Parallel()
	srv, org, admin, _ := newDiscoveryTestServer(t)
	ctx := context.Background()
	often := createUploadTestRepository(t, srv, org)
	once := createUploadTestRepository(t, srv, org)
	analysed := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(ctx, analysed.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-"+uuid.NewString()[:8], store.SnapshotStatusComplete); err != nil {
		t.Fatal(err)
	}

	request := func(handler http.HandlerFunc, params map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		reqCtx := internalauth.WithUser(req.Context(), admin)
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("provider", "github")
		routeCtx.URLParams.Add("slug", org.Slug)
		for key, value := range params {
			routeCtx.URLParams.Add(key, value)
		}
		req = req.WithContext(context.WithValue(reqCtx, chi.RouteCtxKey, routeCtx))
		recorder := httptest.NewRecorder()
		handler(recorder, req)
		return recorder
	}
	for _, repo := range []*store.Repository{often, once} {
		if got := request(srv.handleGetRepo, map[string]string{"repoSlug": repo.Slug}); got.Code != http.StatusOK {
			t.Fatalf("get repo = %d %s", got.Code, got.Body.String())
		}
	}
	// A visit counts once per 30 minutes; age the first so the next counts.
	if _, err := srv.db.ExecContext(ctx, `UPDATE user_repo_visits SET last_visited_at = now() - interval '1 hour' WHERE repo_id = $1`, often.ID); err != nil {
		t.Fatal(err)
	}
	request(srv.handleGetRepo, map[string]string{"repoSlug": often.Slug})
	request(srv.handleGetRepo, map[string]string{"repoSlug": often.Slug})
	var count int
	if err := srv.db.QueryRowContext(ctx, `SELECT visit_count FROM user_repo_visits WHERE user_id = $1 AND repo_id = $2`, admin.ID, often.ID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("visit count = %d (%v), want 2", count, err)
	}
	tokenReq := httptest.NewRequest(http.MethodGet, "/", nil)
	tokenReq = tokenReq.WithContext(internalauth.WithTokenAuth(internalauth.WithUser(ctx, admin), &internalauth.TokenAuth{KeyID: uuid.New()}))
	srv.recordRepoVisit(tokenReq, analysed.ID)

	home := request(srv.handleHome, nil)
	if home.Code != http.StatusOK {
		t.Fatalf("home = %d %s", home.Code, home.Body.String())
	}
	var body struct {
		Data homeResponse `json:"data"`
	}
	if err := json.Unmarshal(home.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	repos := body.Data.Repos
	if len(repos) != 3 || repos[0].ID != often.ID || repos[1].ID != once.ID || repos[2].ID != analysed.ID {
		t.Fatalf("repos = %+v", repos)
	}
	if !repos[0].Visited || repos[2].Visited {
		t.Fatalf("visited flags = %+v", repos)
	}
}

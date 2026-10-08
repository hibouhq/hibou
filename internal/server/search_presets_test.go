package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

func searchPresetRequest(t *testing.T, user *store.User, method, path, presetID, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	ctx := internalauth.WithUser(req.Context(), user)
	if presetID != "" {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("presetID", presetID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	}
	return req.WithContext(ctx)
}

func decodeSearchPreset(t *testing.T, recorder *httptest.ResponseRecorder) searchPreset {
	t.Helper()
	var envelope struct {
		Data searchPreset `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode preset: %v: %s", err, recorder.Body.String())
	}
	return envelope.Data
}

func listSearchPresets(t *testing.T, srv *Server, user *store.User) []searchPreset {
	t.Helper()
	recorder := httptest.NewRecorder()
	srv.handleListSearchPresets(recorder, searchPresetRequest(t, user, http.MethodGet, "/api/v1/users/me/search-presets?surface=findings", "", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data []searchPreset `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return envelope.Data
}

func TestSearchPresetLifecycleIsPerUser(t *testing.T) {
	t.Parallel()

	srv, _, owner, other := newDiscoveryTestServer(t)

	create := httptest.NewRecorder()
	srv.handleCreateSearchPreset(create, searchPresetRequest(t, owner, http.MethodPost, "/api/v1/users/me/search-presets", "",
		`{"surface":"findings","name":"  Critical deps  ","query":" (severity:critical OR severity:high) AND type:dependency "}`))
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", create.Code, create.Body.String())
	}
	created := decodeSearchPreset(t, create)
	if created.Name != "Critical deps" || created.Query != "(severity:critical OR severity:high) AND type:dependency" {
		t.Fatalf("created = %+v, want trimmed name and query", created)
	}
	if created.ScopeType != "user" || created.Surface != "findings" {
		t.Fatalf("created scope = %q/%q", created.ScopeType, created.Surface)
	}

	if got := listSearchPresets(t, srv, owner); len(got) != 1 || got[0].ID != created.ID {
		t.Fatalf("owner list = %+v", got)
	}
	if got := listSearchPresets(t, srv, other); len(got) != 0 {
		t.Fatalf("another user sees %d presets", len(got))
	}

	foreignUpdate := httptest.NewRecorder()
	srv.handleUpdateSearchPreset(foreignUpdate, searchPresetRequest(t, other, http.MethodPut, "/", created.ID.String(),
		`{"name":"Hijacked","query":"severity:low"}`))
	if foreignUpdate.Code != http.StatusNotFound {
		t.Fatalf("foreign update = %d, want 404", foreignUpdate.Code)
	}
	foreignDelete := httptest.NewRecorder()
	srv.handleDeleteSearchPreset(foreignDelete, searchPresetRequest(t, other, http.MethodDelete, "/", created.ID.String(), ""))
	if foreignDelete.Code != http.StatusNotFound {
		t.Fatalf("foreign delete = %d, want 404", foreignDelete.Code)
	}

	update := httptest.NewRecorder()
	srv.handleUpdateSearchPreset(update, searchPresetRequest(t, owner, http.MethodPut, "/", created.ID.String(),
		`{"name":"Critical deps","query":"severity:critical type:dependency openssl"}`))
	if update.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", update.Code, update.Body.String())
	}
	if updated := decodeSearchPreset(t, update); updated.Query != "severity:critical type:dependency openssl" {
		t.Fatalf("updated query = %q", updated.Query)
	}

	remove := httptest.NewRecorder()
	srv.handleDeleteSearchPreset(remove, searchPresetRequest(t, owner, http.MethodDelete, "/", created.ID.String(), ""))
	if remove.Code != http.StatusNoContent {
		t.Fatalf("delete = %d: %s", remove.Code, remove.Body.String())
	}
	if got := listSearchPresets(t, srv, owner); len(got) != 0 {
		t.Fatalf("list after delete = %+v", got)
	}
}

func TestSearchPresetNamesAreUniqueCaseInsensitivelyPerUser(t *testing.T) {
	t.Parallel()

	srv, _, owner, other := newDiscoveryTestServer(t)
	create := func(user *store.User, name string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		srv.handleCreateSearchPreset(recorder, searchPresetRequest(t, user, http.MethodPost, "/", "",
			`{"surface":"findings","name":"`+name+`","query":"severity:critical"}`))
		return recorder
	}

	if code := create(owner, "Triage").Code; code != http.StatusCreated {
		t.Fatalf("first create = %d", code)
	}
	if code := create(owner, "triage").Code; code != http.StatusConflict {
		t.Fatalf("duplicate name = %d, want 409", code)
	}
	if code := create(other, "Triage").Code; code != http.StatusCreated {
		t.Fatalf("same name for another user = %d, want 201", code)
	}

	second := create(owner, "Second")
	if second.Code != http.StatusCreated {
		t.Fatalf("second create = %d", second.Code)
	}
	rename := httptest.NewRecorder()
	srv.handleUpdateSearchPreset(rename, searchPresetRequest(t, owner, http.MethodPut, "/", decodeSearchPreset(t, second).ID.String(),
		`{"name":"TRIAGE","query":"severity:critical"}`))
	if rename.Code != http.StatusConflict {
		t.Fatalf("rename onto an existing name = %d, want 409", rename.Code)
	}
}

func TestSearchPresetRejectsQueriesTheListWouldRefuse(t *testing.T) {
	t.Parallel()

	srv, _, owner, _ := newDiscoveryTestServer(t)
	for _, body := range []string{
		`{"surface":"findings","name":"x","query":"(severity:critical"}`,
		`{"surface":"findings","name":"x","query":"owner:me"}`,
		`{"surface":"findings","name":"x","query":"   "}`,
		`{"surface":"findings","name":"  ","query":"severity:critical"}`,
		`{"surface":"components","name":"x","query":"severity:critical"}`,
	} {
		recorder := httptest.NewRecorder()
		srv.handleCreateSearchPreset(recorder, searchPresetRequest(t, owner, http.MethodPost, "/", "", body))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", body, recorder.Code)
		}
	}
}

func TestSearchPresetLimitPerUser(t *testing.T) {
	t.Parallel()

	srv, _, owner, _ := newDiscoveryTestServer(t)
	ctx := context.Background()
	for i := range maxSearchPresetsPerSurface {
		if _, err := srv.queries.CreateUserSearchPreset(ctx, owner.ID, store.SearchPresetSurfaceFindings, "preset "+strconv.Itoa(i), "severity:low"); err != nil {
			t.Fatalf("seed preset %d: %v", i, err)
		}
	}
	recorder := httptest.NewRecorder()
	srv.handleCreateSearchPreset(recorder, searchPresetRequest(t, owner, http.MethodPost, "/", "",
		`{"surface":"findings","name":"one too many","query":"severity:low"}`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("over limit = %d, want 400", recorder.Code)
	}
}

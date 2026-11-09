package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestAutolinkReferences(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	ctx := context.Background()

	call := func(method, path string, body any, user *store.User) *httptest.ResponseRecorder {
		var payload bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&payload).Encode(body)
		}
		req := httptest.NewRequest(method, path, &payload)
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("provider", org.Provider)
		routeCtx.URLParams.Add("slug", org.Slug)
		if parts := bytes.Split([]byte(path), []byte("/autolinks/")); len(parts) == 2 {
			routeCtx.URLParams.Add("autolinkID", string(parts[1]))
		}
		req = req.WithContext(context.WithValue(internalauth.WithUser(ctx, user), chi.RouteCtxKey, routeCtx))
		rec := httptest.NewRecorder()
		switch method {
		case http.MethodGet:
			srv.handleListAutolinks(rec, req)
		case http.MethodPost:
			srv.handleCreateAutolink(rec, req)
		default:
			srv.handleDeleteAutolink(rec, req)
		}
		return rec
	}

	base := "/api/v1/orgs/" + org.Provider + "/" + org.Slug + "/autolinks"
	for _, bad := range []autolinkRequest{
		{Prefix: "", URLTemplate: "https://t.example/<num>"},
		{Prefix: "SEC-", URLTemplate: "https://t.example/browse/SEC-7"},
		{Prefix: "SEC-", URLTemplate: "javascript:alert(<num>)"},
	} {
		if rec := call(http.MethodPost, base, bad, admin); rec.Code != http.StatusBadRequest {
			t.Fatalf("create %+v = %d, want 400: %s", bad, rec.Code, rec.Body.String())
		}
	}
	rec := call(http.MethodPost, base, autolinkRequest{Prefix: " SEC- ", URLTemplate: "https://tracker.example/browse/SEC-<num>", Alphanumeric: false}, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	var envelope struct {
		Data dbgen.OrgAutolink `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &envelope)
	created := envelope.Data
	if created.Prefix != "SEC-" || created.Alphanumeric {
		t.Fatalf("created = %+v", created)
	}
	if rec := call(http.MethodPost, base, autolinkRequest{Prefix: "SEC-", URLTemplate: "https://other.example/<num>"}, admin); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate prefix = %d", rec.Code)
	}
	if rec := call(http.MethodGet, base, nil, admin); rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"prefix":"SEC-"`)) {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodDelete, base+"/"+created.ID.String(), nil, admin); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodDelete, base+"/"+created.ID.String(), nil, admin); rec.Code != http.StatusNotFound {
		t.Fatalf("delete again = %d", rec.Code)
	}
}

func TestIncidentExternalReference(t *testing.T) {
	f := newIncidentFixture(t)
	ctx := context.Background()
	inc, _, err := f.srv.openIncident(ctx, incidentOpenInput{
		OrgID: f.org.ID, RepoID: uuid.NullUUID{UUID: f.repo.ID, Valid: true}, Kind: incident.KindExploitedVulnerability,
		SubjectType: incident.SubjectAdvisory, SubjectID: f.advisory.ID.String(), Title: "ref test", Priority: "P2",
		SignalSource: "kev", Regimes: []string{incident.RegimeCRA}, Actor: f.actor,
	})
	if err != nil {
		t.Fatalf("incident: %v", err)
	}
	ref := "  SEC-7 "
	updated, err := f.srv.updateIncidentFields(ctx, inc, f.actor, incidentFieldUpdate{ExternalRef: &ref})
	if err != nil || updated.ExternalRef != "SEC-7" {
		t.Fatalf("external_ref = %q (%v)", updated.ExternalRef, err)
	}
	empty := ""
	updated, err = f.srv.updateIncidentFields(ctx, updated, f.actor, incidentFieldUpdate{ExternalRef: &empty})
	if err != nil || updated.ExternalRef != "" {
		t.Fatalf("cleared external_ref = %q (%v)", updated.ExternalRef, err)
	}
}

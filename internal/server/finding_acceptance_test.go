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
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestFindingAcceptanceLifecycle(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "acceptance-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	fingerprint := uuid.NewString()
	finding, err := srv.queries.CreateVulnerability(context.Background(), dbgen.CreateVulnerabilityParams{
		Type:                   "sast",
		SnapshotID:             snapshot.ID,
		Title:                  "hardcoded secret",
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: "G101",
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 "detected",
		ScannerName:            "gosec",
		Fingerprint:            fingerprint,
	})
	if err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}

	call := func(body map[string]any) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/acceptance", bytes.NewReader(payload))
		req = req.WithContext(internalauth.WithUser(req.Context(), admin))
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("provider", "github")
		routeCtx.URLParams.Add("slug", org.Slug)
		routeCtx.URLParams.Add("repoSlug", repo.Slug)
		routeCtx.URLParams.Add("vulnID", finding.ID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		recorder := httptest.NewRecorder()
		srv.handleSetFindingAcceptance(recorder, req)
		return recorder
	}

	if rec := call(map[string]any{"status": "accepted"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("accept without reason = %d, want 400", rec.Code)
	}
	if rec := call(map[string]any{"status": "accepted", "reason": "risk accepted for demo"}); rec.Code != http.StatusOK {
		t.Fatalf("accept = %d: %s", rec.Code, rec.Body.String())
	}

	acceptances, err := srv.queries.ListActiveFindingAcceptancesByRepo(context.Background(), repo.ID)
	if err != nil || len(acceptances) != 1 {
		t.Fatalf("acceptances = %d (%v), want 1", len(acceptances), err)
	}
	if acceptances[0].Fingerprint != fingerprint || acceptances[0].Reason != "risk accepted for demo" {
		t.Fatalf("unexpected acceptance: %+v", acceptances[0])
	}

	if rec := call(map[string]any{"status": "open"}); rec.Code != http.StatusOK {
		t.Fatalf("reopen = %d: %s", rec.Code, rec.Body.String())
	}
	acceptances, err = srv.queries.ListActiveFindingAcceptancesByRepo(context.Background(), repo.ID)
	if err != nil || len(acceptances) != 0 {
		t.Fatalf("after reopen acceptances = %d (%v), want 0", len(acceptances), err)
	}
}

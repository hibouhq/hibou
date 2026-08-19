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

// seedDisputeTestFinding plants one vulnerability with the given status and
// returns its ID — the dispute endpoints are addressed by vulnID.
func seedDisputeTestFinding(t *testing.T, srv *Server, repo *store.Repository, status, fingerprint string) uuid.UUID {
	t.Helper()

	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, uniqueName(t, "branch"), store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-"+status, store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	vulnerability, err := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type:                   "sast",
		SnapshotID:             snapshot.ID,
		Title:                  "walkdir toctou",
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: "G122",
		OriginalSeverity:       dbgen.SeverityLevelMedium,
		Severity:               dbgen.SeverityLevelMedium,
		Status:                 status,
		ScannerName:            "gosec",
		Fingerprint:            fingerprint,
		Metadata:               json.RawMessage(`{"suppression":{"kind":"inSource","justification":"CI-side scan; no trust boundary"}}`),
	})
	if err != nil {
		t.Fatalf("CreateVulnerability(%s): %v", status, err)
	}
	return vulnerability.ID
}

func callFindingDispute(t *testing.T, srv *Server, user *store.User, org *store.Organization, repoSlug string, vulnID uuid.UUID, method string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/dispute", reader)
	ctx := req.Context()
	if user != nil {
		ctx = internalauth.WithUser(ctx, user)
	}
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "github")
	routeCtx.URLParams.Add("slug", org.Slug)
	routeCtx.URLParams.Add("repoSlug", repoSlug)
	routeCtx.URLParams.Add("vulnID", vulnID.String())
	req = req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, routeCtx))

	recorder := httptest.NewRecorder()
	switch method {
	case http.MethodPut:
		srv.handleSetFindingDispute(recorder, req)
	case http.MethodDelete:
		srv.handleDeleteFindingDispute(recorder, req)
	default:
		t.Fatalf("unsupported method %s", method)
	}
	return recorder
}

// The full ADR-026 recourse loop: dispute a suppressed finding (stored,
// audited into the timeline), then withdraw it (gone again).
func TestFindingDisputeLifecycle(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	fingerprint := uuid.NewString()
	vulnID := seedDisputeTestFinding(t, srv, repo, "suppressed", fingerprint)

	recorder := callFindingDispute(t, srv, admin, org, repo.Slug, vulnID, http.MethodPut, map[string]string{"reason": "no trust-boundary analysis was done"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("dispute = %d: %s", recorder.Code, recorder.Body.String())
	}

	dispute, err := srv.queries.GetFindingDispute(context.Background(), repo.ID, fingerprint)
	if err != nil || dispute == nil {
		t.Fatalf("GetFindingDispute = %+v, %v", dispute, err)
	}
	if dispute.Reason != "no trust-boundary analysis was done" {
		t.Fatalf("reason = %q", dispute.Reason)
	}
	if dispute.DisputedBy == nil || *dispute.DisputedBy != admin.ID {
		t.Fatalf("disputed_by = %v, want %s", dispute.DisputedBy, admin.ID)
	}

	// The decision must land in the finding's timeline as a dispute event with
	// its reason, exactly like an acceptance decision does.
	history := decodeFindingHistory(t, callFindingHistory(t, srv, admin, org, repo.Slug, fingerprint))
	found := false
	for _, event := range history.Events {
		if event.Kind == "disputed" {
			found = true
			if reason, _ := event.Detail["reason"].(string); reason != "no trust-boundary analysis was done" {
				t.Fatalf("disputed event detail = %+v", event.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("no disputed event in timeline: %+v", history.Events)
	}

	recorder = callFindingDispute(t, srv, admin, org, repo.Slug, vulnID, http.MethodDelete, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("withdraw = %d: %s", recorder.Code, recorder.Body.String())
	}
	dispute, err = srv.queries.GetFindingDispute(context.Background(), repo.ID, fingerprint)
	if err != nil {
		t.Fatalf("GetFindingDispute after withdraw: %v", err)
	}
	if dispute != nil {
		t.Fatalf("dispute survived withdrawal: %+v", dispute)
	}
}

// Disputing is only meaningful against a scanner suppression: an open finding
// is already gating, a resolved one has nothing to contest.
func TestFindingDisputeRequiresSuppressedStatus(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	vulnID := seedDisputeTestFinding(t, srv, repo, "detected", uuid.NewString())

	recorder := callFindingDispute(t, srv, admin, org, repo.Slug, vulnID, http.MethodPut, map[string]string{"reason": "should not be accepted"})
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("dispute on detected finding = %d, want 422: %s", recorder.Code, recorder.Body.String())
	}
}

func TestFindingDisputeRequiresReason(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	vulnID := seedDisputeTestFinding(t, srv, repo, "suppressed", uuid.NewString())

	recorder := callFindingDispute(t, srv, admin, org, repo.Slug, vulnID, http.MethodPut, map[string]string{"reason": "   "})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("dispute without reason = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
}

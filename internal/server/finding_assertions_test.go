package server

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func callAssertionHandler(t *testing.T, handler http.HandlerFunc, user *store.User, org *store.Organization, repoSlug, fingerprint, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/assertion", strings.NewReader(body))
	ctx := req.Context()
	if user != nil {
		ctx = internalauth.WithUser(ctx, user)
	}
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "github")
	routeCtx.URLParams.Add("slug", org.Slug)
	routeCtx.URLParams.Add("repoSlug", repoSlug)
	routeCtx.URLParams.Add("fingerprint", fingerprint)
	req = req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, routeCtx))
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	return recorder
}

// A manual finding is carried to every new snapshot of its branch; a member
// who did not file it cannot retract it; resolve closes it now and stops the
// carry; re-assert reopens it.
func TestAssertionLifecycle(t *testing.T) {
	srv, org, admin, member := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	first, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-1", store.SnapshotStatusComplete)
	fingerprint := uuid.NewString()
	if _, err := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type: "manual", SnapshotID: first.ID, Title: "IDOR in /orders", PrimaryIdentifierKind: "manual", PrimaryIdentifierValue: "idor",
		OriginalSeverity: dbgen.SeverityLevelHigh, Severity: dbgen.SeverityLevelHigh, Status: "detected", ScannerName: "manual",
		Fingerprint: fingerprint, Origin: dbgen.FindingOriginHuman, CreatedBy: uuid.NullUUID{UUID: admin.ID, Valid: true},
		FilePath: sql.NullString{String: "orders.go", Valid: true},
	}); err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}

	second, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-2", store.SnapshotStatusComplete)
	srv.reconcileFindingPresence(ctx, second.ID)
	row, ok := presenceByFingerprint(t, srv, second.ID)[fingerprint]
	if !ok || derefString(row.PresenceReason) != presence.ReasonAssertion || row.Status != "detected" {
		t.Fatalf("assertion must be carried and open: %+v (present %v)", row, ok)
	}

	if rec := callAssertionHandler(t, srv.handleRetractFinding, member, org, repo.Slug, fingerprint, `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("retract by a non-filer = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := callAssertionHandler(t, srv.handleResolveFinding, admin, org, repo.Slug, fingerprint, `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("resolve without reason = %d", rec.Code)
	}
	if rec := callAssertionHandler(t, srv.handleResolveFinding, admin, org, repo.Slug, fingerprint, `{"reason":"fixed in #42"}`); rec.Code != http.StatusOK {
		t.Fatalf("resolve = %d: %s", rec.Code, rec.Body.String())
	}
	if row := presenceByFingerprint(t, srv, second.ID)[fingerprint]; row.Status != "resolved" {
		t.Fatalf("resolve must close the latest row now: %+v", row)
	}
	third, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-3", store.SnapshotStatusComplete)
	srv.reconcileFindingPresence(ctx, third.ID)
	if _, ok := presenceByFingerprint(t, srv, third.ID)[fingerprint]; ok {
		t.Fatal("a resolved assertion is no longer carried")
	}

	// Re-assert on the latest snapshot that still holds it reopens it.
	if rec := callAssertionHandler(t, srv.handleReassertFinding, admin, org, repo.Slug, fingerprint, ``); rec.Code != http.StatusOK {
		t.Fatalf("reassert = %d: %s", rec.Code, rec.Body.String())
	}
	assertion, err := srv.queries.GetFindingAssertion(ctx, repo.ID, fingerprint)
	if err != nil || assertion == nil || assertion.ClosedKind != "" || assertion.LastConfirmedAt == nil {
		t.Fatalf("assertion after reassert = %+v, %v", assertion, err)
	}
	if row, ok := presenceByFingerprint(t, srv, third.ID)[fingerprint]; !ok || row.Status != "detected" {
		t.Fatalf("reopened assertion must be open on the latest snapshot: %+v (present %v)", row, ok)
	}

	// Scanner findings are not assertions.
	seedPresenceFinding(t, srv, third.ID, "sast", "gosec", "scanner-fp", "a.go")
	if rec := callAssertionHandler(t, srv.handleResolveFinding, admin, org, repo.Slug, "scanner-fp", `{"reason":"x"}`); rec.Code != http.StatusConflict {
		t.Fatalf("resolve on a scanner finding = %d", rec.Code)
	}
}

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

	"github.com/hibouhq/hibou/internal/apitoken"
	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestFindingAcceptanceTokenScope(t *testing.T) {
	t.Parallel()

	srv, org, admin, repo, snapshotID := newBatchTriageFixture(t)
	findingID, _ := seedTriageFindingWithID(t, srv, snapshotID, "G101")
	call := func(tokenAuth *internalauth.TokenAuth) *httptest.ResponseRecorder {
		payload, err := json.Marshal(map[string]any{"status": "accepted", "reason_kind": "risk_accepted", "reason": "test scope"})
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		req := httptest.NewRequest(http.MethodPut, "/acceptance", bytes.NewReader(payload))
		ctx := internalauth.WithUser(req.Context(), admin)
		ctx = internalauth.WithTokenAuth(ctx, tokenAuth)
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("provider", "github")
		routeCtx.URLParams.Add("slug", org.Slug)
		routeCtx.URLParams.Add("repoSlug", repo.Slug)
		routeCtx.URLParams.Add("vulnID", findingID.String())
		req = req.WithContext(context.WithValue(ctx, chi.RouteCtxKey, routeCtx))
		recorder := httptest.NewRecorder()
		srv.handleSetFindingAcceptance(recorder, req)
		return recorder
	}

	readOnly := &internalauth.TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:   org.Slug,
			Repos: apitoken.RepoSelector{Mode: apitoken.RepoAll},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{
				apitoken.CapTriage: apitoken.AccessRead,
			},
		},
	}
	if recorder := call(readOnly); recorder.Code != http.StatusForbidden {
		t.Fatalf("scoped read-only acceptance = %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := call(&internalauth.TokenAuth{}); recorder.Code != http.StatusOK {
		t.Fatalf("unscoped acceptance = %d: %s", recorder.Code, recorder.Body.String())
	}
}

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
	if rec := call(map[string]any{"status": "accepted", "reason": "no kind"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("accept without reason_kind = %d, want 400", rec.Code)
	}
	if rec := call(map[string]any{"status": "accepted", "reason_kind": "risk_accepted", "reason": "risk accepted for demo", "labels": []string{"Demo", "demo", " q3-review "}}); rec.Code != http.StatusOK {
		t.Fatalf("accept = %d: %s", rec.Code, rec.Body.String())
	}

	acceptances, err := srv.queries.ListActiveFindingAcceptancesByRepo(context.Background(), repo.ID)
	if err != nil || len(acceptances) != 1 {
		t.Fatalf("acceptances = %d (%v), want 1", len(acceptances), err)
	}
	if acceptances[0].Fingerprint != fingerprint || acceptances[0].Reason != "risk accepted for demo" {
		t.Fatalf("unexpected acceptance: %+v", acceptances[0])
	}
	if acceptances[0].ReasonKind != "risk_accepted" {
		t.Fatalf("reason_kind = %q, want risk_accepted", acceptances[0].ReasonKind)
	}
	if len(acceptances[0].Labels) != 2 || acceptances[0].Labels[0] != "demo" || acceptances[0].Labels[1] != "q3-review" {
		t.Fatalf("labels = %v, want normalized deduped [demo q3-review]", acceptances[0].Labels)
	}

	if rec := call(map[string]any{"status": "open"}); rec.Code != http.StatusOK {
		t.Fatalf("reopen = %d: %s", rec.Code, rec.Body.String())
	}
	acceptances, err = srv.queries.ListActiveFindingAcceptancesByRepo(context.Background(), repo.ID)
	if err != nil || len(acceptances) != 0 {
		t.Fatalf("after reopen acceptances = %d (%v), want 0", len(acceptances), err)
	}
}

// seedTriageFinding creates one finding on a repo and returns its fingerprint.
func seedTriageFinding(t *testing.T, srv *Server, snapshotID uuid.UUID, rule string) string {
	_, fingerprint := seedTriageFindingWithID(t, srv, snapshotID, rule)
	return fingerprint
}

func seedTriageFindingWithID(t *testing.T, srv *Server, snapshotID uuid.UUID, rule string) (uuid.UUID, string) {
	t.Helper()
	fingerprint := uuid.NewString()
	finding, err := srv.queries.CreateVulnerability(context.Background(), dbgen.CreateVulnerabilityParams{
		Type:                   "sast",
		SnapshotID:             snapshotID,
		Title:                  "finding " + rule,
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: rule,
		OriginalSeverity:       dbgen.SeverityLevelLow,
		Severity:               dbgen.SeverityLevelLow,
		Status:                 "detected",
		ScannerName:            "gosec",
		Fingerprint:            fingerprint,
	})
	if err != nil {
		t.Fatalf("CreateVulnerability(%s): %v", rule, err)
	}
	return finding.ID, fingerprint
}

func newBatchTriageFixture(t *testing.T) (*Server, *store.Organization, *store.User, *store.Repository, uuid.UUID) {
	t.Helper()
	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uuid.NewString(), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	return srv, org, admin, repo, snapshot.ID
}

func callBatchTriage(t *testing.T, srv *Server, org *store.Organization, admin *store.User, repo *store.Repository, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/acceptance", bytes.NewReader(payload))
	req = req.WithContext(internalauth.WithUser(req.Context(), admin))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "github")
	routeCtx.URLParams.Add("slug", org.Slug)
	routeCtx.URLParams.Add("repoSlug", repo.Slug)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	recorder := httptest.NewRecorder()
	srv.handleBatchFindingAcceptance(recorder, req)
	return recorder
}

// The point of the batch endpoint: filter, select all, decide once with one
// shared reason.
func TestBatchFindingAcceptanceAppliesOneReasonToMany(t *testing.T) {
	t.Parallel()
	srv, org, admin, repo, snapshotID := newBatchTriageFixture(t)
	fingerprints := []string{
		seedTriageFinding(t, srv, snapshotID, "G101"),
		seedTriageFinding(t, srv, snapshotID, "G102"),
		seedTriageFinding(t, srv, snapshotID, "G103"),
	}

	rec := callBatchTriage(t, srv, org, admin, repo, map[string]any{
		"fingerprints": fingerprints,
		"status":       "accepted",
		"reason_kind":  "false_positive",
		"reason":       "test fixtures, not production code",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("batch accept = %d: %s", rec.Code, rec.Body.String())
	}

	acceptances, err := srv.queries.ListActiveFindingAcceptancesByRepo(context.Background(), repo.ID)
	if err != nil {
		t.Fatalf("ListActiveFindingAcceptancesByRepo: %v", err)
	}
	if len(acceptances) != len(fingerprints) {
		t.Fatalf("stored %d acceptances, want %d", len(acceptances), len(fingerprints))
	}
	for _, acceptance := range acceptances {
		if acceptance.Reason != "test fixtures, not production code" || acceptance.ReasonKind != "false_positive" {
			t.Fatalf("acceptance = %+v, want the shared reason and false_positive kind", acceptance)
		}
	}

	// Reopening the same batch must clear every row.
	if rec := callBatchTriage(t, srv, org, admin, repo, map[string]any{
		"fingerprints": fingerprints,
		"status":       "open",
	}); rec.Code != http.StatusOK {
		t.Fatalf("batch reopen = %d: %s", rec.Code, rec.Body.String())
	}
	remaining, err := srv.queries.ListActiveFindingAcceptancesByRepo(context.Background(), repo.ID)
	if err != nil {
		t.Fatalf("ListActiveFindingAcceptancesByRepo after reopen: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("remaining acceptances = %d, want 0", len(remaining))
	}
}

func TestBatchFindingAcceptanceValidation(t *testing.T) {
	t.Parallel()
	srv, org, admin, repo, snapshotID := newBatchTriageFixture(t)
	fingerprint := seedTriageFinding(t, srv, snapshotID, "G201")

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"no reason", map[string]any{"fingerprints": []string{fingerprint}, "status": "accepted"}, http.StatusBadRequest},
		{"bad status", map[string]any{"fingerprints": []string{fingerprint}, "status": "whatever", "reason": "x"}, http.StatusBadRequest},
		{"no fingerprints", map[string]any{"fingerprints": []string{}, "status": "accepted", "reason": "x"}, http.StatusBadRequest},
		{"blank fingerprints only", map[string]any{"fingerprints": []string{"", "  "}, "status": "accepted", "reason": "x"}, http.StatusBadRequest},
		{"past expiry", map[string]any{"fingerprints": []string{fingerprint}, "status": "accepted", "reason": "x", "expires_at": "2020-01-01T00:00:00Z"}, http.StatusBadRequest},
		// Reopen needs no reason: removing a suppression is not a decision that
		// needs justifying.
		{"reopen without reason", map[string]any{"fingerprints": []string{fingerprint}, "status": "open"}, http.StatusOK},
	}
	for _, testCase := range cases {
		if rec := callBatchTriage(t, srv, org, admin, repo, testCase.body); rec.Code != testCase.want {
			t.Fatalf("%s = %d, want %d: %s", testCase.name, rec.Code, testCase.want, rec.Body.String())
		}
	}
}

func TestBatchFindingAcceptanceRejectsOversizedBatch(t *testing.T) {
	t.Parallel()
	srv, org, admin, repo, snapshotID := newBatchTriageFixture(t)
	fingerprint := seedTriageFinding(t, srv, snapshotID, "G301")

	oversized := make([]string, 0, maxBatchAcceptance+1)
	oversized = append(oversized, fingerprint)
	for len(oversized) <= maxBatchAcceptance {
		oversized = append(oversized, uuid.NewString())
	}

	rec := callBatchTriage(t, srv, org, admin, repo, map[string]any{
		"fingerprints": oversized,
		"status":       "accepted",
		"reason_kind":  "risk_accepted",
		"reason":       "too many",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch = %d, want 400", rec.Code)
	}
}

// A caller must not be able to suppress another repository's findings by
// guessing fingerprints; unknown ones are skipped and counted.
func TestBatchFindingAcceptanceSkipsForeignFingerprints(t *testing.T) {
	t.Parallel()
	srv, org, admin, repo, snapshotID := newBatchTriageFixture(t)
	mine := seedTriageFinding(t, srv, snapshotID, "G401")
	foreign := uuid.NewString()

	rec := callBatchTriage(t, srv, org, admin, repo, map[string]any{
		"fingerprints": []string{mine, foreign},
		"status":       "accepted",
		"reason_kind":  "risk_accepted",
		"reason":       "mixed batch",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("mixed batch = %d: %s", rec.Code, rec.Body.String())
	}

	var response struct {
		Data batchAcceptanceResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Data.Applied != 1 || response.Data.Skipped != 1 {
		t.Fatalf("applied/skipped = %d/%d, want 1/1", response.Data.Applied, response.Data.Skipped)
	}

	acceptances, err := srv.queries.ListActiveFindingAcceptancesByRepo(context.Background(), repo.ID)
	if err != nil {
		t.Fatalf("list acceptances: %v", err)
	}
	if len(acceptances) != 1 || acceptances[0].Fingerprint != mine {
		t.Fatalf("acceptances = %+v, want only the owned fingerprint", acceptances)
	}
}

// The discrete acceptance filter (ADR-023): open / accepted / by reason kind,
// applied server-side on the acceptance join in list, count and facets.
func TestListVulnerabilitiesAcceptanceFilter(t *testing.T) {
	t.Parallel()

	srv, org, admin, repo, snapshotID := newBatchTriageFixture(t)
	accepted := seedTriageFinding(t, srv, snapshotID, "RULE-ACCEPTED")
	seedTriageFinding(t, srv, snapshotID, "RULE-OPEN")

	rec := callBatchTriage(t, srv, org, admin, repo, map[string]any{
		"fingerprints": []string{accepted},
		"status":       "accepted",
		"reason_kind":  "false_positive",
		"reason":       "scanner matches test fixture",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("accept = %d: %s", rec.Code, rec.Body.String())
	}

	list := func(filter string) []store.Vulnerability {
		t.Helper()
		rows, total, err := srv.queries.ListVulnerabilitiesBySnapshot(context.Background(), snapshotID, store.VulnerabilityListOptions{
			Acceptance: filter,
			Limit:      50,
		})
		if err != nil {
			t.Fatalf("list acceptance=%q: %v", filter, err)
		}
		if total != len(rows) {
			t.Fatalf("acceptance=%q total = %d, rows = %d", filter, total, len(rows))
		}
		return rows
	}

	if rows := list(""); len(rows) != 2 {
		t.Fatalf("no filter = %d rows, want 2", len(rows))
	}
	if rows := list("open"); len(rows) != 1 || rows[0].Fingerprint == accepted {
		t.Fatalf("open = %+v, want only the untriaged finding", rows)
	}
	rows := list("accepted")
	if len(rows) != 1 || rows[0].Fingerprint != accepted {
		t.Fatalf("accepted = %+v, want only the accepted finding", rows)
	}
	if rows[0].Acceptance == nil || rows[0].Acceptance.ReasonKind != "false_positive" {
		t.Fatalf("acceptance projection = %+v, want reason_kind=false_positive", rows[0].Acceptance)
	}
	if rows := list("false_positive"); len(rows) != 1 || rows[0].Fingerprint != accepted {
		t.Fatalf("false_positive = %+v, want only the accepted finding", rows)
	}
	if rows := list("risk_accepted"); len(rows) != 0 {
		t.Fatalf("risk_accepted = %d rows, want 0", len(rows))
	}
	// Unknown values are dropped, not silently matched to nothing.
	if rows := list("bogus"); len(rows) != 2 {
		t.Fatalf("bogus filter = %d rows, want 2 (filter ignored)", len(rows))
	}

	facets, err := srv.queries.FacetVulnerabilitiesBySnapshot(context.Background(), snapshotID, store.VulnerabilityListOptions{Acceptance: "open"})
	if err != nil {
		t.Fatalf("facets acceptance=open: %v", err)
	}
	if facets.Severity["low"] != 1 {
		t.Fatalf("facets severity[low] = %d, want 1 (acceptance filter respected)", facets.Severity["low"])
	}
}

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/kev"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type findingHistoryFixture struct {
	srv         *Server
	org         *store.Organization
	admin       *store.User
	member      *store.User
	repo        *store.Repository
	otherRepo   *store.Repository
	fingerprint string
}

func newFindingHistoryFixture(t *testing.T) findingHistoryFixture {
	t.Helper()

	srv, org, admin, member := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	otherRepo := createUploadTestRepository(t, srv, org)
	fingerprint := uuid.NewString()

	// Two snapshots on main: detected, then resolved. That series IS the scan
	// history the endpoint derives its timeline from.
	seedHistoryFinding(t, srv, repo, "main", "sha-detected", fingerprint, "detected")
	seedHistoryFinding(t, srv, repo, "main", "sha-resolved", fingerprint, "resolved")

	return findingHistoryFixture{srv: srv, org: org, admin: admin, member: member, repo: repo, otherRepo: otherRepo, fingerprint: fingerprint}
}

func seedHistoryFinding(t *testing.T, srv *Server, repo *store.Repository, refName, sha, fingerprint, status string) {
	t.Helper()

	ctx := context.Background()
	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, refName, store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByName: %v", err)
	}
	if ref == nil {
		ref, err = srv.queries.CreateRef(ctx, repo.ID, refName, store.RefTypeBranch, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreateRef: %v", err)
		}
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, sha, store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, err := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type:                   "sast",
		SnapshotID:             snapshot.ID,
		Title:                  "hardcoded credential",
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: "G101",
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 status,
		ScannerName:            "gosec",
		Fingerprint:            fingerprint,
	}); err != nil {
		t.Fatalf("CreateVulnerability(%s): %v", status, err)
	}
}

// seedHistoryFindingWithReachability is seedHistoryFinding plus a call-graph
// verdict on the observation, for timeline reachability-transition tests.
func seedHistoryFindingWithReachability(t *testing.T, srv *Server, repo *store.Repository, refName, sha, fingerprint, status, reachability string) {
	t.Helper()

	ctx := context.Background()
	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, refName, store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByName: %v", err)
	}
	if ref == nil {
		ref, err = srv.queries.CreateRef(ctx, repo.ID, refName, store.RefTypeBranch, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreateRef: %v", err)
		}
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, sha, store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	params := dbgen.CreateVulnerabilityParams{
		Type:                   "dependency",
		SnapshotID:             snapshot.ID,
		Title:                  "vulnerable dependency",
		PrimaryIdentifierKind:  "advisory",
		PrimaryIdentifierValue: "CVE-2026-0001",
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 status,
		ScannerName:            "trivy",
		Fingerprint:            fingerprint,
	}
	if reachability != "" {
		params.Reachability = dbgen.NullReachability{Reachability: dbgen.Reachability(reachability), Valid: true}
	}
	if _, err := srv.queries.CreateVulnerability(ctx, params); err != nil {
		t.Fatalf("CreateVulnerability(%s/%s): %v", status, reachability, err)
	}
}

// seedHistoryAuditLog writes one raw audit entry, so a test can plant exactly
// the row it wants the endpoint to return — or to refuse to return.
func seedHistoryAuditLog(t *testing.T, srv *Server, orgID uuid.UUID, repoID, action string, context map[string]any) {
	t.Helper()

	body, err := json.Marshal(context)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if _, err := srv.queries.CreateAuditLog(t.Context(), dbgen.CreateAuditLogParams{
		ActorType:    "user",
		ActorDisplay: "Alice Admin",
		Action:       action,
		ResourceType: "repository",
		ResourceID:   repoID,
		OrgID:        uuid.NullUUID{UUID: orgID, Valid: true},
		Context:      body,
		IpAddress:    "203.0.113.9",
		UserAgent:    "hibou-web/2.0",
	}); err != nil {
		t.Fatalf("CreateAuditLog: %v", err)
	}
}

func callFindingHistory(t *testing.T, srv *Server, user *store.User, org *store.Organization, repoSlug, fingerprint string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/history", nil)
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
	srv.handleGetFindingHistory(recorder, req)
	return recorder
}

func decodeFindingHistory(t *testing.T, recorder *httptest.ResponseRecorder) findingHistoryResponse {
	t.Helper()

	if recorder.Code != http.StatusOK {
		t.Fatalf("history = %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data findingHistoryResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return envelope.Data
}

// The timeline merges what the scanners saw with what humans decided, newest
// first, and names each change the way a reader thinks about it.
func TestFindingHistoryMergesScanAndTriage(t *testing.T) {
	t.Parallel()

	fixture := newFindingHistoryFixture(t)
	seedHistoryAuditLog(t, fixture.srv, fixture.org.ID, fixture.repo.ID.String(), "finding.acceptance", map[string]any{
		"fingerprint": fixture.fingerprint,
		"status":      "risk_accepted",
		"reason":      "mitigated at the gateway",
		"labels":      []string{"q4-review"},
		"expires_at":  "2027-01-01T00:00:00Z",
	})

	history := decodeFindingHistory(t, callFindingHistory(t, fixture.srv, fixture.admin, fixture.org, fixture.repo.Slug, fixture.fingerprint))

	kinds := make([]string, 0, len(history.Events))
	for _, event := range history.Events {
		kinds = append(kinds, event.Source+":"+event.Kind)
	}
	// Newest first: the acceptance, then resolved, then the first detection.
	want := []string{"activity:accepted", "scan:resolved", "scan:first_detected"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", kinds, want)
	}
	if history.Truncated {
		t.Fatal("truncated = true for a three-event history")
	}

	// The creation point closes the timeline and carries a real date, so
	// "when did this appear" is answerable without leaving the drawer.
	detection := history.Events[2]
	if detection.RefName != "main" || detection.CommitSHA != "sha-detected" || detection.From != "" || detection.To != "detected" {
		t.Fatalf("creation event = %+v", detection)
	}
	if detection.At.IsZero() || detection.At.After(history.Events[1].At) {
		t.Fatalf("creation event is not the oldest: %+v", detection)
	}
	if history.Events[1].From != "detected" || history.Events[1].To != "resolved" {
		t.Fatalf("resolution event = %+v", history.Events[1])
	}
	if reason, _ := history.Events[0].Detail["reason"].(string); reason != "mitigated at the gateway" {
		t.Fatalf("acceptance detail = %+v", history.Events[0].Detail)
	}
	if history.Events[0].ActorDisplay != "Alice Admin" {
		t.Fatalf("actor = %q", history.Events[0].ActorDisplay)
	}
	// The whole decision travels, not just the fact that one was taken: an
	// acceptance that expires is a different decision from one that does not.
	if expires, _ := history.Events[0].Detail["expires_at"].(string); expires != "2027-01-01T00:00:00Z" {
		t.Fatalf("expiry = %q", expires)
	}
	labels, _ := history.Events[0].Detail["labels"].([]any)
	if len(labels) != 1 || labels[0] != "q4-review" {
		t.Fatalf("labels = %+v", history.Events[0].Detail["labels"])
	}
}

func TestFindingHistoryIncludesKEVCatalogEvents(t *testing.T) {
	t.Parallel()

	fixture := newFindingHistoryFixture(t)
	ctx := t.Context()
	cveID := "CVE-" + strings.ToUpper(uuid.NewString())
	canonicalID := "GHSA-" + uuid.NewString()
	advisory, err := fixture.srv.queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{
		CanonicalID: canonicalID, Title: "history test", Severity: dbgen.SeverityLevelHigh,
	})
	if err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}
	if err := fixture.srv.queries.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{AdvisoryID: advisory.ID, Alias: cveID}); err != nil {
		t.Fatalf("UpsertAdvisoryAlias: %v", err)
	}
	seedHistoryKEVFinding(t, fixture.srv, fixture.repo, fixture.fingerprint, advisory.ID, cveID)
	for _, event := range []store.AdvisoryEvent{
		{CVEID: cveID, Kind: store.EventKEVListed, OccurredAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), Detail: json.RawMessage(`{"source":"history-cisa"}`)},
		{CVEID: cveID, Kind: store.EventKEVListed, OccurredAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), Detail: json.RawMessage(`{"source":"history-cisa"}`)},
		{CVEID: cveID, Kind: store.EventKEVDelisted, OccurredAt: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC), Detail: json.RawMessage(`{"source":"history-euvd"}`)},
		{CVEID: "CVE-2099-41999", Kind: store.EventKEVListed, OccurredAt: time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC), Detail: json.RawMessage(`{"source":"other"}`)},
	} {
		if err := fixture.srv.queries.RecordAdvisoryEvent(ctx, event); err != nil {
			t.Fatalf("RecordAdvisoryEvent: %v", err)
		}
	}
	seedKEVEntries(t, fixture.srv, "history-cisa", []kev.Entry{{CVEID: cveID, DateAdded: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)}})
	seedKEVEntries(t, fixture.srv, "history-euvd", []kev.Entry{{CVEID: cveID, DateAdded: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}})
	seedKEVEntries(t, fixture.srv, "history-undated", []kev.Entry{{CVEID: cveID}})

	history := decodeFindingHistory(t, callFindingHistory(t, fixture.srv, fixture.admin, fixture.org, fixture.repo.Slug, fixture.fingerprint))
	got := map[string]findingHistoryEvent{}
	for _, event := range history.Events {
		if event.Source == "advisory" {
			got[event.Kind+":"+event.Detail["source"].(string)] = event
		}
	}
	if len(got) != 3 || got["kev_listed:history-cisa"].At.IsZero() || got["kev_delisted:history-euvd"].At.IsZero() {
		t.Fatalf("advisory events = %+v", got)
	}
	if listed := got["kev_listed:history-cisa"]; listed.At.Format("2006-01-02") != "2025-02-01" {
		t.Fatalf("stored listing = %+v", listed)
	}
	if listed := got["kev_listed:history-euvd"]; listed.At.Format("2006-01-02") != "2025-01-01" {
		t.Fatalf("source-specific seed anchor = %+v", listed)
	}
	if _, ok := got["kev_listed:history-undated"]; ok {
		t.Fatalf("undated catalog row fabricated listing event: %+v", got)
	}
}

func TestFindingHistoryKEVSeedDelistRetainsListingDate(t *testing.T) {
	t.Parallel()

	fixture := newFindingHistoryFixture(t)
	ctx := t.Context()
	cveID := "CVE-" + strings.ToUpper(uuid.NewString())
	undatedCVEID := "CVE-" + strings.ToUpper(uuid.NewString())
	advisory, err := fixture.srv.queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{
		CanonicalID: "GHSA-" + uuid.NewString(), Title: "history delist test", Severity: dbgen.SeverityLevelHigh,
	})
	if err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}
	if err := fixture.srv.queries.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{AdvisoryID: advisory.ID, Alias: cveID}); err != nil {
		t.Fatalf("UpsertAdvisoryAlias: %v", err)
	}
	seedHistoryKEVFinding(t, fixture.srv, fixture.repo, fixture.fingerprint, advisory.ID, cveID)
	source := "history-durable-" + uuid.NewString()
	entries := []kev.Entry{
		{CVEID: cveID, DateAdded: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)},
		{CVEID: undatedCVEID},
	}
	seedKEVEntries(t, fixture.srv, source, entries)
	fixture.srv.recordKEVEvents(ctx, source, kev.Catalog{Entries: entries}, store.KEVReplaceResult{Added: []string{cveID, undatedCVEID}})
	if _, err := fixture.srv.db.ExecContext(ctx, `DELETE FROM kev_entries WHERE source = $1 AND cve_id = ANY($2::text[])`, source, []string{cveID, undatedCVEID}); err != nil {
		t.Fatalf("remove KEV fixture entries: %v", err)
	}
	diff := store.KEVReplaceResult{
		Removed: []string{cveID, undatedCVEID},
		RemovedDateAdded: map[string]time.Time{
			cveID: entries[0].DateAdded,
		},
	}
	if dateAdded := diff.RemovedDateAdded[cveID]; dateAdded.Format("2006-01-02") != "2025-01-02" {
		t.Fatalf("removed date added = %s", dateAdded)
	}
	fixture.srv.recordKEVEvents(ctx, source, kev.Catalog{}, diff)

	history := decodeFindingHistory(t, callFindingHistory(t, fixture.srv, fixture.admin, fixture.org, fixture.repo.Slug, fixture.fingerprint))
	var listings, delistings int
	for _, event := range history.Events {
		if event.Source != "advisory" || event.Detail["source"] != source {
			continue
		}
		switch event.Kind {
		case "kev_listed":
			listings++
			if event.At.Format("2006-01-02") != "2025-01-02" {
				t.Fatalf("listing = %+v", event)
			}
		case "kev_delisted":
			delistings++
		}
	}
	if listings != 1 || delistings != 1 {
		t.Fatalf("history durable KEV events = %+v", history.Events)
	}
	events, err := fixture.srv.queries.ListKEVAdvisoryEventsForCVEs(ctx, []string{cveID, undatedCVEID}, 10)
	if err != nil {
		t.Fatalf("ListKEVAdvisoryEventsForCVEs: %v", err)
	}
	foundUndatedDelist := false
	for _, event := range events {
		if event.CveID != undatedCVEID {
			continue
		}
		foundUndatedDelist = true
		var detail map[string]string
		if err := json.Unmarshal(event.Detail, &detail); err != nil {
			t.Fatalf("decode undated delist detail: %v", err)
		}
		if detail["date_added"] != "" {
			t.Fatalf("undated delist fabricated date: %s", event.Detail)
		}
	}
	if !foundUndatedDelist {
		t.Fatal("missing undated delist event")
	}
}

func TestFindingHistoryKEVBareIdentifierOnlyForComponentFindings(t *testing.T) {
	t.Parallel()

	fixture := newFindingHistoryFixture(t)
	seedHistoryBareKEVFinding(t, fixture.srv, fixture.repo, fixture.fingerprint, "dependency", "CVE-2099-42001")
	if err := fixture.srv.queries.RecordAdvisoryEvent(t.Context(), store.AdvisoryEvent{CVEID: "CVE-2099-42001", Kind: store.EventKEVListed, OccurredAt: time.Now().UTC(), Detail: json.RawMessage(`{"source":"cisa"}`)}); err != nil {
		t.Fatalf("RecordAdvisoryEvent: %v", err)
	}
	history := decodeFindingHistory(t, callFindingHistory(t, fixture.srv, fixture.admin, fixture.org, fixture.repo.Slug, fixture.fingerprint))
	if !findingHistoryHasEvent(history, "advisory", "kev_listed", "cisa") {
		t.Fatalf("dependency history = %+v", history.Events)
	}

	other := newFindingHistoryFixture(t)
	seedHistoryBareKEVFinding(t, other.srv, other.repo, other.fingerprint, "sast", "CVE-2099-42001")
	history = decodeFindingHistory(t, callFindingHistory(t, other.srv, other.admin, other.org, other.repo.Slug, other.fingerprint))
	if findingHistoryHasEvent(history, "advisory", "kev_listed", "cisa") {
		t.Fatalf("sast history leaked bare identifier event: %+v", history.Events)
	}
}

func seedHistoryKEVFinding(t *testing.T, srv *Server, repo *store.Repository, fingerprint string, advisoryID uuid.UUID, identifier string) {
	t.Helper()
	seedHistoryBareKEVFinding(t, srv, repo, fingerprint, "dependency", identifier)
	if _, err := srv.db.ExecContext(t.Context(), `UPDATE vulnerabilities SET advisory_id = $1 WHERE repo_id = $2 AND fingerprint = $3`, advisoryID, repo.ID, fingerprint); err != nil {
		t.Fatalf("attach advisory: %v", err)
	}
}

func seedHistoryBareKEVFinding(t *testing.T, srv *Server, repo *store.Repository, fingerprint, findingType, identifier string) {
	t.Helper()
	ctx := t.Context()
	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, "kev-history", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	if ref == nil {
		ref, err = srv.queries.CreateRef(ctx, repo.ID, "kev-history", store.RefTypeBranch, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreateRef: %v", err)
		}
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, "kev-history-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, err := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{Type: findingType, SnapshotID: snapshot.ID, Title: "kev finding", PrimaryIdentifierKind: "advisory", PrimaryIdentifierValue: identifier, OriginalSeverity: dbgen.SeverityLevelHigh, Severity: dbgen.SeverityLevelHigh, Status: "detected", ScannerName: "trivy", Fingerprint: fingerprint}); err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}
}

func findingHistoryHasEvent(history findingHistoryResponse, source, kind, catalog string) bool {
	for _, event := range history.Events {
		if event.Source == source && event.Kind == kind && event.Detail["source"] == catalog {
			return true
		}
	}
	return false
}

// The endpoint is a keyhole onto the audit log, not a second door into it: an
// entry belonging to another finding, another repository, or an action outside
// the finding allowlist must never come back through it.
func TestFindingHistoryOnlyReturnsThisFindingsEvents(t *testing.T) {
	t.Parallel()

	fixture := newFindingHistoryFixture(t)
	orgID := fixture.org.ID

	seedHistoryAuditLog(t, fixture.srv, orgID, fixture.repo.ID.String(), "finding.acceptance", map[string]any{
		"fingerprint": fixture.fingerprint,
		"status":      "risk_accepted",
		"reason":      "keep me",
	})
	// Same repo, different finding.
	seedHistoryAuditLog(t, fixture.srv, orgID, fixture.repo.ID.String(), "finding.acceptance", map[string]any{
		"fingerprint": uuid.NewString(),
		"status":      "risk_accepted",
		"reason":      "other finding",
	})
	// Same fingerprint, different repository.
	seedHistoryAuditLog(t, fixture.srv, orgID, fixture.otherRepo.ID.String(), "finding.acceptance", map[string]any{
		"fingerprint": fixture.fingerprint,
		"status":      "risk_accepted",
		"reason":      "other repo",
	})
	// Same fingerprint and repo, but an admin-only action that happens to carry
	// a fingerprint: outside the allowlist, so it stays invisible.
	seedHistoryAuditLog(t, fixture.srv, orgID, fixture.repo.ID.String(), "token.create", map[string]any{
		"fingerprint": fixture.fingerprint,
		"token_name":  "ci-bot",
		"reason":      "token secret",
	})

	history := decodeFindingHistory(t, callFindingHistory(t, fixture.srv, fixture.admin, fixture.org, fixture.repo.Slug, fixture.fingerprint))

	activity := 0
	for _, event := range history.Events {
		if event.Source != "activity" {
			continue
		}
		activity++
		if reason, _ := event.Detail["reason"].(string); reason != "keep me" {
			t.Fatalf("leaked event: %+v", event)
		}
	}
	if activity != 1 {
		t.Fatalf("activity events = %d, want 1", activity)
	}
}

// A member may read the history of a finding; the admin-only context an audit
// entry carries (token identity, IP, user agent, the acting user's id) must not
// travel with it.
func TestFindingHistoryRedactsAdminOnlyContext(t *testing.T) {
	t.Parallel()

	fixture := newFindingHistoryFixture(t)
	seedHistoryAuditLog(t, fixture.srv, fixture.org.ID, fixture.repo.ID.String(), "finding.acceptance", map[string]any{
		"fingerprint":      fixture.fingerprint,
		"status":           "risk_accepted",
		"reason":           "mitigated",
		"token_id":         uuid.NewString(),
		"token_name":       "ci-bot",
		"token_owner_id":   uuid.NewString(),
		"token_owner_type": "org",
		"acting_user_id":   uuid.NewString(),
		"repo_id":          fixture.repo.ID.String(),
	})

	recorder := callFindingHistory(t, fixture.srv, fixture.member, fixture.org, fixture.repo.Slug, fixture.fingerprint)
	body := recorder.Body.String()
	history := decodeFindingHistory(t, recorder)

	for _, forbidden := range []string{"token_id", "token_owner_id", "token_owner_type", "acting_user_id", "ip_address", "user_agent", "203.0.113.9", "hibou-web/2.0"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaks %q: %s", forbidden, body)
		}
	}
	if len(history.Events) == 0 {
		t.Fatal("member sees no events")
	}
	if reason, _ := history.Events[0].Detail["reason"].(string); reason != "mitigated" {
		t.Fatalf("member lost the triage detail: %+v", history.Events[0].Detail)
	}
}

func TestFindingHistoryAccess(t *testing.T) {
	t.Parallel()

	fixture := newFindingHistoryFixture(t)

	outsider, err := fixture.srv.queries.CreateUser(t.Context(), uniqueName(t, "outsider")+"@example.com", "Outsider", "github", uniqueName(t, "outsider-user"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cases := []struct {
		name        string
		user        *store.User
		repoSlug    string
		fingerprint string
		want        int
	}{
		{"anonymous", nil, fixture.repo.Slug, fixture.fingerprint, http.StatusUnauthorized},
		{"non-member", outsider, fixture.repo.Slug, fixture.fingerprint, http.StatusNotFound},
		// The whole point of the endpoint: a viewer, who cannot open the
		// org-wide audit log, can still see one finding's history.
		{"viewer member", fixture.member, fixture.repo.Slug, fixture.fingerprint, http.StatusOK},
		{"unknown fingerprint", fixture.admin, fixture.repo.Slug, uuid.NewString(), http.StatusNotFound},
		// The fingerprint exists — on another repository.
		{"wrong repository", fixture.admin, fixture.otherRepo.Slug, fixture.fingerprint, http.StatusNotFound},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := callFindingHistory(t, fixture.srv, testCase.user, fixture.org, testCase.repoSlug, testCase.fingerprint)
			if recorder.Code != testCase.want {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, testCase.want, recorder.Body.String())
			}
		})
	}
}

// A finding whose earliest snapshots have aged out of the transition list must
// still show where and when it started.
func TestFindingHistoryAlwaysCarriesCreationPoint(t *testing.T) {
	t.Parallel()

	fixture := newFindingHistoryFixture(t)
	// A second branch detects the same fingerprint later: its own "detected"
	// transition must not be mistaken for the finding's creation point.
	seedHistoryFinding(t, fixture.srv, fixture.repo, "release", "sha-release", fixture.fingerprint, "detected")

	history := decodeFindingHistory(t, callFindingHistory(t, fixture.srv, fixture.admin, fixture.org, fixture.repo.Slug, fixture.fingerprint))

	anchors := 0
	for _, event := range history.Events {
		if event.Kind == "first_detected" {
			anchors++
			if event.RefName != "main" || event.CommitSHA != "sha-detected" {
				t.Fatalf("creation point = %+v, want the first observation on main", event)
			}
		}
	}
	if anchors != 1 {
		t.Fatalf("creation points = %d, want exactly 1: %+v", anchors, history.Events)
	}
	if last := history.Events[len(history.Events)-1]; last.Kind != "first_detected" {
		t.Fatalf("timeline does not end on the creation point: %+v", last)
	}
}

// Dependency fingerprints are `advisory:component` pairs, so a client must
// percent-encode them into the path — and chi hands the segment back raw. If
// the handler does not decode it, an entire class of findings answers 404.
func TestFindingHistoryAcceptsEncodedFingerprint(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	fingerprint := uuid.NewString() + ":" + uuid.NewString()
	seedHistoryFinding(t, srv, repo, "main", "sha-encoded", fingerprint, "detected")

	for _, variant := range []struct {
		name  string
		value string
	}{
		{"raw", fingerprint},
		{"percent-encoded", url.PathEscape(fingerprint)},
	} {
		t.Run(variant.name, func(t *testing.T) {
			history := decodeFindingHistory(t, callFindingHistory(t, srv, admin, org, repo.Slug, variant.value))
			if len(history.Events) == 0 {
				t.Fatalf("no events for the %s fingerprint", variant.name)
			}
		})
	}
}

// A developer who suppresses in code (`#nosec G101 -- reason`) has already
// written the triage comment; the scanner extracts it and the ingest stores it
// on the suppressed row. The timeline must surface it as the transition's
// comment, the same way a UI decision's comment travels.
func TestFindingHistoryCarriesInSourceSuppressionComment(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	fingerprint := uuid.NewString()

	seedHistoryFinding(t, srv, repo, "main", "sha-detected", fingerprint, "detected")

	ctx := context.Background()
	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, "main", store.RefTypeBranch)
	if err != nil || ref == nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-suppressed", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, err := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type:                   "sast",
		SnapshotID:             snapshot.ID,
		Title:                  "hardcoded credential",
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: "G101",
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 "suppressed",
		ScannerName:            "gosec",
		Fingerprint:            fingerprint,
		Metadata:               json.RawMessage(`{"suppression":{"kind":"inSource","justification":"event name, not a credential"}}`),
	}); err != nil {
		t.Fatalf("CreateVulnerability(suppressed): %v", err)
	}

	history := decodeFindingHistory(t, callFindingHistory(t, srv, admin, org, repo.Slug, fingerprint))

	var suppressed *findingHistoryEvent
	for index := range history.Events {
		if history.Events[index].Kind == "suppressed" {
			suppressed = &history.Events[index]
		}
	}
	if suppressed == nil {
		t.Fatalf("no suppressed event: %+v", history.Events)
	}
	if comment, _ := suppressed.Detail["comment"].(string); comment != "event name, not a credential" {
		t.Fatalf("suppressed event detail = %+v, want the in-source justification", suppressed.Detail)
	}
}

// A reachability verdict is a timeline event (it changes gating and the VEX
// export): unknown → not_reachable reads "proven unreachable", a later flip
// back reads "reachable again", and going back to unknown is silence, not an
// event.
func TestFindingHistoryShowsReachabilityTransitions(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	fingerprint := uuid.NewString()

	seedHistoryFindingWithReachability(t, srv, repo, "main", "sha-1", fingerprint, "detected", "")
	seedHistoryFindingWithReachability(t, srv, repo, "main", "sha-2", fingerprint, "detected", "not_reachable")
	seedHistoryFindingWithReachability(t, srv, repo, "main", "sha-3", fingerprint, "detected", "reachable")
	// Back to unknown (fresh snapshot never classified): must NOT emit an event.
	seedHistoryFindingWithReachability(t, srv, repo, "main", "sha-4", fingerprint, "detected", "")

	history := decodeFindingHistory(t, callFindingHistory(t, srv, admin, org, repo.Slug, fingerprint))

	kinds := make([]string, 0, len(history.Events))
	for _, event := range history.Events {
		kinds = append(kinds, event.Kind)
	}
	want := []string{"became_reachable", "became_unreachable", "first_detected"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
	if history.Events[1].From != "" || history.Events[1].To != "not_reachable" {
		t.Fatalf("unreachable event from/to = %q/%q, want the verdicts", history.Events[1].From, history.Events[1].To)
	}
	if history.Events[0].From != "not_reachable" || history.Events[0].To != "reachable" {
		t.Fatalf("reachable event from/to = %q/%q", history.Events[0].From, history.Events[0].To)
	}
}

// scanHistoryEvent must attach the in-source justification only when there is
// one: a plain transition keeps a nil detail so the API shape stays stable.
func TestScanHistoryEventSuppressionComment(t *testing.T) {
	t.Parallel()

	plain := scanHistoryEvent(store.FindingTransition{PreviousStatus: "detected", Status: "resolved"})
	if plain.Detail != nil {
		t.Fatalf("plain transition detail = %+v, want nil", plain.Detail)
	}
	blank := scanHistoryEvent(store.FindingTransition{PreviousStatus: "detected", Status: "suppressed", SuppressionJustification: "   "})
	if blank.Detail != nil {
		t.Fatalf("blank justification detail = %+v, want nil", blank.Detail)
	}
	justified := scanHistoryEvent(store.FindingTransition{PreviousStatus: "detected", Status: "suppressed", SuppressionJustification: "bounded by API parsing"})
	if comment, _ := justified.Detail["comment"].(string); comment != "bounded by API parsing" {
		t.Fatalf("justified detail = %+v", justified.Detail)
	}
}

func TestScanEventKind(t *testing.T) {
	t.Parallel()

	cases := []struct{ previous, current, want string }{
		{"", "detected", "detected"},
		{"detected", "resolved", "resolved"},
		{"resolved", "detected", "reintroduced"},
		{"detected", "suppressed", "suppressed"},
		{"suppressed", "detected", "status_change"},
	}
	for _, testCase := range cases {
		if got := scanEventKind(testCase.previous, testCase.current); got != testCase.want {
			t.Fatalf("scanEventKind(%q, %q) = %q, want %q", testCase.previous, testCase.current, got, testCase.want)
		}
	}
}

func TestProjectFindingActivityContext(t *testing.T) {
	t.Parallel()

	if got := projectFindingActivityContext(nil); got != nil {
		t.Fatalf("nil context = %+v", got)
	}
	if got := projectFindingActivityContext(json.RawMessage("not json")); got != nil {
		t.Fatalf("malformed context = %+v", got)
	}
	if got := projectFindingActivityContext(json.RawMessage(`{"token_id":"x"}`)); got != nil {
		t.Fatalf("context with no allowlisted key = %+v", got)
	}
	// An empty reason carries no information and would render as a stray dash.
	if got := projectFindingActivityContext(json.RawMessage(`{"reason":"  ","status":"open"}`)); len(got) != 1 || got["status"] != "open" {
		t.Fatalf("projected = %+v", got)
	}
}

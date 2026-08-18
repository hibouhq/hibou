package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
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

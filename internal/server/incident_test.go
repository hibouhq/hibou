package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/kev"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// incidentFixture is a product with one exploited dependency shipped in a
// release a client runs.
type incidentFixture struct {
	srv      *Server
	org      *store.Organization
	admin    *store.User
	repo     *store.Repository
	advisory dbgen.Advisory
	cve      string
	release  *store.Release
	client   *store.Client
	purl     string
	actor    incidentActor
}

func newIncidentFixture(t *testing.T) incidentFixture {
	t.Helper()
	srv, org, admin, _ := newDiscoveryTestServer(t)
	ctx := context.Background()
	repo := createUploadTestRepository(t, srv, org)
	cve := fmt.Sprintf("CVE-2099-%05d", rand.IntN(90000)+10000)

	advisory, err := upsertRatedAdvisory(ctx, srv.queries, dbgen.UpsertAdvisoryParams{CanonicalID: cve, Title: "XXE in parser", Description: "XML external entities."},
		dbgen.SetAdvisoryRatingParams{Severity: dbgen.SeverityLevelHigh, CvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssScore: sql.NullString{String: "8.1", Valid: true}, CvssVersion: dbgen.NullCvssVersion{CvssVersion: dbgen.CvssVersionV31, Valid: true}})
	if err != nil {
		t.Fatalf("advisory: %v", err)
	}
	if _, err := srv.queries.ReplaceKEVSource(ctx, srv.db, "test-"+uuid.NewString()[:8], []kev.Entry{{CVEID: cve, VendorProject: "example", Product: "parser", DateAdded: time.Now().UTC()}}, 0); err != nil {
		t.Fatalf("kev: %v", err)
	}

	tag, err := srv.queries.CreateRef(ctx, repo.ID, "v4.2.1", store.RefTypeTag, nil, nil, nil)
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, tag.ID, "release-sha-"+uuid.NewString()[:8], store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	purl := "pkg:maven/org.example/parser@2.3.1"
	if _, err := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type: "dependency", SnapshotID: snapshot.ID, Title: "XXE in parser", PrimaryIdentifierKind: "cve", PrimaryIdentifierValue: cve,
		OriginalSeverity: dbgen.SeverityLevelHigh, Severity: dbgen.SeverityLevelHigh, Status: "detected", ScannerName: "osv",
		Fingerprint: uuid.NewString(), AdvisoryID: uuid.NullUUID{UUID: advisory.ID, Valid: true},
		ComponentPurl: sql.NullString{String: purl, Valid: true}, ComponentName: sql.NullString{String: "parser", Valid: true},
	}); err != nil {
		t.Fatalf("finding: %v", err)
	}
	snapshotID := snapshot.ID
	release, err := srv.queries.UpsertRelease(ctx, store.UpsertReleaseParams{RepoID: repo.ID, RefID: tag.ID, SnapshotID: &snapshotID, Version: "v4.2.1"})
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := srv.pinReleaseSnapshot(ctx, snapshotID); err != nil {
		t.Fatalf("pin: %v", err)
	}
	email := "security@castor.example"
	client, err := srv.queries.CreateClient(ctx, org.ID, "Castor", uniqueName(t, "castor"), json.RawMessage(`{"country":"fr"}`), "external", &email, nil, nil, nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if _, err := srv.queries.CreateDeployment(ctx, client.ID, release.ID, "production", store.DeploymentStatusActive, time.Now().UTC(), nil, nil, nil); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	return incidentFixture{
		srv: srv, org: org, admin: admin, repo: repo, advisory: advisory, cve: cve, release: release, client: client, purl: purl,
		actor: incidentActor{ID: uuid.NullUUID{UUID: admin.ID, Valid: true}, Type: "user", Display: "Admin"},
	}
}

// privateAdvisory strips the fixture advisory of its public identifier: a
// vulnerability reported to us directly, which the component's maintainer
// does not know about yet, so an upstream notice is owed (guidance §223).
func (f incidentFixture) privateAdvisory(t *testing.T) {
	t.Helper()
	if _, err := f.srv.db.ExecContext(context.Background(), `UPDATE advisories SET canonical_id = $1 WHERE id = $2`, "PRIVATE-"+uuid.NewString()[:8], f.advisory.ID); err != nil {
		t.Fatalf("private advisory: %v", err)
	}
}

func (f incidentFixture) actions(t *testing.T, inc dbgen.Incident) map[string][]dbgen.IncidentAction {
	t.Helper()
	rows, err := f.srv.queries.Incidents().ListIncidentActions(context.Background(), inc.ID)
	if err != nil {
		t.Fatalf("actions: %v", err)
	}
	out := map[string][]dbgen.IncidentAction{}
	for _, row := range rows {
		if !row.Obsolete {
			out[row.Kind] = append(out[row.Kind], row)
		}
	}
	return out
}

func (f incidentFixture) reload(t *testing.T, inc dbgen.Incident) dbgen.Incident {
	t.Helper()
	reloaded, err := f.srv.reconcileIncident(context.Background(), inc.ID)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return reloaded
}

func TestIncidentLifecycleExploitedVulnerability(t *testing.T) {
	t.Parallel()
	f := newIncidentFixture(t)
	ctx := context.Background()
	db := f.srv.queries.Incidents()

	// 1. The built-in rule opens a signal on the released snapshot; no T0.
	opened, err := f.srv.sweepIncidentRules(ctx, f.repo.ID)
	if err != nil || opened != 1 {
		t.Fatalf("sweep opened %d (%v), want 1", opened, err)
	}
	if again, _ := f.srv.sweepIncidentRules(ctx, f.repo.ID); again != 0 {
		t.Fatalf("a second sweep opened %d more", again)
	}
	inc, err := db.FindIncidentForSubject(ctx, dbgen.FindIncidentForSubjectParams{OrgID: f.org.ID, RepoID: uuid.NullUUID{UUID: f.repo.ID, Valid: true}, Kind: incident.KindExploitedVulnerability, SubjectType: incident.SubjectAdvisory, SubjectID: f.advisory.ID.String()})
	if err != nil {
		t.Fatalf("incident: %v", err)
	}
	if inc.State != dbgen.IncidentStateSignal || inc.AwareAt.Valid || inc.Number != 1 || inc.Priority != "P1" {
		t.Fatalf("opened incident = %+v", inc)
	}
	scope, _ := db.ListIncidentScope(ctx, inc.ID)
	if len(scope) != 1 || scope[0].Status != incident.ScopePending || scope[0].ComponentPurl != f.purl {
		t.Fatalf("scope = %+v", scope)
	}
	if acts := f.actions(t, inc); len(acts[incident.ActionVEX]) != 1 || len(acts["srp_early_warning"]) != 0 {
		t.Fatalf("pre-decision actions = %+v", acts)
	}

	// 2. A decision without its ladder step is refused; with it, T0 starts the clocks.
	if _, _, err := f.srv.decideIncident(ctx, inc, f.actor, incidentDecision{State: incident.StateReportable, Reason: "customer saw it"}); err == nil {
		t.Fatal("decision without decision_step accepted")
	}
	aware := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	inc, _, err = f.srv.decideIncident(ctx, inc, f.actor, incidentDecision{State: incident.StateReportable, Reason: "a customer found it used against their instance", DecisionStep: incident.StepAttacked, AwareAt: &aware})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !inc.AwareAt.Valid || !inc.AwareAt.Time.Equal(aware) || inc.State != dbgen.IncidentStateReportable {
		t.Fatalf("decided incident = %+v", inc)
	}
	deadlines, _ := db.ListIncidentDeadlines(ctx, inc.ID)
	due := map[string]time.Time{}
	for _, row := range deadlines {
		due[row.Regime+"/"+row.Step] = row.DueAt
	}
	if !due["cra-article-14/early_warning"].Equal(aware.Add(24*time.Hour)) || !due["cra-article-14/notification"].Equal(aware.Add(72*time.Hour)) {
		t.Fatalf("deadlines = %+v", deadlines)
	}
	acts := f.actions(t, inc)
	if len(acts["srp_early_warning"]) != 1 || len(acts[incident.ActionClientNotice]) != 1 || acts[incident.ActionClientNotice][0].SubjectID != f.client.ID.String() {
		t.Fatalf("reportable actions = %+v", acts)
	}

	// 3. The statement for the release satisfies the vex action.
	params, err := buildCreateVEXParams(f.org.ID, f.repo.ID, f.admin.ID, f.advisory.ID, createVEXStatementRequest{Status: "affected", ActionStatement: "Disable external entities; upgrade to 4.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	params.ReleaseID = uuid.NullUUID{UUID: f.release.ID, Valid: true}
	params.ApprovedBy = params.CreatedBy
	if _, err := f.srv.queries.RecordVEXStatement(ctx, params); err != nil {
		t.Fatalf("statement: %v", err)
	}
	inc = f.reload(t, inc)
	if acts := f.actions(t, inc); acts[incident.ActionVEX][0].State != "done" {
		t.Fatalf("vex action = %+v", acts[incident.ActionVEX][0])
	}
	scope, _ = db.ListIncidentScope(ctx, inc.ID)
	if scope[0].Status != incident.ScopeAffected {
		t.Fatalf("scope after statement = %s", scope[0].Status)
	}

	// 4. Filings are recorded with the platform's reference, never submitted.
	acts = f.actions(t, inc)
	if _, err := f.srv.recordIncidentFiling(ctx, inc, f.actor, acts["srp_early_warning"][0].ID, "", time.Time{}); err == nil {
		t.Fatal("filing without reference accepted")
	}
	for _, kind := range []string{"srp_early_warning", "srp_notification"} {
		if _, err := f.srv.recordIncidentFiling(ctx, inc, f.actor, acts[kind][0].ID, "SRP-"+kind, time.Now().UTC()); err != nil {
			t.Fatalf("filing %s: %v", kind, err)
		}
	}
	// T0 is fixed once something is filed.
	earlier := aware.Add(-time.Hour)
	if _, _, err := f.srv.decideIncident(ctx, f.reload(t, inc), f.actor, incidentDecision{State: incident.StateReportable, Reason: "earlier evidence", DecisionStep: incident.StepAttacked, AwareAt: &earlier}); err == nil {
		t.Fatal("aware_at moved after a filing")
	}

	// 5. The client notice: a manual delivery needs its evidence; documents
	// are stored and verify by re-rendering.
	if _, err := f.srv.deliverIncidentNotices(ctx, f.reload(t, inc), f.org, f.actor, deliverRequest{ClientIDs: []string{f.client.ID.String()}, Channel: "manual"}); err == nil {
		t.Fatal("manual delivery without evidence accepted")
	}
	deliveries, err := f.srv.deliverIncidentNotices(ctx, f.reload(t, inc), f.org, f.actor, deliverRequest{ClientIDs: []string{f.client.ID.String()}, Channel: "manual", Evidence: "read out on the weekly call, minutes 2026-10-23", Measures: "Disable external entities until 4.2.2."})
	if err != nil || len(deliveries) != 1 || deliveries[0].Status != "sent" || !deliveries[0].AuditLogID.Valid {
		t.Fatalf("delivery = %+v (%v)", deliveries, err)
	}
	var refs []documentRef
	_ = json.Unmarshal(deliveries[0].Documents, &refs)
	if len(refs) != len(clientDocumentKinds) {
		t.Fatalf("documents = %+v", refs)
	}
	for _, ref := range refs {
		result, err := f.srv.verifyIncidentDocument(ctx, f.org.ID, ref.SHA256)
		if err != nil || result["rerendered_matches"] != true || result["stored_matches_digest"] != true {
			t.Fatalf("verify %s = %v (%v)", ref.Kind, result, err)
		}
		if ref.Kind == docCSAFAdvisory {
			_, body, _ := f.srv.loadIncidentDocument(ctx, f.org.ID, ref.SHA256)
			text := string(body)
			for _, want := range []string{`"csaf_security_advisory"`, f.cve, `"known_affected"`, "4.2.1", "exploit_status", "Disable external entities"} {
				if !strings.Contains(text, want) {
					t.Fatalf("CSAF advisory lacks %q:\n%s", want, text)
				}
			}
		}
	}
	inc = f.reload(t, inc)
	if acts := f.actions(t, inc); acts[incident.ActionClientNotice][0].State != "done" {
		t.Fatalf("client notice = %+v", acts[incident.ActionClientNotice][0])
	}

	// 6. A later 4.2.x without the vulnerability ships the fix.
	fixRef, _ := f.srv.queries.CreateRef(ctx, f.repo.ID, "v4.2.2", store.RefTypeTag, nil, nil, nil)
	fixSnapshot, _ := f.srv.queries.CreateSnapshot(ctx, fixRef.ID, "fix-sha-"+uuid.NewString()[:8], store.SnapshotStatusComplete)
	fixSnapshotID := fixSnapshot.ID
	time.Sleep(10 * time.Millisecond)
	if _, err := f.srv.queries.UpsertRelease(ctx, store.UpsertReleaseParams{RepoID: f.repo.ID, RefID: fixRef.ID, SnapshotID: &fixSnapshotID, Version: "v4.2.2"}); err != nil {
		t.Fatalf("fix release: %v", err)
	}
	inc = f.reload(t, inc)
	if acts := f.actions(t, inc); acts[incident.ActionFixRelease][0].State != "done" {
		t.Fatalf("fix_release = %+v", acts[incident.ActionFixRelease][0])
	}
	if inc.State == dbgen.IncidentStateClosed {
		t.Fatal("closed before the final report")
	}

	// 7. The fix starts the final-report clock; filing it closes the incident.
	inc, err = f.srv.setIncidentFixAvailable(ctx, inc, f.actor, time.Time{}, "4.2.2 released")
	if err != nil {
		t.Fatalf("fix available: %v", err)
	}
	acts = f.actions(t, inc)
	if len(acts["srp_final_report"]) != 1 {
		t.Fatalf("final report action missing: %+v", acts)
	}
	if _, err := f.srv.recordIncidentFiling(ctx, inc, f.actor, acts["srp_final_report"][0].ID, "SRP-final", time.Now().UTC()); err != nil {
		t.Fatalf("final filing: %v", err)
	}
	inc, _ = db.GetIncident(ctx, inc.ID)
	if inc.State != dbgen.IncidentStateClosed || !inc.ClosedAt.Valid {
		pending := []string{}
		for kind, rows := range f.actions(t, inc) {
			for _, row := range rows {
				if row.State == "pending" && !row.Optional {
					pending = append(pending, kind+":"+row.Label)
				}
			}
		}
		t.Fatalf("incident not closed: %s; pending %v", inc.State, pending)
	}

	// 8. A new client on the affected release reopens it.
	email := "soc@pollux.example"
	pollux, _ := f.srv.queries.CreateClient(ctx, f.org.ID, "Pollux", uniqueName(t, "pollux"), nil, "external", &email, nil, nil, nil)
	if _, err := f.srv.queries.CreateDeployment(ctx, pollux.ID, f.release.ID, "production", store.DeploymentStatusActive, time.Now().UTC(), nil, nil, nil); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	inc = f.reload(t, inc)
	if inc.State != dbgen.IncidentStateReportable {
		t.Fatalf("not reopened: %s", inc.State)
	}
	events, _ := db.ListIncidentEvents(ctx, inc.ID)
	kinds := map[string]bool{}
	for _, event := range events {
		kinds[event.Kind] = true
	}
	for _, want := range []string{"opened", "decided", "filing.recorded", "delivery.sent", "closed", "reopened"} {
		if !kinds[want] {
			t.Fatalf("timeline lacks %s: %v", want, kinds)
		}
	}
}

func TestIncidentFourEyesAndWithdraw(t *testing.T) {
	t.Parallel()
	f := newIncidentFixture(t)
	f.privateAdvisory(t)
	ctx := context.Background()
	if _, err := f.srv.queries.Incidents().UpsertIncidentSettings(ctx, dbgen.UpsertIncidentSettingsParams{
		OrgID: f.org.ID, DefaultRules: []byte(`null`), LockedRules: []byte(`[]`), InternalTargets: []byte(`{}`), NationalRegimes: []byte(`[]`), FourEyes: true, DueSoonLeadMinutes: 360,
	}); err != nil {
		t.Fatalf("settings: %v", err)
	}
	if _, err := f.srv.sweepIncidentRules(ctx, f.repo.ID); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	inc, err := f.srv.queries.Incidents().GetIncidentByNumber(ctx, dbgen.GetIncidentByNumberParams{OrgID: f.org.ID, Number: 1})
	if err != nil {
		t.Fatalf("incident: %v", err)
	}
	inc, proposed, err := f.srv.decideIncident(ctx, inc, f.actor, incidentDecision{State: incident.StateNotReportable, Reason: "not reachable", DecisionStep: incident.StepNotReachable})
	if err != nil || !proposed || inc.State != dbgen.IncidentStateSignal {
		t.Fatalf("hiding decision applied directly: proposed=%v state=%s err=%v", proposed, inc.State, err)
	}
	if _, err := f.srv.approveIncidentDecision(ctx, inc, f.actor); err == nil {
		t.Fatal("the proposer approved their own decision")
	}
	second, err := f.srv.queries.CreateUser(ctx, uniqueName(t, "second")+"@example.com", "Second", "github", uniqueName(t, "second-user"))
	if err != nil {
		t.Fatal(err)
	}
	approver := incidentActor{ID: uuid.NullUUID{UUID: second.ID, Valid: true}, Type: "user", Display: "Second"}
	inc, err = f.srv.approveIncidentDecision(ctx, inc, approver)
	if err != nil || inc.State != dbgen.IncidentStateNotReportable {
		t.Fatalf("approve = %s (%v)", inc.State, err)
	}
	acts := f.actions(t, inc)
	if len(acts[incident.ActionUpstreamNotice]) != 1 || len(acts[incident.ActionClientNotice]) != 0 {
		t.Fatalf("not reportable actions = %+v", acts)
	}
	if _, err := f.srv.withdrawIncident(ctx, inc, f.actor, ""); err == nil {
		t.Fatal("withdraw without reason accepted")
	}
	inc, err = f.srv.withdrawIncident(ctx, inc, f.actor, "duplicate of a vendor advisory")
	if err != nil || inc.State != dbgen.IncidentStateWithdrawn {
		t.Fatalf("withdraw = %s (%v)", inc.State, err)
	}
	// A withdrawn subject is never re-opened by a rule.
	if opened, _ := f.srv.sweepIncidentRules(ctx, f.repo.ID); opened != 0 {
		t.Fatalf("sweep reopened a withdrawn subject: %d", opened)
	}
}

func TestIncidentAPIListAndDetail(t *testing.T) {
	t.Parallel()
	f := newIncidentFixture(t)
	ctx := context.Background()
	if _, err := f.srv.sweepIncidentRules(ctx, f.repo.ID); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	request := func(method, path string, params map[string]string, handler http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req = req.WithContext(internalauth.WithUser(req.Context(), f.admin))
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("provider", "github")
		routeCtx.URLParams.Add("slug", f.org.Slug)
		for key, value := range params {
			routeCtx.URLParams.Add(key, value)
		}
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		recorder := httptest.NewRecorder()
		handler(recorder, req)
		return recorder
	}
	list := request(http.MethodGet, "/incidents?state=open", nil, f.srv.handleListIncidents)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"kind_label":"Exploited vulnerability"`) {
		t.Fatalf("list = %d %s", list.Code, list.Body.String())
	}
	detail := request(http.MethodGet, "/incidents/1", map[string]string{"number": "1"}, f.srv.handleGetIncident)
	if detail.Code != http.StatusOK {
		t.Fatalf("detail = %d %s", detail.Code, detail.Body.String())
	}
	var body struct {
		Data incidentDetailResponse `json:"data"`
	}
	if err := json.Unmarshal(detail.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data.Scope) != 1 || len(body.Data.Scope[0].Clients) != 1 || body.Data.Scope[0].Clients[0].Name != "Castor" || body.Data.Advisory == nil || body.Data.Advisory.CanonicalID != f.cve {
		t.Fatalf("detail = %+v", body.Data)
	}
	if body.Data.DecisionStates[0] != incident.StateReportable || !body.Data.CanManage {
		t.Fatalf("decision states / can manage = %v %v", body.Data.DecisionStates, body.Data.CanManage)
	}
	draft := request(http.MethodGet, "/incidents/1/filing-draft?step=early_warning", map[string]string{"number": "1"}, f.srv.handleIncidentFilingDraft)
	if draft.Code != http.StatusOK || !strings.Contains(draft.Body.String(), "FR") || !strings.Contains(draft.Body.String(), "4.2.1") {
		t.Fatalf("filing draft = %d %s", draft.Code, draft.Body.String())
	}
}

// A reconcile keeps a deadline's notified marker: rewriting the rows reset it
// and re-sent the due-soon warning every minute.
func TestIncidentReconcileKeepsDeadlineNotified(t *testing.T) {
	t.Parallel()
	f := newIncidentFixture(t)
	ctx := context.Background()
	db := f.srv.queries.Incidents()
	if _, err := f.srv.sweepIncidentRules(ctx, f.repo.ID); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	inc, err := db.FindIncidentForSubject(ctx, dbgen.FindIncidentForSubjectParams{OrgID: f.org.ID, RepoID: uuid.NullUUID{UUID: f.repo.ID, Valid: true}, Kind: incident.KindExploitedVulnerability, SubjectType: incident.SubjectAdvisory, SubjectID: f.advisory.ID.String()})
	if err != nil {
		t.Fatal(err)
	}
	aware := time.Now().UTC().Add(-20 * time.Hour).Truncate(time.Second)
	if _, _, err := f.srv.decideIncident(ctx, inc, f.actor, incidentDecision{State: incident.StateReportable, Reason: "attack seen", DecisionStep: incident.StepAttacked, AwareAt: &aware}); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkIncidentDeadlineNotified(ctx, dbgen.MarkIncidentDeadlineNotifiedParams{IncidentID: inc.ID, Regime: "cra-article-14", Step: "early_warning", Notified: "due_soon"}); err != nil {
		t.Fatal(err)
	}
	f.reload(t, inc)
	f.reload(t, inc)
	rows, err := db.ListIncidentDeadlines(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.Regime == "cra-article-14" && row.Step == "early_warning" {
			found = true
			if row.Notified != "due_soon" {
				t.Fatalf("notified = %q after reconcile, want due_soon", row.Notified)
			}
		}
	}
	if !found {
		t.Fatalf("early warning deadline missing: %+v", rows)
	}
}

// A "cannot be exploited here" decision writes the VEX statement of every
// release in scope without one, so one decision closes the ladder instead of
// one statement per release; a release with its own statement keeps it.
func TestIncidentDecisionWritesStatements(t *testing.T) {
	t.Parallel()
	f := newIncidentFixture(t)
	ctx := context.Background()
	db := f.srv.queries.Incidents()
	if _, err := f.srv.sweepIncidentRules(ctx, f.repo.ID); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	inc, err := db.FindIncidentForSubject(ctx, dbgen.FindIncidentForSubjectParams{OrgID: f.org.ID, RepoID: uuid.NullUUID{UUID: f.repo.ID, Valid: true}, Kind: incident.KindExploitedVulnerability, SubjectType: incident.SubjectAdvisory, SubjectID: f.advisory.ID.String()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.srv.decideIncident(ctx, inc, f.actor, incidentDecision{
		State: incident.StateNotReportable, DecisionStep: incident.StepNotReachable, Justification: "inline_mitigations_already_exist",
		Reason: "External entities are disabled in our parser configuration.", WriteStatements: true,
	}); err != nil {
		t.Fatalf("decide: %v", err)
	}
	inc = f.reload(t, inc)
	scope, _ := db.ListIncidentScope(ctx, inc.ID)
	if len(scope) != 1 || scope[0].Status != incident.ScopeNotAffected || !scope[0].VexStatementID.Valid || scope[0].Reason != "inline_mitigations_already_exist" {
		t.Fatalf("scope after decision = %+v", scope)
	}
	acts := f.actions(t, inc)
	if len(acts[incident.ActionVEX]) != 1 || acts[incident.ActionVEX][0].State != "done" {
		t.Fatalf("vex action = %+v", acts[incident.ActionVEX])
	}
	// A public CVE: the maintainer already knows, nothing is owed upstream.
	if up := acts[incident.ActionUpstreamNotice]; len(up) != 0 {
		t.Fatalf("upstream notice = %+v", up)
	}
	// Nothing required is left: the incident closed itself.
	if inc.State != dbgen.IncidentStateClosed {
		t.Fatalf("state = %s, want closed", inc.State)
	}
	// Writing again does not duplicate the statement.
	if written, err := f.srv.writeDecisionStatements(ctx, inc, f.actor, incidentDecision{DecisionStep: incident.StepNotReachable, Reason: "re-checked"}); err != nil || written != 0 {
		t.Fatalf("second write: written=%d err=%v", written, err)
	}
	var statements int
	if err := f.srv.db.QueryRowContext(ctx, `SELECT count(*) FROM vex_statements WHERE repo_id = $1 AND advisory_id = $2 AND superseded_at IS NULL AND NOT withdrawn`, f.repo.ID, f.advisory.ID).Scan(&statements); err != nil {
		t.Fatal(err)
	}
	if statements != 1 {
		t.Fatalf("statements = %d, want 1", statements)
	}
}

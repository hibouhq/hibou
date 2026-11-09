package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func openFixtureIncident(t *testing.T, f incidentFixture) dbgen.Incident {
	t.Helper()
	if _, err := f.srv.sweepIncidentRules(context.Background(), f.repo.ID); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	inc, err := f.srv.queries.Incidents().GetIncidentByNumber(context.Background(), dbgen.GetIncidentByNumberParams{OrgID: f.org.ID, Number: 1})
	if err != nil {
		t.Fatalf("incident: %v", err)
	}
	return inc
}

// The client webhook channel: signed JSON with the documents, and a 2xx is
// the client's acknowledgement.
func TestIncidentWebhookDeliveryIsAcknowledgedBy2xx(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "true")
	f := newIncidentFixture(t)
	ctx := context.Background()
	var received struct {
		sync.Mutex
		body      []byte
		signature string
	}
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Lock()
		defer received.Unlock()
		received.body, _ = io.ReadAll(r.Body)
		received.signature = r.Header.Get("X-Hibou-Signature-256")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer receiver.Close()

	inc := openFixtureIncident(t, f)
	inc, _, err := f.srv.decideIncident(ctx, inc, f.actor, incidentDecision{State: incident.StateReportable, Reason: "attack reported", DecisionStep: incident.StepAttacked})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	client, err := f.srv.queries.Incidents().GetClientRow(ctx, f.client.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(clientDeliveryConfig{Channel: channelWebhook, WebhookURL: receiver.URL, Secret: "s3cret"})
	if _, err := f.srv.queries.Incidents().UpdateClientDelivery(ctx, dbgen.UpdateClientDeliveryParams{ID: client.ID, SecurityContacts: []byte(`[]`), DeliveryConfig: raw}); err != nil {
		t.Fatal(err)
	}
	deliveries, err := f.srv.deliverIncidentNotices(ctx, inc, f.org, f.actor, deliverRequest{ClientIDs: []string{client.ID.String()}, Measures: "upgrade"})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("deliver = %+v (%v)", deliveries, err)
	}
	if deliveries[0].Status != "acknowledged" || !deliveries[0].AcknowledgedAt.Valid {
		t.Fatalf("delivery status = %s (error %q)", deliveries[0].Status, deliveries[0].Error)
	}
	received.Lock()
	defer received.Unlock()
	if !strings.HasPrefix(received.signature, "sha256=") || !bytes.Contains(received.body, []byte(`"csaf_security_advisory"`)) {
		t.Fatalf("webhook body/signature = %q / %s", received.signature, received.body)
	}
}

// The tracker mirror creates one issue, posts the timeline as comments, and
// inbound status changes complete only manual, non-filing actions.
func TestIncidentTrackerMirror(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "true")
	f := newIncidentFixture(t)
	f.privateAdvisory(t)
	ctx := context.Background()
	var mu sync.Mutex
	calls := []string{}
	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodPost && r.URL.Path == "/rest/api/2/issue" {
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "SEC-7"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer tracker.Close()

	config, _ := json.Marshal(map[string]any{
		"base_url": tracker.URL, "token": "t", "auth": "bearer", "project_key": "SEC",
		"inbound_secret": "inbound", "status_map": map[string]string{"Registry reported": incident.ActionUpstreamNotice},
	})
	integration, err := f.srv.queries.CreateIntegration(ctx, f.org.ID, "Jira", string(dbgen.IntegrationTypeJira), config, true)
	if err != nil {
		t.Fatalf("integration: %v", err)
	}
	inc := openFixtureIncident(t, f)
	f.srv.syncIncidentTrackers(ctx, inc.ID)
	links, _ := f.srv.queries.Incidents().ListIncidentTrackerLinks(ctx, inc.ID)
	if len(links) != 1 || links[0].ExternalKey != "SEC-7" || links[0].LastError != "" {
		t.Fatalf("links = %+v", links)
	}
	_ = f.srv.addIncidentNote(ctx, inc, f.actor, "looking at it")
	f.srv.syncIncidentTrackers(ctx, inc.ID)
	mu.Lock()
	joined := strings.Join(calls, "\n")
	mu.Unlock()
	if strings.Count(joined, "POST /rest/api/2/issue\n") != 1 || !strings.Contains(joined, "POST /rest/api/2/issue/SEC-7/comment") {
		t.Fatalf("tracker calls:\n%s", joined)
	}

	// Inbound: decide not reportable (upstream notice owed), then the tracker
	// moves the issue to the mapped status.
	if _, _, err := f.srv.decideIncident(ctx, inc, f.actor, incidentDecision{State: incident.StateNotReportable, Reason: "not reachable", DecisionStep: incident.StepNotReachable}); err != nil {
		t.Fatalf("decide: %v", err)
	}
	body := []byte(`{"webhookEvent":"jira:issue_updated","issue":{"key":"SEC-7","fields":{"status":{"name":"Registry reported"}}},"user":{"displayName":"Ana"}}`)
	call := func(secret string) int {
		req := httptest.NewRequest(http.MethodPost, "/hooks/incident-tracker/x?secret="+secret, bytes.NewReader(body))
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("integrationID", integration.ID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		recorder := httptest.NewRecorder()
		f.srv.handleIncidentTrackerWebhook(recorder, req)
		return recorder.Code
	}
	if code := call("wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong secret = %d", code)
	}
	if code := call("inbound"); code != http.StatusAccepted {
		t.Fatalf("inbound = %d", code)
	}
	acts := f.actions(t, inc)
	if len(acts[incident.ActionUpstreamNotice]) != 1 || acts[incident.ActionUpstreamNotice][0].State != "done" {
		t.Fatalf("upstream notice after inbound = %+v", acts[incident.ActionUpstreamNotice])
	}
}

// The secret checklist: revocation needs its place, rotation "not needed"
// needs its reason, and the incident's actions follow the attestation.
func TestSecretChecklistDrivesTheIncident(t *testing.T) {
	t.Parallel()
	srv, org, admin, _ := newDiscoveryTestServer(t)
	ctx := context.Background()
	repo := createUploadTestRepository(t, srv, org)
	ref, _ := srv.queries.CreateRef(ctx, repo.ID, repo.DefaultBranch, store.RefTypeBranch, nil, nil, nil)
	snapshot, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "secret-sha-"+uuid.NewString()[:8], store.SnapshotStatusComplete)
	finding, err := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type: "secret", SnapshotID: snapshot.ID, Title: "AWS key", PrimaryIdentifierKind: "rule", PrimaryIdentifierValue: "aws-access-key",
		OriginalSeverity: dbgen.SeverityLevelCritical, Severity: dbgen.SeverityLevelCritical, Status: "detected", ScannerName: "betterleaks",
		Fingerprint: uuid.NewString(), Verified: sql.NullBool{Bool: true, Valid: true},
	})
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	opened, err := srv.sweepIncidentRules(ctx, repo.ID)
	if err != nil || opened != 1 {
		t.Fatalf("verified secret opened %d (%v)", opened, err)
	}
	inc, _ := srv.queries.Incidents().GetIncidentByNumber(ctx, dbgen.GetIncidentByNumberParams{OrgID: org.ID, Number: 1})
	if inc.Kind != incident.KindSecretLeak {
		t.Fatalf("kind = %s", inc.Kind)
	}
	post := func(body map[string]any) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/revocation", bytes.NewReader(payload))
		req = req.WithContext(internalauth.WithUser(req.Context(), admin))
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("provider", "github")
		routeCtx.URLParams.Add("slug", org.Slug)
		routeCtx.URLParams.Add("repoSlug", repo.Slug)
		routeCtx.URLParams.Add("vulnID", finding.ID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		recorder := httptest.NewRecorder()
		srv.handleAttestSecretRevocation(recorder, req)
		return recorder
	}
	if rec := post(map[string]any{"checklist": map[string]any{"revoked": true}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("revoked without place = %d", rec.Code)
	}
	if rec := post(map[string]any{"checklist": map[string]any{"rotation": "not_needed"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("not needed without reason = %d", rec.Code)
	}
	if rec := post(map[string]any{"checklist": map[string]any{"revoked": true, "revoked_where": "AWS IAM console", "revoked_by": "Ana", "reference": "SEC-12", "rotation": "rotated", "exposure": "assessed", "exposure_note": "private repo, 2 h"}}); rec.Code != http.StatusOK {
		t.Fatalf("checklist = %d %s", rec.Code, rec.Body.String())
	}
	inc, _ = srv.queries.Incidents().GetIncident(ctx, inc.ID)
	actions, _ := srv.queries.Incidents().ListIncidentActions(ctx, inc.ID)
	for _, action := range actions {
		if action.Optional || action.Obsolete {
			continue
		}
		if action.State != "done" {
			t.Fatalf("action %s still %s", action.Kind, action.State)
		}
	}
	if inc.State != dbgen.IncidentStateClosed {
		t.Fatalf("secret incident state = %s, want closed", inc.State)
	}
}

func TestSecretValidatorDeadIsRead(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"ValidationStatus":"revoked"}`:             true,
		`{"source":{"validation_status":"invalid"}}`: true,
		`{"ValidationStatus":"unknown"}`:             false,
		`{"ValidationStatus":"valid"}`:               false,
		`{}`:                                         false,
	} {
		if got := secretValidatorDead(json.RawMessage(raw)); got != want {
			t.Fatalf("secretValidatorDead(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestPortalTokenSeesOnlyItsClient(t *testing.T) {
	t.Parallel()
	f := newIncidentFixture(t)
	ctx := context.Background()
	inc := openFixtureIncident(t, f)
	inc, _, err := f.srv.decideIncident(ctx, inc, f.actor, incidentDecision{State: incident.StateReportable, Reason: "attack", DecisionStep: incident.StepAttacked})
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := f.srv.deliverIncidentNotices(ctx, inc, f.org, f.actor, deliverRequest{ClientIDs: []string{f.client.ID.String()}, Channel: channelPortal})
	if err != nil || deliveries[0].Status != "sent" {
		t.Fatalf("portal delivery = %+v (%v)", deliveries, err)
	}
	token, hash, _ := newPortalToken()
	if _, err := f.srv.queries.Incidents().CreateClientPortalToken(ctx, dbgen.CreateClientPortalTokenParams{OrgID: f.org.ID, ClientID: f.client.ID, Name: "castor", TokenHash: hash}); err != nil {
		t.Fatal(err)
	}
	get := func(path, bearer string, params map[string]string, handler http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		routeCtx := chi.NewRouteContext()
		for key, value := range params {
			routeCtx.URLParams.Add(key, value)
		}
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		recorder := httptest.NewRecorder()
		handler(recorder, req)
		return recorder
	}
	if rec := get("/portal/notices", "", nil, f.srv.handlePortalList); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous portal = %d", rec.Code)
	}
	list := get("/portal/notices", token, nil, f.srv.handlePortalList)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), deliveries[0].ID.String()) {
		t.Fatalf("portal list = %d %s", list.Code, list.Body.String())
	}
	var refs []documentRef
	_ = json.Unmarshal(deliveries[0].Documents, &refs)
	doc := get("/doc", token, map[string]string{"deliveryID": deliveries[0].ID.String(), "sha256": refs[0].SHA256}, f.srv.handlePortalDocument)
	if doc.Code != http.StatusOK {
		t.Fatalf("portal document = %d", doc.Code)
	}
	delivery, _ := f.srv.queries.Incidents().GetIncidentDelivery(ctx, deliveries[0].ID)
	if delivery.Status != "acknowledged" {
		t.Fatalf("download did not acknowledge: %s", delivery.Status)
	}
	other, otherHash, _ := newPortalToken()
	email := "x@other.example"
	otherClient, _ := f.srv.queries.CreateClient(ctx, f.org.ID, "Other", uniqueName(t, "other"), nil, "external", &email, nil, nil, nil)
	_, _ = f.srv.queries.Incidents().CreateClientPortalToken(ctx, dbgen.CreateClientPortalTokenParams{OrgID: f.org.ID, ClientID: otherClient.ID, Name: "other", TokenHash: otherHash})
	if rec := get("/doc", other, map[string]string{"deliveryID": deliveries[0].ID.String(), "sha256": refs[0].SHA256}, f.srv.handlePortalDocument); rec.Code != http.StatusNotFound {
		t.Fatalf("another client's token = %d", rec.Code)
	}
}

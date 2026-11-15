package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func addRemovalDeployment(t *testing.T, f repoRemovalFixture, status store.DeploymentStatus) *store.Deployment {
	t.Helper()
	ctx := context.Background()
	client, err := f.srv.queries.CreateClient(ctx, f.org.ID, "Fixture Client", uniqueName(t, "fixture-client"), json.RawMessage(`{}`), "external", nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := f.srv.queries.CreateDeployment(ctx, client.ID, f.releaseID, "fixture", status, time.Now().UTC(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return deployment
}

func removeRepositoryWithQuery(t *testing.T, f repoRemovalFixture, query string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	f.srv.handleRemoveRepo(response, newRepoRequest(t, f.admin, http.MethodDelete, "/?"+query, "github", f.org.Slug, f.repo.Slug))
	return response
}

func TestRepositoryRemovalPreviewCountsAndAuthorization(t *testing.T) {
	f := newRepoRemovalFixture(t)
	for _, status := range []store.DeploymentStatus{store.DeploymentStatusActive, store.DeploymentStatusRolledBack, store.DeploymentStatusSuperseded} {
		addRemovalDeployment(t, f, status)
	}
	response := httptest.NewRecorder()
	f.srv.handleGetRepositoryRemovalPreview(response, newRepoRequest(t, f.admin, http.MethodGet, "/", "github", f.org.Slug, f.repo.Slug))
	if response.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Data dbgen.GetRepositoryRemovalPreviewRow `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := dbgen.GetRepositoryRemovalPreviewRow{Snapshots: 1, Releases: 1, Artifacts: 1, Incidents: 1, ActiveDeployments: 1, InactiveDeployments: 2}
	if body.Data != want {
		t.Fatalf("preview=%+v want %+v", body.Data, want)
	}
	f.assertIntact(t)
	forbidden := httptest.NewRecorder()
	f.srv.handleGetRepositoryRemovalPreview(forbidden, newRepoRequest(t, f.member, http.MethodGet, "/", "github", f.org.Slug, f.repo.Slug))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("member preview status=%d", forbidden.Code)
	}
	forbidden = httptest.NewRecorder()
	f.srv.handleRemoveRepo(forbidden, newRepoRequest(t, f.member, http.MethodDelete, "/?purge_deployment_history=true", "github", f.org.Slug, f.repo.Slug))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("member purge status=%d", forbidden.Code)
	}
	f.assertIntact(t)
}

func TestInactiveDeploymentHistoryRequiresExplicitConsent(t *testing.T) {
	f := newRepoRemovalFixture(t)
	addRemovalDeployment(t, f, store.DeploymentStatusRolledBack)
	if err := f.srv.queries.DeleteRepository(context.Background(), f.repo.ID); !errors.Is(err, store.ErrRepositoryHasDeployments) {
		t.Fatalf("default deletion failed to protect history: %v", err)
	}
	for _, query := range []string{"", "purge_deployment_history=false"} {
		response := removeRepositoryWithQuery(t, f, query)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "explicitly confirm") {
			t.Fatalf("default status=%d body=%s", response.Code, response.Body.String())
		}
		f.assertIntact(t)
	}
}

func TestExplicitHistoryPurgeDeletesOnlyInactiveRepositoryHistory(t *testing.T) {
	f := newRepoRemovalFixture(t)
	rolledBack := addRemovalDeployment(t, f, store.DeploymentStatusRolledBack)
	addRemovalDeployment(t, f, store.DeploymentStatusSuperseded)
	ctx := context.Background()
	otherRepo := createUploadTestRepository(t, f.srv, f.org)
	ref, err := f.srv.queries.CreateRef(ctx, otherRepo.ID, "v1.0.0", store.RefTypeTag, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	release, err := f.srv.queries.UpsertRelease(ctx, store.UpsertReleaseParams{RepoID: otherRepo.ID, RefID: ref.ID, Version: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	otherDeployment, err := f.srv.queries.CreateDeployment(ctx, rolledBack.ClientID, release.ID, "fixture", store.DeploymentStatusActive, time.Now().UTC(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := removeRepositoryWithQuery(t, f, "purge_deployment_history=true")
	if response.Code != http.StatusNoContent {
		t.Fatalf("purge status=%d body=%s", response.Code, response.Body.String())
	}
	var remaining, clients int
	if err := f.srv.db.QueryRowContext(ctx, `SELECT count(*) FROM deployments WHERE release_id=$1`, f.releaseID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("owned history count=%d err=%v", remaining, err)
	}
	if err := f.srv.db.QueryRowContext(ctx, `SELECT count(*) FROM clients WHERE id=$1`, rolledBack.ClientID).Scan(&clients); err != nil || clients != 1 {
		t.Fatalf("client record lost: count=%d err=%v", clients, err)
	}
	if err := f.srv.db.QueryRowContext(ctx, `SELECT count(*) FROM deployments WHERE id=$1 AND status='active'`, otherDeployment.ID).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("other repository deployment lost: count=%d err=%v", remaining, err)
	}
	inc, err := f.srv.queries.Incidents().GetIncident(ctx, f.incidentID)
	if err != nil || inc.RepoID.Valid || !inc.RemovedRepoName.Valid || inc.RemovedRepoName.String != f.repo.Name {
		t.Fatalf("incident not retained: %+v err=%v", inc, err)
	}
	if reader, err := f.srv.objStore.Get(ctx, f.objectKey); !errors.Is(err, fs.ErrNotExist) {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("artifact bytes not removed after successful purge: %v", err)
	}
	var raw []byte
	if err := f.srv.db.QueryRowContext(ctx, `SELECT context FROM audit_logs WHERE action=$1 AND resource_id=$2 ORDER BY created_at DESC LIMIT 1`,
		audit.ActionRepoRemoved, f.repo.ID.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var auditContext struct {
		Purge bool `json:"purge_inactive_deployment_history"`
	}
	if err := json.Unmarshal(raw, &auditContext); err != nil || !auditContext.Purge {
		t.Fatalf("explicit purge not audited: context=%s err=%v", raw, err)
	}
}

func TestExplicitHistoryPurgeNeverDeletesActiveDeployments(t *testing.T) {
	f := newRepoRemovalFixture(t)
	deployment := addRemovalDeployment(t, f, store.DeploymentStatusActive)
	response := removeRepositoryWithQuery(t, f, "purge_deployment_history=true")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "active client deployments") {
		t.Fatalf("active purge status=%d body=%s", response.Code, response.Body.String())
	}
	f.assertIntact(t)
	var count int
	if err := f.srv.db.QueryRow(`SELECT count(*) FROM deployments WHERE id=$1 AND status='active'`, deployment.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("active deployment lost: count=%d err=%v", count, err)
	}
}

func TestHistoryPurgeRollsBackWhenIncidentDetachmentFails(t *testing.T) {
	f := newRepoRemovalFixture(t)
	deployment := addRemovalDeployment(t, f, store.DeploymentStatusRolledBack)
	if _, err := f.srv.db.Exec(`INSERT INTO incidents (org_id,number,kind,title,signal_source,subject_type,subject_id)
		VALUES ($1,2,'policy_breach','Fixture org incident','test','fingerprint','fixture-subject')`, f.org.ID); err != nil {
		t.Fatal(err)
	}
	response := removeRepositoryWithQuery(t, f, "purge_deployment_history=true")
	if response.Code != http.StatusConflict {
		t.Fatalf("collision status=%d body=%s", response.Code, response.Body.String())
	}
	f.assertIntact(t)
	var count int
	if err := f.srv.db.QueryRow(`SELECT count(*) FROM deployments WHERE id=$1 AND status='rolled_back'`, deployment.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("history purge failed to roll back: count=%d err=%v", count, err)
	}
}

func TestRepositoryRemovalRejectsInvalidPurgeConsent(t *testing.T) {
	f := newRepoRemovalFixture(t)
	for _, query := range []string{"purge_deployment_history=", "purge_deployment_history=yes", "purge_deployment_history=true&purge_deployment_history=false"} {
		response := removeRepositoryWithQuery(t, f, query)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid consent status=%d query=%s", response.Code, query)
		}
		f.assertIntact(t)
	}
}

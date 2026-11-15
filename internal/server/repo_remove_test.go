package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type repoRemovalFixture struct {
	srv        *Server
	org        *store.Organization
	repo       *store.Repository
	admin      *store.User
	member     *store.User
	releaseID  uuid.UUID
	incidentID uuid.UUID
	objectKey  string
}

func newRepoRemovalFixture(t *testing.T) repoRemovalFixture {
	t.Helper()
	srv, org, admin, member := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "v1.0.0", store.RefTypeTag, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, "fixture", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	release, err := srv.queries.UpsertRelease(ctx, store.UpsertReleaseParams{RepoID: repo.ID, RefID: ref.ID, SnapshotID: &snapshot.ID, Version: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var incidentID uuid.UUID
	if err := srv.db.QueryRowContext(ctx, `INSERT INTO incidents (org_id,number,repo_id,kind,title,signal_source,subject_type,subject_id)
		VALUES ($1,1,$2,'policy_breach','Fixture incident','test','fingerprint','fixture-subject') RETURNING id`, org.ID, repo.ID).Scan(&incidentID); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.db.ExecContext(ctx, `INSERT INTO incident_scope (incident_id,subject_type,subject_id,label,status)
		VALUES ($1,'release',$2,'Fixture release','affected')`, incidentID, release.ID.String()); err != nil {
		t.Fatal(err)
	}
	objectKey := "fixture/" + snapshot.ID.String() + "/report"
	if err := srv.objStore.Put(ctx, objectKey, strings.NewReader("fixture report"), "text/plain"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.queries.CreateSnapshotArtifact(ctx, store.CreateSnapshotArtifactParams{
		SnapshotID: snapshot.ID, Kind: "sarif", ObjectKey: objectKey, SizeBytes: int64(len("fixture report")), Filename: "fixture.sarif",
	}); err != nil {
		t.Fatal(err)
	}
	return repoRemovalFixture{srv: srv, org: org, repo: repo, admin: admin, member: member, releaseID: release.ID, incidentID: incidentID, objectKey: objectKey}
}

func (f repoRemovalFixture) remove(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	f.srv.handleRemoveRepo(response, newRepoRequest(t, f.admin, http.MethodDelete, "/", "github", f.org.Slug, f.repo.Slug))
	return response
}

func (f repoRemovalFixture) assertIntact(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	repo, err := f.srv.queries.GetRepositoryByID(ctx, f.repo.ID)
	if err != nil || repo == nil {
		t.Fatalf("repository lost: %+v err=%v", repo, err)
	}
	var releases int
	if err := f.srv.db.QueryRowContext(ctx, `SELECT count(*) FROM releases WHERE id=$1`, f.releaseID).Scan(&releases); err != nil || releases != 1 {
		t.Fatalf("release lost: count=%d err=%v", releases, err)
	}
	inc, err := f.srv.queries.Incidents().GetIncident(ctx, f.incidentID)
	if err != nil || !inc.RepoID.Valid || inc.RepoID.UUID != f.repo.ID || inc.RemovedRepoName.Valid {
		t.Fatalf("incident changed: %+v err=%v", inc, err)
	}
	reader, err := f.srv.objStore.Get(ctx, f.objectKey)
	if err != nil {
		t.Fatalf("artifact bytes lost: %v", err)
	}
	content, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil || string(content) != "fixture report" {
		t.Fatalf("artifact content=%q err=%v", content, err)
	}
}

func TestDeleteRepositoryWithReleasesAndIncident(t *testing.T) {
	f := newRepoRemovalFixture(t)
	tx, err := f.srv.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, deleteErr := tx.ExecContext(context.Background(), `DELETE FROM repositories WHERE id=$1`, f.repo.ID)
	rollbackErr := tx.Rollback()
	var constraintErr *pq.Error
	if !errors.As(deleteErr, &constraintErr) || (constraintErr.Code != "23503" && constraintErr.Code != "23001") || rollbackErr != nil {
		t.Fatalf("bare deletion should reproduce the FK failure: delete=%v rollback=%v", deleteErr, rollbackErr)
	}
	f.assertIntact(t)
	response := f.remove(t)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	ctx := context.Background()
	for _, query := range []string{`SELECT count(*) FROM repositories WHERE id=$1`, `SELECT count(*) FROM releases WHERE repo_id=$1`} {
		var count int
		if err := f.srv.db.QueryRowContext(ctx, query, f.repo.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("retained rows=%d err=%v", count, err)
		}
	}
	inc, err := f.srv.queries.Incidents().GetIncident(ctx, f.incidentID)
	if err != nil || inc.RepoID.Valid || !inc.RemovedRepoName.Valid || inc.RemovedRepoName.String != f.repo.Name {
		t.Fatalf("retained incident=%+v err=%v", inc, err)
	}
	if reader, err := f.srv.objStore.Get(ctx, f.objectKey); !errors.Is(err, fs.ErrNotExist) {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("artifact not purged after successful delete: %v", err)
	}
	if _, err := f.srv.reconcileIncident(ctx, inc.ID); err != nil {
		t.Fatal(err)
	}
	scope, err := f.srv.queries.Incidents().ListIncidentScope(ctx, inc.ID)
	if err != nil || len(scope) != 1 || scope[0].Status != "affected" {
		t.Fatalf("retained scope changed: %+v err=%v", scope, err)
	}
	list := httptest.NewRecorder()
	f.srv.handleListIncidents(list, newOrgRequest(t, f.admin, http.MethodGet, "/", "github", f.org.Slug))
	var body struct {
		Data []incidentSummary `json:"data"`
	}
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	if err := json.Unmarshal(list.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 || body.Data[0].RepoName != f.repo.Name || body.Data[0].RepoSlug != "" || !body.Data[0].RemovedRepoName.Valid {
		t.Fatalf("removed incident label lost: %+v", body.Data)
	}
	detail, err := f.srv.incidentDetail(newOrgRequest(t, f.admin, http.MethodGet, "/", "github", f.org.Slug), f.org, inc)
	if err != nil || detail.Incident.RepoName != f.repo.Name || detail.Incident.RepoSlug != "" {
		t.Fatalf("detail label=%+v err=%v", detail.Incident, err)
	}
	_, err = f.srv.queries.Incidents().FindIncidentForSubject(ctx, dbgen.FindIncidentForSubjectParams{
		OrgID: f.org.ID, Kind: inc.Kind, SubjectType: inc.SubjectType, SubjectID: inc.SubjectID,
	})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("detached repository incident matched as org-wide: %v", err)
	}
}

func TestDeleteRepositoryWithDeploymentsLeavesEverythingIntact(t *testing.T) {
	f := newRepoRemovalFixture(t)
	ctx := context.Background()
	client, err := f.srv.queries.CreateClient(ctx, f.org.ID, "Fixture Client", "fixture-client", json.RawMessage(`{}`), "external", nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.queries.CreateDeployment(ctx, client.ID, f.releaseID, "fixture", store.DeploymentStatusActive, time.Now().UTC(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.queries.DeleteRepository(ctx, f.repo.ID); !errors.Is(err, store.ErrRepositoryHasActiveDeployments) {
		t.Fatalf("deployment blocker=%v", err)
	}
	var log bytes.Buffer
	f.srv.log = zerolog.New(&log)
	response := f.remove(t)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "active client deployments") || !strings.Contains(log.String(), "active deployments") {
		t.Fatalf("status=%d body=%s log=%s", response.Code, response.Body.String(), log.String())
	}
	f.assertIntact(t)
}

func TestDeleteRepositoryIncidentCollisionRollsBack(t *testing.T) {
	f := newRepoRemovalFixture(t)
	ctx := context.Background()
	if _, err := f.srv.db.ExecContext(ctx, `INSERT INTO incidents (org_id,number,kind,title,signal_source,subject_type,subject_id)
		VALUES ($1,2,'policy_breach','Fixture org incident','test','fingerprint','fixture-subject')`, f.org.ID); err != nil {
		t.Fatal(err)
	}
	response := f.remove(t)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "incidents_open_subject") {
		t.Fatalf("collision status=%d body=%s", response.Code, response.Body.String())
	}
	f.assertIntact(t)
}

func TestDeleteRepositoryJoinsCallerTransaction(t *testing.T) {
	f := newRepoRemovalFixture(t)
	ctx := context.Background()
	tx, err := f.srv.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := f.srv.queries.WithTx(tx).DeleteRepository(ctx, f.repo.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM repositories WHERE id=$1`, f.repo.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("caller transaction did not see deletion: count=%d err=%v", count, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	f.assertIntact(t)
}

func TestDeleteRepositoryLateConstraintFailurePreservesArtifacts(t *testing.T) {
	f := newRepoRemovalFixture(t)
	ctx := context.Background()
	table := pq.QuoteIdentifier("repo_remove_blocker_" + strings.ReplaceAll(uuid.NewString(), "-", ""))
	if _, err := f.srv.db.ExecContext(ctx, `CREATE TABLE `+table+` (
		repo_id uuid CONSTRAINT repo_remove_test_restrict_fkey REFERENCES repositories(id) ON DELETE RESTRICT
	)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.srv.db.ExecContext(ctx, `DROP TABLE `+table); err != nil {
			t.Errorf("drop fixture blocker table: %v", err)
		}
	})
	if _, err := f.srv.db.ExecContext(ctx, `INSERT INTO `+table+` VALUES ($1)`, f.repo.ID); err != nil {
		t.Fatal(err)
	}
	response := f.remove(t)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "repo_remove_test_restrict_fkey") {
		t.Fatalf("late blocker status=%d body=%s", response.Code, response.Body.String())
	}
	f.assertIntact(t)
}

func TestDeleteRepositorySerializesWithIncidentReconciliation(t *testing.T) {
	f := newRepoRemovalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reconcileTx, err := f.srv.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reconcileTx.Rollback() }()
	if _, err := f.srv.queries.WithTx(reconcileTx).Incidents().GetIncidentForUpdate(ctx, f.incidentID); err != nil {
		t.Fatal(err)
	}
	removeTx, err := f.srv.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = removeTx.Rollback() }()
	var pid int
	if err := removeTx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		if err := f.srv.queries.WithTx(removeTx).DeleteRepository(ctx, f.repo.ID); err != nil {
			done <- err
			return
		}
		done <- removeTx.Commit()
	}()
	for {
		var blocked bool
		if err := f.srv.db.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock'
		)`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("removal bypassed the incident reconciliation lock: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err := reconcileTx.ExecContext(ctx, `UPDATE incident_scope SET status='not_affected' WHERE incident_id=$1`, f.incidentID); err != nil {
		t.Fatal(err)
	}
	if err := reconcileTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.reconcileIncident(ctx, f.incidentID); err != nil {
		t.Fatal(err)
	}
	scope, err := f.srv.queries.Incidents().ListIncidentScope(ctx, f.incidentID)
	if err != nil || len(scope) != 1 || scope[0].Status != "not_affected" {
		t.Fatalf("retained reconciled scope=%+v err=%v", scope, err)
	}
}

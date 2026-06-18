package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type failingPutObjStore struct {
	putErr error
}

type recordingObjStore struct {
	existsResult bool
	deleteErr    error
	deleted      []string
	puts         []string
	exists       []string
}

type uploadArtifactExpectation struct {
	name            string
	artifactContent []byte
	extra           map[string]any
	prepare         func(*testing.T, *Server)
	wantKind        string
	wantFormat      *string
	wantTool        *string
	wantContentType string
}

func (s *failingPutObjStore) Put(context.Context, string, io.Reader, string) error { return s.putErr }
func (s *failingPutObjStore) Get(context.Context, string) (io.ReadCloser, error)   { return nil, nil }
func (s *failingPutObjStore) Exists(context.Context, string) (bool, error)         { return false, nil }
func (s *failingPutObjStore) Delete(context.Context, string) error                 { return nil }

func (s *recordingObjStore) Put(_ context.Context, key string, _ io.Reader, _ string) error {
	s.puts = append(s.puts, key)
	return nil
}

func (s *recordingObjStore) Get(context.Context, string) (io.ReadCloser, error) {
	return nil, nil
}

func (s *recordingObjStore) Exists(_ context.Context, key string) (bool, error) {
	s.exists = append(s.exists, key)
	return s.existsResult, nil
}

func (s *recordingObjStore) Delete(_ context.Context, key string) error {
	s.deleted = append(s.deleted, key)
	return s.deleteErr
}

func TestUploadAutoReusesSnapshotForSameRefCommit(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	first := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "abc123",
		"run_id":     "run-1",
		"expect":     2,
		"complete":   false,
	}))
	second := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "abc123",
		"run_id":     "run-1",
		"run_number": "2",
		"complete":   false,
	}))

	if first.SnapshotID != second.SnapshotID {
		t.Fatalf("expected same snapshot id, got %s and %s", first.SnapshotID, second.SnapshotID)
	}

	ref, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "main", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	snapshot, err := srv.queries.GetSnapshotByRefCommit(context.Background(), ref.ID, "abc123")
	if err != nil {
		t.Fatalf("GetSnapshotByRefCommit: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot to be stored")
	}
	if snapshot.ReceivedUploads != 2 {
		t.Fatalf("received_uploads = %d, want 2", snapshot.ReceivedUploads)
	}
	if snapshot.ExpectedUploads == nil || *snapshot.ExpectedUploads != 2 {
		t.Fatalf("expected_uploads = %v, want 2", snapshot.ExpectedUploads)
	}
	if snapshot.Status != store.SnapshotStatusComplete {
		t.Fatalf("status = %s, want complete", snapshot.Status)
	}
}

func TestUploadAutoCreatesDistinctSnapshotsForDifferentRunAttempt(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	first := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":         "refs/heads/main",
		"commit_sha":  "attempt123",
		"run_id":      "run-42",
		"run_attempt": "1",
		"complete":    false,
	}))
	second := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"ref":         "refs/heads/main",
		"commit_sha":  "attempt123",
		"run_id":      "run-42",
		"run_attempt": "2",
		"complete":    false,
	}))

	if first.SnapshotID == second.SnapshotID {
		t.Fatalf("expected distinct snapshot ids for different run_attempt, got %s", first.SnapshotID)
	}

	firstID := snapshotIDFromResponse(t, first)
	storedFirst, err := srv.queries.GetSnapshotByID(context.Background(), firstID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(first): %v", err)
	}
	if storedFirst == nil || storedFirst.RunAttempt == nil || *storedFirst.RunAttempt != "1" {
		t.Fatalf("first snapshot run_attempt = %v, want 1", storedFirst)
	}
}

func TestUploadAutoCreatesNewAttemptAfterPreviousBuildFinished(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	commitSHA := "gitlab-retry-finished"
	runID := "pipeline-42"

	first := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   false,
	}))

	completed := performUploadAuto(t, srv, admin, map[string]any{
		"provider":   "github",
		"org":        org.Slug,
		"repo":       repo.Slug,
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   true,
	})
	if completed.SnapshotID != first.SnapshotID {
		t.Fatalf("completed snapshot id = %s, want %s", completed.SnapshotID, first.SnapshotID)
	}

	second := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   false,
	}))
	if second.SnapshotID == first.SnapshotID {
		t.Fatalf("expected retry upload to create distinct snapshot, got %s", second.SnapshotID)
	}

	secondSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotIDFromResponse(t, second))
	if err != nil {
		t.Fatalf("GetSnapshotByID(second): %v", err)
	}
	if secondSnapshot == nil || secondSnapshot.RunAttempt == nil || strings.TrimSpace(*secondSnapshot.RunAttempt) == "" {
		t.Fatalf("second snapshot run_attempt = %#v, want synthetic attempt", secondSnapshot)
	}
}

func TestUploadAutoAttachesWithinPendingBuild(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	commitSHA := "gitlab-retry-pending"
	runID := "pipeline-77"

	first := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"expect":     3,
		"complete":   false,
	}))
	second := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"expect":     3,
		"complete":   false,
	}))

	if first.SnapshotID != second.SnapshotID {
		t.Fatalf("expected pending uploads to attach to same snapshot, got %s and %s", first.SnapshotID, second.SnapshotID)
	}

	ref, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "main", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotIDFromResponse(t, first))
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot to exist")
	}
	if snapshot.RunAttempt != nil {
		t.Fatalf("run_attempt = %v, want nil for pending build", snapshot.RunAttempt)
	}
	latest, err := srv.queries.GetLatestSnapshotForBuild(context.Background(), ref.ID, commitSHA, stringPtrForTest(runID))
	if err != nil {
		t.Fatalf("GetLatestSnapshotForBuild: %v", err)
	}
	if latest == nil || latest.ID != snapshot.ID {
		t.Fatalf("latest snapshot = %#v, want %s", latest, snapshot.ID)
	}
}

func TestUploadAutoAttachesWithinPendingSyntheticRetryAttempt(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	commitSHA := "gitlab-retry-pending-synthetic"
	runID := "pipeline-78"

	first := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   false,
	}))
	performUploadAuto(t, srv, admin, map[string]any{
		"provider":   "github",
		"org":        org.Slug,
		"repo":       repo.Slug,
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   true,
	})
	retryFirst := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   false,
	}))
	retrySecond := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   false,
	}))

	if retryFirst.SnapshotID != retrySecond.SnapshotID {
		t.Fatalf("expected retry uploads to attach to same synthetic snapshot, got %s and %s", retryFirst.SnapshotID, retrySecond.SnapshotID)
	}
	if retryFirst.SnapshotID == first.SnapshotID {
		t.Fatalf("retry upload attached to original snapshot %s", retryFirst.SnapshotID)
	}

	firstSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotIDFromResponse(t, first))
	if err != nil {
		t.Fatalf("GetSnapshotByID(first): %v", err)
	}
	retrySnapshotID := snapshotIDFromResponse(t, retryFirst)
	retrySnapshot, err := srv.queries.GetSnapshotByID(context.Background(), retrySnapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(retry): %v", err)
	}
	if firstSnapshot == nil || firstSnapshot.Status != store.SnapshotStatusComplete {
		t.Fatalf("first snapshot status = %#v, want complete", firstSnapshot)
	}
	if retrySnapshot == nil || retrySnapshot.RunAttempt == nil || *retrySnapshot.RunAttempt != "1" {
		t.Fatalf("retry snapshot run_attempt = %#v, want synthetic attempt 1", retrySnapshot)
	}
	assertSnapshotReceivedUploads(t, srv, retrySnapshotID, 2)

	ref, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "main", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	latest, err := srv.queries.GetLatestSnapshotForBuild(context.Background(), ref.ID, commitSHA, stringPtrForTest(runID))
	if err != nil {
		t.Fatalf("GetLatestSnapshotForBuild: %v", err)
	}
	if latest == nil || latest.ID != retrySnapshotID {
		t.Fatalf("latest snapshot = %#v, want retry snapshot %s", latest, retrySnapshotID)
	}
}

func TestUploadCompleteTargetsLatestAttemptForGitLabRetry(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	commitSHA := "gitlab-retry-complete"
	runID := "pipeline-99"

	first := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   false,
	}))
	performUploadAuto(t, srv, admin, map[string]any{
		"provider":   "github",
		"org":        org.Slug,
		"repo":       repo.Slug,
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   true,
	})
	second := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   false,
	}))

	completed := performUploadAuto(t, srv, admin, map[string]any{
		"provider":   "github",
		"org":        org.Slug,
		"repo":       repo.Slug,
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"complete":   true,
	})
	if completed.SnapshotID != second.SnapshotID {
		t.Fatalf("completed snapshot id = %s, want latest attempt %s", completed.SnapshotID, second.SnapshotID)
	}
	if completed.SnapshotID == first.SnapshotID {
		t.Fatalf("completion targeted old snapshot id %s", completed.SnapshotID)
	}

	firstSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotIDFromResponse(t, first))
	if err != nil {
		t.Fatalf("GetSnapshotByID(first): %v", err)
	}
	secondSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotIDFromResponse(t, second))
	if err != nil {
		t.Fatalf("GetSnapshotByID(second): %v", err)
	}
	if firstSnapshot == nil || firstSnapshot.Status != store.SnapshotStatusComplete {
		t.Fatalf("first snapshot status = %#v, want complete", firstSnapshot)
	}
	if secondSnapshot == nil || secondSnapshot.Status != store.SnapshotStatusComplete {
		t.Fatalf("second snapshot status = %#v, want complete", secondSnapshot)
	}
}

func TestUploadAutoCompleteTrueTransitionsSnapshot(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	response := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "def456",
		"complete":   true,
	}))

	if response.Status != string(store.SnapshotStatusComplete) {
		t.Fatalf("status = %s, want complete", response.Status)
	}
}

func TestUploadAutoCoverageStaysPendingWithoutCompletionSignal(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	response := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalCoberturaForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "cov123",
		"complete":   false,
	}))

	if response.Status != string(store.SnapshotStatusPending) {
		t.Fatalf("status = %s, want pending", response.Status)
	}
}

func TestUploadAutoCompleteWithoutArtifactClosesExistingSnapshot(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "fin123",
		"complete":   false,
	}))

	response := performUploadAuto(t, srv, admin, map[string]any{
		"provider":   "github",
		"org":        org.Slug,
		"repo":       repo.Slug,
		"ref":        "refs/heads/main",
		"commit_sha": "fin123",
		"complete":   true,
	})

	if response.Status != string(store.SnapshotStatusComplete) {
		t.Fatalf("status = %s, want complete", response.Status)
	}
}

func TestUploadAutoCompleteWithoutArtifactReturnsNotFoundWhenSnapshotMissing(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	payload := map[string]any{
		"provider":   "github",
		"org":        org.Slug,
		"repo":       repo.Slug,
		"ref":        "refs/heads/main",
		"commit_sha": "missing123",
		"complete":   true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(internalauth.WithUser(req.Context(), admin))
	recorder := httptest.NewRecorder()

	srv.handleUploadAuto(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNotFound, recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "no pending snapshot for ref/commit") {
		t.Fatalf("response = %s, want missing snapshot error", recorder.Body.String())
	}
	ref, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "main", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	if ref == nil {
		t.Fatal("expected ref to exist after completion lookup")
	}
	snapshot, err := srv.queries.GetSnapshotByRefCommit(context.Background(), ref.ID, "missing123")
	if err != nil {
		t.Fatalf("GetSnapshotByRefCommit: %v", err)
	}
	if snapshot != nil {
		t.Fatalf("snapshot = %+v, want nil", snapshot)
	}
}

func TestUploadAutoCompleteWithoutArtifactReturnsConflictWhenSnapshotTimedOut(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	commitSHA := "timed-out-complete"

	performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"complete":   false,
	}))

	ref, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "main", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	snapshot, err := srv.queries.GetSnapshotByRefCommit(context.Background(), ref.ID, commitSHA)
	if err != nil {
		t.Fatalf("GetSnapshotByRefCommit: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot to exist")
	}
	if _, err := srv.queries.UpdateSnapshotStatus(context.Background(), snapshot.ID, store.SnapshotStatusFailed); err != nil {
		t.Fatalf("UpdateSnapshotStatus: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"provider":   "github",
		"org":        org.Slug,
		"repo":       repo.Slug,
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"complete":   true,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(internalauth.WithUser(req.Context(), admin))
	recorder := httptest.NewRecorder()

	srv.handleUploadAuto(recorder, req)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d: %s", http.StatusConflict, recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "snapshot already finalized or timed out") {
		t.Fatalf("response = %s, want finalized snapshot error", recorder.Body.String())
	}
	storedSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshot.ID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if storedSnapshot == nil || storedSnapshot.Status != store.SnapshotStatusFailed {
		t.Fatalf("snapshot status = %#v, want failed", storedSnapshot)
	}
}

func TestUploadAutoArtifactAfterFailedSnapshotCreatesNewSyntheticAttempt(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	commitSHA := "timed-out-expected"
	runID := "run-timeout-expected"

	performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"expect":     2,
		"complete":   false,
	}))

	ref, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "main", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	snapshot, err := srv.queries.GetSnapshotByBuildIdentity(context.Background(), ref.ID, commitSHA, stringPtrForTest(runID), nil)
	if err != nil {
		t.Fatalf("GetSnapshotByBuildIdentity: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot to exist")
	}
	if _, err := srv.queries.UpdateSnapshotStatus(context.Background(), snapshot.ID, store.SnapshotStatusFailed); err != nil {
		t.Fatalf("UpdateSnapshotStatus: %v", err)
	}

	response := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": commitSHA,
		"run_id":     runID,
		"expect":     2,
		"complete":   false,
	}))

	if response.Status != string(store.SnapshotStatusPending) {
		t.Fatalf("status = %s, want pending for new synthetic attempt", response.Status)
	}
	storedSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshot.ID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if storedSnapshot == nil || storedSnapshot.Status != store.SnapshotStatusFailed {
		t.Fatalf("original snapshot status = %#v, want failed", storedSnapshot)
	}

	newSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotIDFromResponse(t, response))
	if err != nil {
		t.Fatalf("GetSnapshotByID(new): %v", err)
	}
	if newSnapshot == nil {
		t.Fatal("expected new synthetic snapshot to exist")
	}
	if newSnapshot.ID == snapshot.ID {
		t.Fatalf("expected new synthetic snapshot id, got original %s", newSnapshot.ID)
	}
	if newSnapshot.Status != store.SnapshotStatusPending {
		t.Fatalf("new snapshot status = %#v, want pending", newSnapshot)
	}
	if newSnapshot.RunAttempt == nil || strings.TrimSpace(*newSnapshot.RunAttempt) == "" {
		t.Fatalf("new snapshot run_attempt = %#v, want synthetic attempt", newSnapshot)
	}
}

func TestUploadAutoTagDerivedFromTagRef(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	response := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/tags/v1.2.3",
		"commit_sha": "tag123",
		"complete":   true,
	}))

	if response.Status != string(store.SnapshotStatusComplete) {
		t.Fatalf("status = %s, want complete", response.Status)
	}
	ref, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "v1.2.3", store.RefTypeTag)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	snapshot, err := srv.queries.GetSnapshotByRefCommit(context.Background(), ref.ID, "tag123")
	if err != nil {
		t.Fatalf("GetSnapshotByRefCommit: %v", err)
	}
	if snapshot == nil || snapshot.Tag == nil || *snapshot.Tag != "v1.2.3" {
		t.Fatalf("tag = %v, want v1.2.3", snapshot)
	}
}

func TestUploadAutoCreatesSnapshotArtifactWhenObjectStoreConfigured(t *testing.T) {
	t.Parallel()

	tests := []uploadArtifactExpectation{
		{
			name:            "sbom",
			artifactContent: minimalSBOMForTest(),
			extra: map[string]any{
				"ref":        "refs/heads/main",
				"commit_sha": "artifact123",
				"complete":   true,
			},
			wantKind:        "sbom",
			wantFormat:      stringPtrForTest("cyclonedx-json"),
			wantContentType: "application/json",
		},
		{
			name:            "sarif",
			artifactContent: minimalSARIFForTest(),
			extra: map[string]any{
				"ref":        "refs/heads/main",
				"commit_sha": "artifact-sarif",
				"complete":   true,
			},
			wantKind:        "sarif",
			wantTool:        stringPtrForTest("semgrep"),
			wantContentType: "application/sarif+json",
		},
		{
			name:            "coverage",
			artifactContent: minimalCoberturaForTest(),
			extra: map[string]any{
				"ref":        "refs/heads/main",
				"commit_sha": "artifact-coverage",
				"complete":   true,
			},
			wantKind:        "coverage",
			wantFormat:      stringPtrForTest("cobertura"),
			wantContentType: "application/xml",
		},
		{
			name:            "vex",
			artifactContent: minimalOpenVEXForTest(),
			extra: map[string]any{
				"ref":        "refs/heads/main",
				"commit_sha": "artifact-vex",
				"complete":   true,
			},
			prepare:         seedVEXAdvisoryForTest,
			wantKind:        "vex",
			wantFormat:      stringPtrForTest("openvex"),
			wantContentType: "application/json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertSnapshotArtifactPersistedForUpload(t, tc)
		})
	}
}

func TestUploadAutoPutFailureDoesNotIncrementReceivedUploads(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	srv.objStore = &failingPutObjStore{putErr: errors.New("put failed")}
	repo := createUploadTestRepository(t, srv, org)

	recorder := performUploadAutoRecorder(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "put-failure",
		"expect":     1,
		"complete":   false,
	}))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d: %s", http.StatusInternalServerError, recorder.Code, recorder.Body.String())
	}

	ref, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "main", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	if ref == nil {
		t.Fatal("expected ref to exist")
	}
	snapshot, err := srv.queries.GetSnapshotByRefCommit(context.Background(), ref.ID, "put-failure")
	if err != nil {
		t.Fatalf("GetSnapshotByRefCommit: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected pending snapshot to be created")
	}
	if snapshot.ReceivedUploads != 0 {
		t.Fatalf("received_uploads = %d, want 0", snapshot.ReceivedUploads)
	}
	if snapshot.Status != store.SnapshotStatusPending {
		t.Fatalf("status = %s, want pending", snapshot.Status)
	}
	artifacts, err := srv.queries.ListSnapshotArtifactsBySnapshot(context.Background(), snapshot.ID)
	if err != nil {
		t.Fatalf("ListSnapshotArtifactsBySnapshot: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("artifact rows = %d, want 0", len(artifacts))
	}
}

func TestAdvanceUploadSnapshotCleansUpOnlyNewBlobOnFinalizeFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		preExisted      bool
		wantDeleteCalls int
	}{
		{
			name:            "delete new blob",
			preExisted:      false,
			wantDeleteCalls: 1,
		},
		{
			name:            "keep shared existing blob",
			preExisted:      true,
			wantDeleteCalls: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, snapshot, artifact, wantKey := newAdvanceUploadSnapshotFailureCase(t, tc.preExisted)

			_, err := srv.advanceUploadSnapshot(context.Background(), snapshot.ID, artifact)
			if err == nil {
				t.Fatal("advanceUploadSnapshot error = nil, want finalize failure")
			}

			assertRecordingObjStoreCalls(t, srv.objStore.(*recordingObjStore), wantKey, tc.wantDeleteCalls)
			assertSnapshotAdvanceFailedState(t, srv, snapshot.ID)
		})
	}
}

func TestUploadAutoSkipsSnapshotArtifactWhenObjectStoreNil(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	response := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "artifact456",
		"complete":   true,
	}))

	artifacts, err := srv.queries.ListSnapshotArtifactsBySnapshot(context.Background(), snapshotIDFromResponse(t, response))
	if err != nil {
		t.Fatalf("ListSnapshotArtifactsBySnapshot: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("artifact rows = %d, want 0", len(artifacts))
	}
}

func createUploadTestRepository(t *testing.T, srv *Server, org *store.Organization) *store.Repository {
	t.Helper()

	repo, err := srv.queries.CreateRepository(context.Background(), org.ID, nil, uniqueName(t, "upload-repo"), uniqueName(t, "upload-repo"), "github", uniqueName(t, "upload-provider-id"), "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	return repo
}

func performUploadAuto(t *testing.T, srv *Server, user *store.User, payload map[string]any) uploadResponse {
	t.Helper()

	recorder := performUploadAutoRecorder(t, srv, user, payload)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d: %s", http.StatusAccepted, recorder.Code, recorder.Body.String())
	}

	var envelope struct {
		Data uploadResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return envelope.Data
}

func performUploadAutoRecorder(t *testing.T, srv *Server, user *store.User, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(internalauth.WithUser(req.Context(), user))
	recorder := httptest.NewRecorder()

	srv.handleUploadAuto(recorder, req)
	return recorder
}

func uploadPayloadForTest(orgSlug, repoSlug string, artifactContent []byte, extra map[string]any) map[string]any {
	payload := map[string]any{
		"provider":   "github",
		"org":        orgSlug,
		"repo":       repoSlug,
		"ref":        "refs/heads/main",
		"commit_sha": "test-sha",
		"complete":   false,
		"artifact": map[string]any{
			"filename":       "artifact.json",
			"content_base64": base64.StdEncoding.EncodeToString(artifactContent),
		},
	}
	for key, value := range extra {
		payload[key] = value
	}
	return payload
}

func minimalSBOMForTest() []byte {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`)
}

func minimalSARIFForTest() []byte {
	return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}}}]}`)
}

func minimalCoberturaForTest() []byte {
	return []byte(`<?xml version="1.0"?><coverage line-rate="0.5" branch-rate="0"><packages></packages></coverage>`)
}

func minimalOpenVEXForTest() []byte {
	return []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "@id": "doc-1",
	  "timestamp": "2026-05-29T10:00:00Z",
	  "statements": [
	    {
	      "vulnerability": {"@id": "CVE-2026-0001"},
	      "products": [{"@id": "pkg:golang/example/one@1.0.0"}],
	      "status": "affected"
	    }
	  ]
	}`)
}

func assertSnapshotArtifactPersistedForUpload(t *testing.T, tc uploadArtifactExpectation) {
	t.Helper()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	artifactDir := t.TempDir()
	artifactStore, err := objstore.NewFilesystemStore(artifactDir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	srv.objStore = artifactStore
	if tc.prepare != nil {
		tc.prepare(t, srv)
	}
	repo := createUploadTestRepository(t, srv, org)

	response := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, tc.artifactContent, tc.extra))
	snapshotID := snapshotIDFromResponse(t, response)
	assertSnapshotReceivedUploads(t, srv, snapshotID, 1)
	artifacts, err := srv.queries.ListSnapshotArtifactsBySnapshot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("ListSnapshotArtifactsBySnapshot: %v", err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("artifact rows = %d, want 1", len(artifacts))
	}
	artifact := artifacts[0]
	if artifact.Kind != tc.wantKind {
		t.Fatalf("artifact kind = %q, want %q", artifact.Kind, tc.wantKind)
	}
	assertOptionalStringEqual(t, "artifact format", artifact.Format, tc.wantFormat)
	assertOptionalStringEqual(t, "artifact tool", artifact.ToolName, tc.wantTool)
	if artifact.SHA256 == nil {
		t.Fatal("artifact sha256 = nil, want value")
	}
	if artifact.ObjectKey != snapshotArtifactObjectKey(snapshotID, *artifact.SHA256) {
		t.Fatalf("artifact object_key = %q, want %q", artifact.ObjectKey, snapshotArtifactObjectKey(snapshotID, *artifact.SHA256))
	}
	if artifact.ContentType == nil || *artifact.ContentType != tc.wantContentType {
		t.Fatalf("artifact content_type = %v, want %q", artifact.ContentType, tc.wantContentType)
	}
	if ok, err := srv.objStore.Exists(context.Background(), artifact.ObjectKey); err != nil {
		t.Fatalf("Exists(%q): %v", artifact.ObjectKey, err)
	} else if !ok {
		t.Fatalf("expected object %q to exist", artifact.ObjectKey)
	}
	if _, err := os.Stat(artifactDir); err != nil {
		t.Fatalf("artifact dir stat: %v", err)
	}
}

func newAdvanceUploadSnapshotFailureCase(t *testing.T, preExisted bool) (*Server, *store.Snapshot, *rawArtifactPayload, string) {
	t.Helper()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	objStore := &recordingObjStore{existsResult: preExisted}
	srv.objStore = objStore
	repo := createUploadTestRepository(t, srv, org)
	snapshot := createPendingSnapshotForAdvanceUploadTest(t, srv, admin.ID, org.Slug, repo.Slug)
	artifact := &rawArtifactPayload{
		kind:    "sbom",
		format:  "cyclonedx-json",
		tool:    "syft",
		content: minimalSBOMForTest(),
	}
	params := buildSnapshotArtifactParams(snapshot.ID, artifact.kind, artifact.format, artifact.tool, artifact.content)
	setAdvanceUploadSnapshotFailingDB(t, srv)
	return srv, snapshot, artifact, params.ObjectKey
}

func createPendingSnapshotForAdvanceUploadTest(t *testing.T, srv *Server, userID uuid.UUID, orgSlug, repoSlug string) *store.Snapshot {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	snapshot, err := srv.createPendingUploadSnapshot(req, userID, uploadRequest{
		Provider:  "github",
		Org:       orgSlug,
		Repo:      repoSlug,
		Ref:       "refs/heads/main",
		CommitSHA: uniqueName(t, "finalize-fail"),
	}, nil)
	if err != nil {
		t.Fatalf("createPendingUploadSnapshot: %v", err)
	}
	return snapshot
}

func setAdvanceUploadSnapshotFailingDB(t *testing.T, srv *Server) {
	t.Helper()

	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	failingDB, err := store.New(databaseURL)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := failingDB.Close(); err != nil {
		t.Fatalf("Close failing DB: %v", err)
	}
	srv.db = failingDB
}

func assertRecordingObjStoreCalls(t *testing.T, objStore *recordingObjStore, wantKey string, wantDeleteCalls int) {
	t.Helper()

	if len(objStore.exists) != 1 || objStore.exists[0] != wantKey {
		t.Fatalf("Exists calls = %v, want [%q]", objStore.exists, wantKey)
	}
	if len(objStore.puts) != 1 || objStore.puts[0] != wantKey {
		t.Fatalf("Put calls = %v, want [%q]", objStore.puts, wantKey)
	}
	if len(objStore.deleted) != wantDeleteCalls {
		t.Fatalf("Delete calls = %d, want %d", len(objStore.deleted), wantDeleteCalls)
	}
	if wantDeleteCalls == 1 && objStore.deleted[0] != wantKey {
		t.Fatalf("Delete key = %q, want %q", objStore.deleted[0], wantKey)
	}
}

func assertSnapshotAdvanceFailedState(t *testing.T, srv *Server, snapshotID uuid.UUID) {
	t.Helper()

	storedSnapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if storedSnapshot == nil {
		t.Fatal("expected snapshot to exist")
	}
	assertSnapshotReceivedUploads(t, srv, snapshotID, 0)
	artifacts, err := srv.queries.ListSnapshotArtifactsBySnapshot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("ListSnapshotArtifactsBySnapshot: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("artifact rows = %d, want 0", len(artifacts))
	}
}

func assertSnapshotReceivedUploads(t *testing.T, srv *Server, snapshotID uuid.UUID, want int) {
	t.Helper()

	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot to exist")
	}
	if snapshot.ReceivedUploads != want {
		t.Fatalf("received_uploads = %d, want %d", snapshot.ReceivedUploads, want)
	}
}

func seedVEXAdvisoryForTest(t *testing.T, srv *Server) {
	t.Helper()

	if _, err := srv.queries.UpsertAdvisory(context.Background(), dbgen.UpsertAdvisoryParams{
		CanonicalID: "CVE-2026-0001",
		Title:       "VEX test advisory",
		Description: "test advisory for uploaded VEX import",
		Severity:    dbgen.SeverityLevelLow,
		CvssScore:   sql.NullString{},
		CvssVersion: dbgen.NullCvssVersion{},
		PublishedAt: sql.NullTime{},
		WithdrawnAt: sql.NullTime{},
	}); err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}
}

func assertOptionalStringEqual(t *testing.T, label string, got, want *string) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("%s = %v, want nil", label, got)
		}
		return
	}
	if got == nil || *got != *want {
		t.Fatalf("%s = %v, want %q", label, got, *want)
	}
}

func stringPtrForTest(value string) *string {
	return &value
}

func snapshotIDFromResponse(t *testing.T, response uploadResponse) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(response.SnapshotID)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", response.SnapshotID, err)
	}
	return id
}

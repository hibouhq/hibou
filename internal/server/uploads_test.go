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
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/apitoken"
	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/retention"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/vex"
	"github.com/hibouhq/hibou/internal/ws"
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

type retentionNudgeStoreStub struct {
	started chan context.Context
	release chan struct{}
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

func (s *retentionNudgeStoreStub) ListRepositoriesForRetention(ctx context.Context) ([]store.Repository, error) {
	select {
	case s.started <- ctx:
	default:
	}
	select {
	case <-s.release:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (*retentionNudgeStoreStub) ListRefsByRepo(context.Context, uuid.UUID, int, int) ([]store.Ref, int, error) {
	panic("unexpected ListRefsByRepo call")
}

func (*retentionNudgeStoreStub) ListSnapshotsForRetentionTimeline(context.Context, uuid.UUID, uuid.UUID) ([]store.Snapshot, error) {
	panic("unexpected ListSnapshotsForRetentionTimeline call")
}

func (*retentionNudgeStoreStub) ListVulnerabilitySummaryBySnapshot(context.Context, uuid.UUID) ([]dbgen.ListVulnerabilitySummaryBySnapshotRow, error) {
	panic("unexpected ListVulnerabilitySummaryBySnapshot call")
}

func (*retentionNudgeStoreStub) ListStalePendingSnapshots(context.Context, time.Time, int32) ([]dbgen.Snapshot, error) {
	panic("unexpected ListStalePendingSnapshots call")
}

func (*retentionNudgeStoreStub) ListSnapshotArtifactObjectKeys(context.Context, uuid.UUID) ([]string, error) {
	panic("unexpected ListSnapshotArtifactObjectKeys call")
}

func (*retentionNudgeStoreStub) ArchiveSnapshot(context.Context, uuid.UUID) error {
	panic("unexpected ArchiveSnapshot call")
}

func (*retentionNudgeStoreStub) MarkSnapshotFailed(context.Context, uuid.UUID) error {
	panic("unexpected MarkSnapshotFailed call")
}

func (*retentionNudgeStoreStub) PurgeSnapshot(context.Context, uuid.UUID) error {
	panic("unexpected PurgeSnapshot call")
}

func (*retentionNudgeStoreStub) RollupSnapshotVulnerabilities(context.Context, uuid.UUID) (int64, error) {
	panic("unexpected RollupSnapshotVulnerabilities call")
}

func (*retentionNudgeStoreStub) GetSnapshotVulnRollup(context.Context, uuid.UUID) (store.SnapshotVulnRollup, bool, error) {
	panic("unexpected GetSnapshotVulnRollup call")
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
	// Auto-completion with queued SBOM/SARIF artifacts lands on processing.
	if snapshot.Status != store.SnapshotStatusProcessing {
		t.Fatalf("status = %s, want processing", snapshot.Status)
	}
}

func TestUploadAutoEnrollsUnknownRepository(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	slug := uniqueName(t, "unenrolled-repo")

	performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/release",
		"commit_sha": "enroll-sha",
	}))

	repo, err := srv.queries.GetRepositoryBySlug(context.Background(), org.ID, slug)
	if err != nil {
		t.Fatalf("GetRepositoryBySlug: %v", err)
	}
	if repo == nil {
		t.Fatal("expected the upload to enroll the repository")
	}
	if repo.SyncState != "enrolled" {
		t.Fatalf("sync_state = %q, want enrolled", repo.SyncState)
	}
	if repo.DefaultBranch != "release" {
		t.Fatalf("default_branch = %q, want release", repo.DefaultBranch)
	}
	if want := org.Slug + "/" + slug; repo.ProviderID != want {
		t.Fatalf("provider_id = %q, want %q", repo.ProviderID, want)
	}
}

func TestUploadAutoDeniedScopedTokenDoesNotEnrollRepository(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	slug := uniqueName(t, "denied-repo")
	body, err := json.Marshal(uploadPayloadForTest(org.Slug, slug, minimalSBOMForTest(), map[string]any{
		"commit_sha": "denied-enrollment",
	}))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	ctx := internalauth.WithUser(req.Context(), admin)
	ctx = internalauth.WithTokenAuth(ctx, &internalauth.TokenAuth{Scoped: true, Scope: apitoken.Scope{
		Org:   org.Slug,
		Repos: apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{"allowed-repo"}},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{
			apitoken.CapUploads: apitoken.AccessWrite,
		},
	}})
	recorder := httptest.NewRecorder()
	srv.handleUploadAuto(recorder, req.WithContext(ctx))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	repo, err := srv.queries.GetRepositoryBySlug(context.Background(), org.ID, slug)
	if err != nil {
		t.Fatalf("GetRepositoryBySlug: %v", err)
	}
	if repo != nil {
		t.Fatal("denied scoped upload must not enroll a repository")
	}
}

func TestUploadSetsPRMergeTargetWithoutWebhook(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":              "refs/pull/7/merge",
		"commit_sha":       "pr-head-sha",
		"pr_target_branch": "main",
	}))

	prRef, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "refs/pull/7", store.RefTypePullRequest)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	if prRef == nil {
		t.Fatal("expected PR ref to exist")
	}
	if prRef.MergeTargetRefID == nil {
		t.Fatal("expected upload to set the PR merge target")
	}
	targetRef, err := srv.queries.GetRefByRepoAndName(context.Background(), repo.ID, "main", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName(main): %v", err)
	}
	if targetRef == nil || *prRef.MergeTargetRefID != targetRef.ID {
		t.Fatalf("merge target = %v, want the main branch ref", prRef.MergeTargetRefID)
	}
}

func TestUploadDefaultBranchFromRef(t *testing.T) {
	t.Parallel()

	// Only a branch push says anything about the default branch; tags and pull
	// requests must not enroll a repository pointing at a throwaway ref.
	cases := map[string]string{
		"refs/heads/main":    "main",
		"refs/heads/develop": "develop",
		"refs/tags/v1.2.3":   "main",
		"refs/pull/42/merge": "main",
		"":                   "main",
	}
	for ref, want := range cases {
		if got := uploadDefaultBranchFromRef(ref); got != want {
			t.Errorf("uploadDefaultBranchFromRef(%q) = %q, want %q", ref, got, want)
		}
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

func TestPRRefDerivationHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		refName       string
		wantPRNum     string
		wantCanonical string
	}{
		{name: "github merge", refName: "refs/pull/1/merge", wantPRNum: "1", wantCanonical: "refs/pull/1"},
		{name: "github head", refName: "refs/pull/1/head", wantPRNum: "1", wantCanonical: "refs/pull/1"},
		{name: "gitlab merge", refName: "refs/merge-requests/2/merge", wantPRNum: "2", wantCanonical: "refs/merge-requests/2"},
		{name: "already canonical", refName: "refs/pull/3", wantPRNum: "3", wantCanonical: "refs/pull/3"},
		{name: "branch ref", refName: "refs/heads/main", wantPRNum: "", wantCanonical: "main"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := prNumberFromName(tt.refName); got != tt.wantPRNum {
				t.Fatalf("prNumberFromName(%q) = %q, want %q", tt.refName, got, tt.wantPRNum)
			}
			if got := normalizeStoredRefName(tt.refName); got != tt.wantCanonical {
				t.Fatalf("normalizeStoredRefName(%q) = %q, want %q", tt.refName, got, tt.wantCanonical)
			}
		})
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
	if firstSnapshot == nil || firstSnapshot.Status != store.SnapshotStatusProcessing {
		t.Fatalf("first snapshot status = %#v, want processing", firstSnapshot)
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
	if firstSnapshot == nil || firstSnapshot.Status != store.SnapshotStatusProcessing {
		t.Fatalf("first snapshot status = %#v, want processing", firstSnapshot)
	}
	if secondSnapshot == nil || secondSnapshot.Status != store.SnapshotStatusProcessing {
		t.Fatalf("second snapshot status = %#v, want processing", secondSnapshot)
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

	// Finalizing with a queued SBOM lands on processing; the artifact worker
	// flips it to complete once ingestion runs.
	if response.Status != string(store.SnapshotStatusProcessing) {
		t.Fatalf("status = %s, want processing", response.Status)
	}
}

func TestUploadAutoCompleteTriggersAsyncRetentionNudge(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	lifecycleCtx, shutdownCancel := context.WithCancel(context.Background())
	t.Cleanup(shutdownCancel)
	srv.lifecycleCtx = lifecycleCtx
	srv.shutdownCancel = shutdownCancel

	workerStore := &retentionNudgeStoreStub{
		started: make(chan context.Context, 1),
		release: make(chan struct{}),
	}
	srv.retentionWorker = retention.NewWorker(workerStore, nil, nil, nil, zerolog.New(io.Discard), retention.Preset("envelope"), 0)

	body, err := json.Marshal(uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "retention-nudge",
		"complete":   true,
	}))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(internalauth.WithUser(req.Context(), admin))
	recorder := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		srv.handleUploadAuto(recorder, req)
		close(done)
	}()

	var runCtx context.Context
	select {
	case runCtx = <-workerStore.started:
	case <-time.After(2 * time.Second):
		close(workerStore.release)
		t.Fatal("retention nudge did not start")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(workerStore.release)
		t.Fatal("upload response blocked on retention nudge")
	}

	if recorder.Code != http.StatusAccepted {
		close(workerStore.release)
		t.Fatalf("expected status %d, got %d: %s", http.StatusAccepted, recorder.Code, recorder.Body.String())
	}
	if runCtx != srv.lifecycleCtx {
		close(workerStore.release)
		t.Fatal("retention nudge context = request-scoped or unexpected context, want server lifecycle context")
	}
	select {
	case <-runCtx.Done():
		close(workerStore.release)
		t.Fatal("retention nudge context canceled before shutdown")
	default:
	}

	shutdownCancel()
	select {
	case <-runCtx.Done():
	case <-time.After(2 * time.Second):
		close(workerStore.release)
		t.Fatal("retention nudge context did not stop on shutdown")
	}
	close(workerStore.release)
	<-done
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

func TestProcessCoverageUploadIsIdempotent(t *testing.T) {
	t.Parallel()

	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest(uniqueName(t, "sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uniqueName(t, "coverage-commit"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	content := richerCoberturaForTest()
	srv.processCoverageUpload(context.Background(), snapshot.ID, content, "cobertura")
	firstState := captureCoverageProcessorState(t, srv, snapshot.ID)
	srv.processCoverageUpload(context.Background(), snapshot.ID, content, "cobertura")
	secondState := captureCoverageProcessorState(t, srv, snapshot.ID)
	if !reflect.DeepEqual(firstState, secondState) {
		t.Fatalf("coverage state changed on replay\nfirst: %#v\nsecond: %#v", firstState, secondState)
	}

	if len(secondState.Reports) != 1 {
		t.Fatalf("coverage report count = %d, want 1", len(secondState.Reports))
	}
	report := secondState.Reports[0]
	files := secondState.Files[report.Format]
	if len(files) != 1 {
		t.Fatalf("coverage file count = %d, want 1", len(files))
	}
	if files[0].FilePath != "main.go" {
		t.Fatalf("coverage file_path = %q, want main.go", files[0].FilePath)
	}

	var reportCount int
	if err := srv.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM coverage_reports WHERE snapshot_id = $1`, snapshot.ID).Scan(&reportCount); err != nil {
		t.Fatalf("count coverage_reports: %v", err)
	}
	if reportCount != 1 {
		t.Fatalf("coverage report rows = %d, want 1", reportCount)
	}
	var fileCount int
	if err := srv.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM coverage_files WHERE coverage_report_id = $1`, report.ID).Scan(&fileCount); err != nil {
		t.Fatalf("count coverage_files: %v", err)
	}
	if fileCount != 1 {
		t.Fatalf("coverage file rows = %d, want 1", fileCount)
	}
	if report.LinesValid != 2 || report.LinesCovered != 1 {
		t.Fatalf("coverage summary = %+v, want stable parsed values", report)
	}
	if files[0].LinesValid != 2 || files[0].LinesCovered != 1 {
		t.Fatalf("coverage file = %+v, want stable parsed values", files[0])
	}
}

func TestProcessCoverageUploadPersistsPerLineHits(t *testing.T) {
	t.Parallel()

	srv, org, _, _ := newDiscoveryTestServer(t)
	srv.cfg.CoverageStoreLines = true
	repo := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest(uniqueName(t, "lines-sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uniqueName(t, "coverage-lines"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	// Upload twice to prove per-line rows are replaced, not accumulated.
	srv.processCoverageUpload(context.Background(), snapshot.ID, richerCoberturaForTest(), "cobertura")
	srv.processCoverageUpload(context.Background(), snapshot.ID, richerCoberturaForTest(), "cobertura")

	lines, err := srv.queries.ListCoverageLinesBySnapshotFormat(context.Background(), snapshot.ID, "cobertura")
	if err != nil {
		t.Fatalf("ListCoverageLinesBySnapshotFormat: %v", err)
	}
	hits := make(map[int]int, len(lines))
	for _, line := range lines {
		if line.FilePath != "main.go" {
			t.Fatalf("unexpected file path %q", line.FilePath)
		}
		hits[line.LineNumber] = line.Hits
	}
	if len(hits) != 2 || hits[1] != 1 || hits[2] != 0 {
		t.Fatalf("per-line hits = %+v, want {1:1, 2:0}", hits)
	}
}

func TestProcessCoverageUploadOmitsPerLineHitsWhenDisabled(t *testing.T) {
	t.Parallel()

	srv, org, _, _ := newDiscoveryTestServer(t)
	srv.cfg.CoverageStoreLines = false
	repo := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest(uniqueName(t, "no-lines-sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uniqueName(t, "coverage-no-lines"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	srv.processCoverageUpload(context.Background(), snapshot.ID, richerCoberturaForTest(), "cobertura")

	lines, err := srv.queries.ListCoverageLinesBySnapshotFormat(context.Background(), snapshot.ID, "cobertura")
	if err != nil {
		t.Fatalf("ListCoverageLinesBySnapshotFormat: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("expected no per-line rows when storage disabled, got %d", len(lines))
	}
}

func TestProcessCoverageUploadPersistsMultipleFormatsAndCoverageEndpointReturnsAllReports(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest(uniqueName(t, "multi-format-sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uniqueName(t, "coverage-multi-format"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	srv.processCoverageUpload(context.Background(), snapshot.ID, []byte(`mode: set
github.com/example/project/alpha.go:1.1,10.1 10 1
github.com/example/project/beta.go:1.1,5.1 5 0`), "gocover")
	srv.processCoverageUpload(context.Background(), snapshot.ID, []byte(`TN:
SF:/repo/alpha.go
LF:10
LH:5
BRF:4
BRH:2
end_of_record`), "lcov")

	state := captureCoverageProcessorState(t, srv, snapshot.ID)
	if len(state.Reports) != 2 {
		t.Fatalf("coverage report count = %d, want 2", len(state.Reports))
	}
	if len(state.Files["gocover"]) != 2 {
		t.Fatalf("gocover file count = %d, want 2", len(state.Files["gocover"]))
	}
	if len(state.Files["lcov"]) != 1 {
		t.Fatalf("lcov file count = %d, want 1", len(state.Files["lcov"]))
	}

	srv.router = chi.NewRouter()
	srv.wsHub = ws.NewHub(zerolog.New(io.Discard))
	configureRouter(srv.router, zerolog.New(io.Discard))
	srv.routes(nil)

	recorder := httptest.NewRecorder()
	srv.router.ServeHTTP(recorder, newAuthenticatedRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/coverage?ref=main"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /coverage status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response coverageSummaryAPIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Data == nil {
		t.Fatal("expected coverage response data")
	}
	if response.Data.Format != "aggregate" {
		t.Fatalf("format = %q, want aggregate", response.Data.Format)
	}
	// Union of both reports: gocover alpha.go (10/10) + beta.go (0/5) + lcov
	// /repo/alpha.go (5/10; different canonical path, so no collision).
	if response.Data.LinesValid != 25 {
		t.Fatalf("aggregate lines_valid = %d, want 25", response.Data.LinesValid)
	}
	if response.Data.LinesCovered != 15 {
		t.Fatalf("aggregate lines_covered = %d, want 15", response.Data.LinesCovered)
	}
	if len(response.Data.Files) != 3 {
		t.Fatalf("aggregate file count = %d, want 3", len(response.Data.Files))
	}
	if len(response.Data.Reports) != 2 {
		t.Fatalf("reports count = %d, want 2", len(response.Data.Reports))
	}
	if response.Data.Reports[0].Format != "gocover" || response.Data.Reports[1].Format != "lcov" {
		t.Fatalf("report formats = %#v, want [gocover lcov]", []string{response.Data.Reports[0].Format, response.Data.Reports[1].Format})
	}
	if len(response.Data.Reports[0].Files) != 2 {
		t.Fatalf("gocover response file count = %d, want 2", len(response.Data.Reports[0].Files))
	}
	if len(response.Data.Reports[1].Files) != 1 {
		t.Fatalf("lcov response file count = %d, want 1", len(response.Data.Reports[1].Files))
	}
}

func TestCoverageEndpointSingleFormatRemainsBackwardCompatible(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest(uniqueName(t, "single-format-sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uniqueName(t, "coverage-single-format"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	srv.processCoverageUpload(context.Background(), snapshot.ID, richerCoberturaForTest(), "cobertura")

	srv.router = chi.NewRouter()
	srv.wsHub = ws.NewHub(zerolog.New(io.Discard))
	configureRouter(srv.router, zerolog.New(io.Discard))
	srv.routes(nil)

	recorder := httptest.NewRecorder()
	srv.router.ServeHTTP(recorder, newAuthenticatedRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/coverage?ref=main"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /coverage status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response coverageSummaryAPIResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Data == nil {
		t.Fatal("expected coverage response data")
	}
	if response.Data.Format != "cobertura" {
		t.Fatalf("format = %q, want cobertura", response.Data.Format)
	}
	if len(response.Data.Files) != 1 {
		t.Fatalf("file count = %d, want 1", len(response.Data.Files))
	}
	if len(response.Data.Reports) != 1 {
		t.Fatalf("reports count = %d, want 1", len(response.Data.Reports))
	}
	if response.Data.Reports[0].Format != response.Data.Format {
		t.Fatalf("reports[0].format = %q, want %q", response.Data.Reports[0].Format, response.Data.Format)
	}
	if !reflect.DeepEqual(response.Data.Reports[0].Files, response.Data.Files) {
		t.Fatalf("reports[0].files = %#v, want %#v", response.Data.Reports[0].Files, response.Data.Files)
	}
}

func TestImportUploadedVEXIsIdempotent(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	seedVEXAdvisoryForTest(t, srv)
	repo := createUploadTestRepository(t, srv, org)
	content := minimalOpenVEXForTest()
	request := httptest.NewRequest(http.MethodPost, "/upload", nil)
	request = request.WithContext(internalauth.WithUser(request.Context(), admin))
	artifact := &uploadArtifact{Filename: "artifact.openvex.json"}
	input := uploadRequest{
		Provider:  "github",
		Org:       org.Slug,
		Repo:      repo.Slug,
		Ref:       "refs/heads/main",
		CommitSHA: uniqueName(t, "vex-commit"),
	}

	if err := srv.importUploadedVEX(request, admin.ID, input, artifact, "openvex", content); err != nil {
		t.Fatalf("first importUploadedVEX: %v", err)
	}
	firstState := captureImportedVEXState(t, srv, org.ID, repo.ID)
	if err := srv.importUploadedVEX(request, admin.ID, input, artifact, "openvex", content); err != nil {
		t.Fatalf("second importUploadedVEX: %v", err)
	}
	secondState := captureImportedVEXState(t, srv, org.ID, repo.ID)
	if !reflect.DeepEqual(firstState, secondState) {
		t.Fatalf("imported VEX state changed on replay\nfirst: %#v\nsecond: %#v", firstState, secondState)
	}

	statements := secondState
	if len(statements) != 1 {
		t.Fatalf("vex statement count = %d, want 1", len(statements))
	}
	if statements[0].Source != string(dbgen.VexSourceImported) {
		t.Fatalf("vex source = %q, want imported", statements[0].Source)
	}
	if statements[0].SourceDocumentURL != "artifact.openvex.json" {
		t.Fatalf("source_document_url = %q, want document identity", statements[0].SourceDocumentURL)
	}
	if statements[0].ComponentPURL.String != "pkg:golang/example/one@1.0.0" {
		t.Fatalf("component_purl = %q, want pkg:golang/example/one@1.0.0", statements[0].ComponentPURL.String)
	}
	if statements[0].Status != string(dbgen.VexStatusAffected) {
		t.Fatalf("status = %q, want affected", statements[0].Status)
	}
	var count int
	if err := srv.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM vex_statements WHERE org_id = $1 AND repo_id = $2`, org.ID, repo.ID).Scan(&count); err != nil {
		t.Fatalf("count vex_statements: %v", err)
	}
	if count != 1 {
		t.Fatalf("vex rows = %d, want 1", count)
	}
}

func TestImportUploadedVEXSameDocumentRevisionConverges(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	seedVEXAdvisoryForTest(t, srv)
	seedVEXAdvisoryForTestID(t, srv, "CVE-2026-0002")
	repo := createUploadTestRepository(t, srv, org)
	request := httptest.NewRequest(http.MethodPost, "/upload", nil)
	request = request.WithContext(internalauth.WithUser(request.Context(), admin))
	input := uploadRequest{
		Provider:  "github",
		Org:       org.Slug,
		Repo:      repo.Slug,
		Ref:       "refs/heads/main",
		CommitSHA: uniqueName(t, "vex-commit"),
	}

	originalContent := openVEXForTest(openVEXDocumentForTest{
		ID: "doc-1",
		Statements: []openVEXStatementForTest{
			{VulnerabilityID: "CVE-2026-0001", ComponentPURL: "pkg:golang/example/one@1.0.0", Status: vex.StatusAffected},
			{VulnerabilityID: "CVE-2026-0002", ComponentPURL: "pkg:golang/example/two@2.0.0", Status: vex.StatusAffected},
		},
	})
	if err := srv.importUploadedVEX(request, admin.ID, input, &uploadArtifact{Filename: "artifact.openvex.json"}, "openvex", originalContent); err != nil {
		t.Fatalf("first importUploadedVEX: %v", err)
	}
	firstState := captureImportedVEXState(t, srv, org.ID, repo.ID)
	firstByScope := indexImportedVEXState(firstState)

	revisedContent := openVEXForTest(openVEXDocumentForTest{
		ID: "doc-2",
		Statements: []openVEXStatementForTest{
			{VulnerabilityID: "CVE-2026-0001", ComponentPURL: "pkg:golang/example/one@1.0.0", Status: vex.StatusFixed},
		},
	})
	if err := srv.importUploadedVEX(request, admin.ID, input, &uploadArtifact{Filename: "artifact.openvex.json"}, "openvex", revisedContent); err != nil {
		t.Fatalf("revision reupload importUploadedVEX: %v", err)
	}
	revisedState := captureImportedVEXState(t, srv, org.ID, repo.ID)
	if len(revisedState) != 1 {
		t.Fatalf("revised state rows = %d, want 1", len(revisedState))
	}
	revisedRow := revisedState[0]
	originalRow := firstByScope[vexStateScopeKey(importedVEXStateRow{AdvisoryID: revisedRow.AdvisoryID, ComponentPURL: revisedRow.ComponentPURL})]
	if revisedRow.ID != originalRow.ID {
		t.Fatalf("revised row id = %s, want preserved id %s", revisedRow.ID, originalRow.ID)
	}
	if revisedRow.Status != string(dbgen.VexStatusFixed) {
		t.Fatalf("revised row status = %q, want fixed", revisedRow.Status)
	}
	if revisedRow.SourceDocumentURL != "artifact.openvex.json" {
		t.Fatalf("revised row source_document_url = %q, want stable document identity", revisedRow.SourceDocumentURL)
	}

	if err := srv.importUploadedVEX(request, admin.ID, input, &uploadArtifact{Filename: "artifact.openvex.json"}, "openvex", revisedContent); err != nil {
		t.Fatalf("replay revised importUploadedVEX: %v", err)
	}
	replayedRevisedState := captureImportedVEXState(t, srv, org.ID, repo.ID)
	if !reflect.DeepEqual(revisedState, replayedRevisedState) {
		t.Fatalf("revised VEX state changed on replay\nfirst: %#v\nsecond: %#v", revisedState, replayedRevisedState)
	}
}

func TestImportUploadedVEXDifferentDocumentsPreserveUniqueScopes(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	seedVEXAdvisoryForTest(t, srv)
	seedVEXAdvisoryForTestID(t, srv, "CVE-2026-0002")
	seedVEXAdvisoryForTestID(t, srv, "CVE-2026-0003")
	repo := createUploadTestRepository(t, srv, org)
	request := httptest.NewRequest(http.MethodPost, "/upload", nil)
	request = request.WithContext(internalauth.WithUser(request.Context(), admin))
	input := uploadRequest{
		Provider:  "github",
		Org:       org.Slug,
		Repo:      repo.Slug,
		Ref:       "refs/heads/main",
		CommitSHA: uniqueName(t, "vex-commit"),
	}

	documentA := openVEXForTest(openVEXDocumentForTest{
		ID: "doc-a",
		Statements: []openVEXStatementForTest{
			{VulnerabilityID: "CVE-2026-0001", ComponentPURL: "pkg:golang/example/one@1.0.0", Status: vex.StatusAffected},
			{VulnerabilityID: "CVE-2026-0002", ComponentPURL: "pkg:golang/example/two@2.0.0", Status: vex.StatusAffected},
		},
	})
	if err := srv.importUploadedVEX(request, admin.ID, input, &uploadArtifact{Filename: "artifact.openvex.json"}, "openvex", documentA); err != nil {
		t.Fatalf("document A importUploadedVEX: %v", err)
	}
	stateAfterDocumentA := captureImportedVEXState(t, srv, org.ID, repo.ID)
	firstByScope := indexImportedVEXState(stateAfterDocumentA)

	documentB := openVEXForTest(openVEXDocumentForTest{
		ID: "doc-b",
		Statements: []openVEXStatementForTest{
			{VulnerabilityID: "CVE-2026-0001", ComponentPURL: "pkg:golang/example/one@1.0.0", Status: vex.StatusFixed},
			{VulnerabilityID: "CVE-2026-0003", ComponentPURL: "pkg:golang/example/three@3.0.0", Status: vex.StatusAffected},
		},
	})
	if err := srv.importUploadedVEX(request, admin.ID, input, &uploadArtifact{Filename: "renamed.openvex.json"}, "openvex", documentB); err != nil {
		t.Fatalf("document B importUploadedVEX: %v", err)
	}
	stateAfterDocumentB := captureImportedVEXState(t, srv, org.ID, repo.ID)
	if len(stateAfterDocumentB) != 3 {
		t.Fatalf("state rows after second document = %d, want 3", len(stateAfterDocumentB))
	}

	sharedRow := importedVEXStateRowByComponentPURL(t, stateAfterDocumentB, "pkg:golang/example/one@1.0.0")
	sharedScope := vexStateScopeKey(sharedRow)
	firstSharedRow := firstByScope[sharedScope]
	if sharedRow.ID != firstSharedRow.ID {
		t.Fatalf("shared row id changed across documents: %s -> %s", firstSharedRow.ID, sharedRow.ID)
	}
	if sharedRow.Status != string(dbgen.VexStatusFixed) {
		t.Fatalf("shared row status = %q, want fixed", sharedRow.Status)
	}
	if sharedRow.SourceDocumentURL != "renamed.openvex.json" {
		t.Fatalf("shared row source_document_url = %q, want renamed.openvex.json", sharedRow.SourceDocumentURL)
	}

	uniqueDocumentARow := importedVEXStateRowByComponentPURL(t, stateAfterDocumentB, "pkg:golang/example/two@2.0.0")
	if uniqueDocumentARow.SourceDocumentURL != "artifact.openvex.json" {
		t.Fatalf("document A unique row source_document_url = %q, want artifact.openvex.json", uniqueDocumentARow.SourceDocumentURL)
	}

	uniqueDocumentBRow := importedVEXStateRowByComponentPURL(t, stateAfterDocumentB, "pkg:golang/example/three@3.0.0")
	if uniqueDocumentBRow.SourceDocumentURL != "renamed.openvex.json" {
		t.Fatalf("document B unique row source_document_url = %q, want renamed.openvex.json", uniqueDocumentBRow.SourceDocumentURL)
	}

	if err := srv.importUploadedVEX(request, admin.ID, input, &uploadArtifact{Filename: "renamed.openvex.json"}, "openvex", documentB); err != nil {
		t.Fatalf("replay document B importUploadedVEX: %v", err)
	}
	replayedStateAfterDocumentB := captureImportedVEXState(t, srv, org.ID, repo.ID)
	if !reflect.DeepEqual(stateAfterDocumentB, replayedStateAfterDocumentB) {
		t.Fatalf("different-document VEX state changed on replay\nfirst: %#v\nsecond: %#v", stateAfterDocumentB, replayedStateAfterDocumentB)
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

	// Finalizing with a queued SBOM lands on processing; the artifact worker
	// flips it to complete once ingestion runs.
	if response.Status != string(store.SnapshotStatusProcessing) {
		t.Fatalf("status = %s, want processing", response.Status)
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

	// Finalizing with a queued SBOM lands on processing; the artifact worker
	// flips it to complete once ingestion runs.
	if response.Status != string(store.SnapshotStatusProcessing) {
		t.Fatalf("status = %s, want processing", response.Status)
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

func TestAdvanceUploadSnapshotLeavesBlobOnFinalizeFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		preExisted bool
	}{
		{
			name:       "leave newly written blob orphaned",
			preExisted: false,
		},
		{
			name:       "leave shared existing blob untouched",
			preExisted: true,
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

			assertRecordingObjStoreCalls(t, srv.objStore.(*recordingObjStore), wantKey)
			assertSnapshotAdvanceFailedState(t, srv, snapshot.ID)
		})
	}
}

func TestUploadAutoRejectsArtifactWhenObjectStoreNil(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	srv.objStore = nil
	repo := createUploadTestRepository(t, srv, org)

	recorder := performUploadAutoRecorder(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSBOMForTest(), map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "artifact456",
		"complete":   true,
	}))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d: %s", http.StatusInternalServerError, recorder.Code, recorder.Body.String())
	}

	refs, _, err := srv.queries.ListRefsByRepo(context.Background(), repo.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListRefsByRepo: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("refs = %d, want 1", len(refs))
	}

	snapshots, _, err := srv.queries.ListSnapshotsByRef(context.Background(), refs[0].ID, 10, 0)
	if err != nil {
		t.Fatalf("ListSnapshotsByRef: %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1 pending snapshot record", len(snapshots))
	}

	artifacts, err := srv.queries.ListSnapshotArtifactsBySnapshot(context.Background(), snapshots[0].ID)
	if err != nil {
		t.Fatalf("ListSnapshotArtifactsBySnapshot: %v", err)
	}
	if len(artifacts) != 0 {
		t.Fatalf("artifact rows = %d, want 0", len(artifacts))
	}
}

func TestUploadAutoDuplicateArtifactSameSnapshotDoesNotDoubleCountArtifactBytes(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	artifactDir := t.TempDir()
	artifactStore, err := objstore.NewFilesystemStore(artifactDir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	srv.objStore = artifactStore
	repo := createUploadTestRepository(t, srv, org)
	artifactContent := minimalSBOMForTest()

	first := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, artifactContent, map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "dedupe-same-snapshot",
		"run_id":     "run-dedupe",
		"expect":     2,
		"complete":   false,
	}))
	second := performUploadAuto(t, srv, admin, uploadPayloadForTest(org.Slug, repo.Slug, artifactContent, map[string]any{
		"ref":        "refs/heads/main",
		"commit_sha": "dedupe-same-snapshot",
		"run_id":     "run-dedupe",
		"expect":     2,
		"complete":   false,
	}))

	if first.SnapshotID != second.SnapshotID {
		t.Fatalf("expected same snapshot id, got %s and %s", first.SnapshotID, second.SnapshotID)
	}

	snapshotID := snapshotIDFromResponse(t, first)
	assertSnapshotReceivedUploads(t, srv, snapshotID, 2)

	artifacts, err := srv.queries.ListSnapshotArtifactsBySnapshot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("ListSnapshotArtifactsBySnapshot: %v", err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("artifact rows = %d, want 1", len(artifacts))
	}

	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot to exist")
	}
	if snapshot.ArtifactBytes != int64(len(artifactContent)) {
		t.Fatalf("snapshot artifact_bytes = %d, want %d", snapshot.ArtifactBytes, len(artifactContent))
	}

	storedRepo, err := srv.queries.GetRepositoryByID(context.Background(), repo.ID)
	if err != nil {
		t.Fatalf("GetRepositoryByID: %v", err)
	}
	if storedRepo == nil {
		t.Fatal("expected repository to exist")
	}
	if storedRepo.RetentionArtifactBytes != int64(len(artifactContent)) {
		t.Fatalf("repository retention_artifact_bytes = %d, want %d", storedRepo.RetentionArtifactBytes, len(artifactContent))
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

func richerCoberturaForTest() []byte {
	return []byte(`<?xml version="1.0"?>
<coverage line-rate="0.5" branch-rate="0" lines-valid="2" lines-covered="1" branches-valid="0" branches-covered="0">
	<packages>
		<package name="main">
			<classes>
				<class name="main" filename="main.go" line-rate="0.5" branch-rate="0">
					<lines>
						<line number="1" hits="1"/>
						<line number="2" hits="0"/>
					</lines>
				</class>
			</classes>
		</package>
	</packages>
</coverage>`)
}

func minimalOpenVEXForTest() []byte {
	return openVEXForTest(openVEXDocumentForTest{
		ID: "doc-1",
		Statements: []openVEXStatementForTest{{
			VulnerabilityID: "CVE-2026-0001",
			ComponentPURL:   "pkg:golang/example/one@1.0.0",
			Status:          vex.StatusAffected,
		}},
	})
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
		kind:     "sbom",
		format:   "cyclonedx-json",
		tool:     "syft",
		filename: "sbom.cdx.json",
		content:  minimalSBOMForTest(),
	}
	params := buildSnapshotArtifactParams(snapshot.ID, artifact.kind, artifact.format, artifact.tool, artifact.filename, artifact.content)
	setAdvanceUploadSnapshotFailingDB(t, srv)
	return srv, snapshot, artifact, params.ObjectKey
}

func createPendingSnapshotForAdvanceUploadTest(t *testing.T, srv *Server, userID uuid.UUID, orgSlug, repoSlug string) *store.Snapshot {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	req = req.WithContext(internalauth.WithUser(req.Context(), &store.User{ID: userID}))
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

func assertRecordingObjStoreCalls(t *testing.T, objStore *recordingObjStore, wantKey string) {
	t.Helper()

	if len(objStore.exists) != 0 {
		t.Fatalf("Exists calls = %v, want none", objStore.exists)
	}
	if len(objStore.puts) != 1 || objStore.puts[0] != wantKey {
		t.Fatalf("Put calls = %v, want [%q]", objStore.puts, wantKey)
	}
	if len(objStore.deleted) != 0 {
		t.Fatalf("Delete calls = %v, want none", objStore.deleted)
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
	seedVEXAdvisoryForTestID(t, srv, "CVE-2026-0001")
}

func seedVEXAdvisoryForTestID(t *testing.T, srv *Server, canonicalID string) {
	t.Helper()

	if _, err := srv.queries.UpsertAdvisory(context.Background(), dbgen.UpsertAdvisoryParams{
		CanonicalID: canonicalID,
		Title:       "VEX test advisory",
		Description: "test advisory for uploaded VEX import",
		Severity:    dbgen.SeverityLevelLow,
		CweIds:      []string{},
		CvssScore:   sql.NullString{},
		CvssVersion: dbgen.NullCvssVersion{},
		PublishedAt: sql.NullTime{},
		WithdrawnAt: sql.NullTime{},
	}); err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}
}

type openVEXDocumentForTest struct {
	ID         string
	Statements []openVEXStatementForTest
}

type openVEXStatementForTest struct {
	VulnerabilityID string
	ComponentPURL   string
	Status          string
}

type coverageProcessorState struct {
	Reports []store.CoverageReport
	Files   map[string][]store.CoverageFile
}

type coverageSummaryAPIResponse struct {
	Data *coverageSummaryResponse `json:"data"`
}

type importedVEXStateRow struct {
	ID                uuid.UUID
	AdvisoryID        uuid.UUID
	ComponentPURL     sql.NullString
	Status            string
	Justification     sql.NullString
	ImpactStatement   string
	ActionStatement   string
	Source            string
	SourceDocumentURL string
	Supplier          string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func openVEXForTest(document openVEXDocumentForTest) []byte {
	payload := map[string]any{
		"@context":  "https://openvex.dev/ns/v0.2.0",
		"@id":       document.ID,
		"timestamp": "2026-05-29T10:00:00Z",
	}
	statements := make([]map[string]any, 0, len(document.Statements))
	for _, statement := range document.Statements {
		statements = append(statements, map[string]any{
			"vulnerability": map[string]any{"@id": statement.VulnerabilityID},
			"products":      []map[string]any{{"@id": statement.ComponentPURL}},
			"status":        statement.Status,
		})
	}
	payload["statements"] = statements

	content, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return content
}

func captureCoverageProcessorState(t *testing.T, srv *Server, snapshotID uuid.UUID) coverageProcessorState {
	t.Helper()

	reports, err := srv.queries.ListCoverageReportsBySnapshot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("ListCoverageReportsBySnapshot: %v", err)
	}
	filesByFormat := make(map[string][]store.CoverageFile, len(reports))
	for _, report := range reports {
		files, fileErr := srv.queries.ListCoverageFilesByReport(context.Background(), report.ID)
		if fileErr != nil {
			t.Fatalf("ListCoverageFilesByReport(%s): %v", report.Format, fileErr)
		}
		filesByFormat[report.Format] = files
	}
	return coverageProcessorState{Reports: reports, Files: filesByFormat}
}

func captureImportedVEXState(t *testing.T, srv *Server, orgID, repoID uuid.UUID) []importedVEXStateRow {
	t.Helper()

	rows, err := srv.queries.ListVEXStatementsByRepo(context.Background(), dbgen.ListVEXStatementsByRepoParams{
		OrgID:  orgID,
		RepoID: uuid.NullUUID{UUID: repoID, Valid: true},
		Limit:  100,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("ListVEXStatementsByRepo: %v", err)
	}
	state := make([]importedVEXStateRow, len(rows))
	for i, row := range rows {
		state[i] = importedVEXStateRow{
			ID:                row.ID,
			AdvisoryID:        row.AdvisoryID,
			ComponentPURL:     row.ComponentPurl,
			Status:            string(row.Status),
			Justification:     nullStringFromJustification(row.Justification),
			ImpactStatement:   row.ImpactStatement,
			ActionStatement:   row.ActionStatement,
			Source:            string(row.Source),
			SourceDocumentURL: row.SourceDocumentUrl,
			Supplier:          row.Supplier,
			CreatedAt:         row.CreatedAt,
			UpdatedAt:         row.UpdatedAt,
		}
	}
	sort.Slice(state, func(i, j int) bool {
		left := vexStateScopeKey(state[i])
		right := vexStateScopeKey(state[j])
		return left < right
	})
	return state
}

func indexImportedVEXState(rows []importedVEXStateRow) map[string]importedVEXStateRow {
	indexed := make(map[string]importedVEXStateRow, len(rows))
	for _, row := range rows {
		indexed[vexStateScopeKey(row)] = row
	}
	return indexed
}

func vexStateScopeKey(row importedVEXStateRow) string {
	return row.AdvisoryID.String() + "|" + row.ComponentPURL.String
}

func importedVEXStateRowByComponentPURL(t *testing.T, rows []importedVEXStateRow, componentPURL string) importedVEXStateRow {
	t.Helper()
	for _, row := range rows {
		if row.ComponentPURL.Valid && row.ComponentPURL.String == componentPURL {
			return row
		}
	}
	t.Fatalf("missing row for component_purl %q", componentPURL)
	return importedVEXStateRow{}
}

func nullStringFromJustification(value dbgen.NullVexJustification) sql.NullString {
	if !value.Valid {
		return sql.NullString{}
	}
	return sql.NullString{String: string(value.VexJustification), Valid: true}
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

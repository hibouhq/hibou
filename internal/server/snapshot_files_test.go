package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/ws"
)

func TestSnapshotFilesListDownloadAndOwnership(t *testing.T) {
	t.Parallel()

	srv, org, admin, member := newDiscoveryTestServer(t)
	ctx := context.Background()
	repo := createUploadTestRepository(t, srv, org)

	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest(uniqueName(t, "files-sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, uniqueName(t, "files-snap"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	content := []byte(`{"version":"2.1.0","runs":[]}`)
	objectKey := "test/" + snapshot.ID.String() + "/gosec"
	if err := srv.objStore.Put(ctx, objectKey, bytes.NewReader(content), "application/json"); err != nil {
		t.Fatalf("objStore.Put: %v", err)
	}
	artifact, err := srv.queries.CreateSnapshotArtifact(ctx, store.CreateSnapshotArtifactParams{
		SnapshotID:  snapshot.ID,
		Kind:        "sarif",
		ToolName:    stringPtrForTest("gosec"),
		ObjectKey:   objectKey,
		SizeBytes:   int64(len(content)),
		ContentType: stringPtrForTest("application/json"),
		Filename:    "gosec-results.sarif",
	})
	if err != nil {
		t.Fatalf("CreateSnapshotArtifact: %v", err)
	}

	// A second repo with its own snapshot, to assert cross-repo isolation.
	otherRepo := createUploadTestRepository(t, srv, org)
	otherRef, err := srv.queries.CreateRef(ctx, otherRepo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest(uniqueName(t, "other-sha")))
	if err != nil {
		t.Fatalf("CreateRef other: %v", err)
	}
	otherSnapshot, err := srv.queries.CreateSnapshot(ctx, otherRef.ID, uniqueName(t, "other-snap"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot other: %v", err)
	}

	srv.router = chi.NewRouter()
	srv.wsHub = ws.NewHub(zerolog.New(io.Discard))
	configureRouter(srv.router, zerolog.New(io.Discard))
	srv.routes(nil)

	base := "/api/v1/orgs/github/" + org.Slug + "/repos/" + repo.Slug + "/snapshots/" + snapshot.ID.String()

	// 1. List files.
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, newAuthenticatedRequest(t, member, http.MethodGet, base+"/files"))
	if rec.Code != http.StatusOK {
		t.Fatalf("list files status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var listResp struct {
		Data []snapshotFileResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(listResp.Data) != 1 {
		t.Fatalf("file count = %d, want 1", len(listResp.Data))
	}
	if got := listResp.Data[0].Filename; got != "gosec-results.sarif" {
		t.Fatalf("filename = %q, want gosec-results.sarif (persisted original)", got)
	}

	// 2. Raw bytes are developer+: the viewer can list but not download
	// (Q2 — uploaded reports can carry secret excerpts).
	for _, path := range []string{base + "/files/" + artifact.ID.String(), base + "/files.zip"} {
		rec = httptest.NewRecorder()
		srv.router.ServeHTTP(rec, newAuthenticatedRequest(t, member, http.MethodGet, path))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("viewer GET %s status = %d, want 403 (%s)", path, rec.Code, rec.Body.String())
		}
	}

	// 3. An admin downloads the file; body must round-trip.
	rec = httptest.NewRecorder()
	srv.router.ServeHTTP(rec, newAuthenticatedRequest(t, admin, http.MethodGet, base+"/files/"+artifact.ID.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("download status = %d, want 200", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Fatalf("download body mismatch: got %q", rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Fatal("missing Content-Disposition header")
	}

	// 4. Cross-repo isolation: a snapshot from otherRepo is not reachable via repo.
	rec = httptest.NewRecorder()
	foreign := "/api/v1/orgs/github/" + org.Slug + "/repos/" + repo.Slug + "/snapshots/" + otherSnapshot.ID.String() + "/files"
	srv.router.ServeHTTP(rec, newAuthenticatedRequest(t, member, http.MethodGet, foreign))
	if rec.Code == http.StatusOK {
		t.Fatalf("foreign snapshot files should not be 200, got %d", rec.Code)
	}
}

// Q2: an uploaded SARIF is stored without its region snippets, and the
// recorded digest describes the stored bytes.
func TestStorableArtifactContentStripsSARIFSnippets(t *testing.T) {
	content := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"aws","message":{"text":"secret"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.env"},"region":{"startLine":1,"snippet":{"text":"AKIAIOSFODNN7EXAMPLE"}}}}]}]}]}`)
	stored, err := storableArtifactContent("sarif", content)
	if err != nil {
		t.Fatalf("storableArtifactContent: %v", err)
	}
	if bytes.Contains(stored, []byte("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatalf("stored SARIF keeps the snippet: %s", stored)
	}
	params := buildSnapshotArtifactParams(uuid.New(), "sarif", "", "gitleaks", "x.sarif", stored)
	sum := sha256.Sum256(stored)
	if params.SHA256 == nil || *params.SHA256 != hex.EncodeToString(sum[:]) || params.SizeBytes != int64(len(stored)) {
		t.Fatal("artifact digest/size must describe the stored bytes")
	}

	sbom := []byte(`{"bomFormat":"CycloneDX","snippet":"x"}`)
	if got, err := storableArtifactContent("sbom", sbom); err != nil || !bytes.Equal(got, sbom) {
		t.Fatalf("non-SARIF artifact altered: %s, %v", got, err)
	}
	if _, err := storableArtifactContent("sarif", []byte(`not json`)); err == nil {
		t.Fatal("invalid SARIF accepted for storage")
	}
}

// S3: upload errors never echo internal error text to the client.
func TestWriteUploadErrorDoesNotLeakInternalErrors(t *testing.T) {
	srv := &Server{log: zerolog.New(io.Discard)}
	cases := []struct {
		err      error
		wantCode int
		wantMsg  string
		leak     string
	}{
		{errors.New("commit_sha is required"), http.StatusBadRequest, "commit_sha is required", ""},
		{fmt.Errorf("pq: invalid input syntax for type uuid: %q", "secret-row-value"), http.StatusBadRequest, "invalid upload request", "secret-row-value"},
		{fmt.Errorf("load: %w", errors.New("dial tcp 10.0.0.5:5432: password authentication failed, required")), http.StatusInternalServerError, "failed to process upload", "10.0.0.5"},
		{errBadRequest("invalid SARIF document"), http.StatusBadRequest, "invalid SARIF document", ""},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		srv.writeUploadError(rec, tc.err)
		if rec.Code != tc.wantCode || !strings.Contains(rec.Body.String(), tc.wantMsg) {
			t.Fatalf("writeUploadError(%v) = %d %s, want %d %q", tc.err, rec.Code, rec.Body.String(), tc.wantCode, tc.wantMsg)
		}
		if tc.leak != "" && strings.Contains(rec.Body.String(), tc.leak) {
			t.Fatalf("writeUploadError(%v) leaks %q", tc.err, tc.leak)
		}
	}
}

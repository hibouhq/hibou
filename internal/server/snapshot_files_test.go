package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/ws"
)

func TestSnapshotFilesListDownloadAndOwnership(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
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

	// 2. Download the file; body must round-trip.
	rec = httptest.NewRecorder()
	srv.router.ServeHTTP(rec, newAuthenticatedRequest(t, member, http.MethodGet, base+"/files/"+artifact.ID.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("download status = %d, want 200", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Fatalf("download body mismatch: got %q", rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Fatal("missing Content-Disposition header")
	}

	// 3. Cross-repo isolation: a snapshot from otherRepo is not reachable via repo.
	rec = httptest.NewRecorder()
	foreign := "/api/v1/orgs/github/" + org.Slug + "/repos/" + repo.Slug + "/snapshots/" + otherSnapshot.ID.String() + "/files"
	srv.router.ServeHTTP(rec, newAuthenticatedRequest(t, member, http.MethodGet, foreign))
	if rec.Code == http.StatusOK {
		t.Fatalf("foreign snapshot files should not be 200, got %d", rec.Code)
	}
}

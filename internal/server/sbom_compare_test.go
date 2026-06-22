package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/sbom"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/ws"
)

func TestCompareSBOMs(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	ctx := context.Background()
	repo := createUploadTestRepository(t, srv, org)
	foreignRepo := createUploadTestRepository(t, srv, org)

	baseArtifact := createSBOMCompareArtifact(t, srv, repo, `{
		"bomFormat":"CycloneDX",
		"components":[
			{"name":"alpha","version":"1.0.0","purl":"pkg:npm/alpha@1.0.0"},
			{"name":"local-lib","version":"1.0.0","purl":"pkg:generic/local-lib@1.0.0"}
		]
	}`)
	headArtifact := createSBOMCompareArtifact(t, srv, repo, `{
		"bomFormat":"CycloneDX",
		"components":[
			{"name":"alpha","version":"1.1.0","purl":"pkg:npm/alpha@1.1.0"},
			{"name":"bravo","version":"2.0.0","purl":"pkg:npm/bravo@2.0.0"}
		]
	}`)
	foreignArtifact := createSBOMCompareArtifact(t, srv, foreignRepo, `{
		"bomFormat":"CycloneDX",
		"components":[
			{"name":"omega","version":"9.0.0","purl":"pkg:npm/omega@9.0.0"}
		]
	}`)

	srv.router = chi.NewRouter()
	srv.wsHub = ws.NewHub(zerolog.New(io.Discard))
	configureRouter(srv.router, zerolog.New(io.Discard))
	srv.routes(nil)

	body, err := json.Marshal(compareSBOMsRequest{
		BaseArtifactID: baseArtifact.ID.String(),
		HeadArtifactID: headArtifact.ID.String(),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	path := "/api/v1/orgs/github/" + org.Slug + "/repos/" + repo.Slug + "/sbom/compare"
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	req = req.WithContext(req.Context())
	req = req.WithContext(newAuthenticatedRequest(t, member, http.MethodPost, path).Context())
	rec := httptest.NewRecorder()

	srv.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("compare status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	var response struct {
		Data sbom.SBOMDiff `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if response.Data.Summary.VersionChanged != 1 || response.Data.Summary.Added != 1 || response.Data.Summary.Removed != 1 {
		t.Fatalf("summary = %#v, want 1 changed/added/removed", response.Data.Summary)
	}
	if len(response.Data.VersionChanged) != 1 || response.Data.VersionChanged[0].Name != "alpha" {
		t.Fatalf("version changes = %#v, want alpha version change", response.Data.VersionChanged)
	}
	if len(response.Data.Added) != 1 || response.Data.Added[0].Name != "bravo" {
		t.Fatalf("added = %#v, want bravo", response.Data.Added)
	}
	if len(response.Data.Removed) != 1 || response.Data.Removed[0].Name != "local-lib" {
		t.Fatalf("removed = %#v, want local-lib", response.Data.Removed)
	}

	foreignBody, err := json.Marshal(compareSBOMsRequest{
		BaseArtifactID: baseArtifact.ID.String(),
		HeadArtifactID: foreignArtifact.ID.String(),
	})
	if err != nil {
		t.Fatalf("json.Marshal foreign: %v", err)
	}
	foreignReq := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(foreignBody))
	foreignReq.Header.Set("Content-Type", "application/json")
	foreignReq = foreignReq.WithContext(newAuthenticatedRequest(t, member, http.MethodPost, path).Context())
	foreignRec := httptest.NewRecorder()

	srv.router.ServeHTTP(foreignRec, foreignReq)
	if foreignRec.Code != http.StatusForbidden {
		t.Fatalf("foreign compare status = %d, want 403 (%s)", foreignRec.Code, foreignRec.Body.String())
	}

	inlineBody, err := json.Marshal(compareSBOMsRequest{
		BaseArtifactID: baseArtifact.ID.String(),
		HeadContent: encodeSBOMCompareContent(`{
			"spdxVersion":"SPDX-2.3",
			"packages":[
				{"name":"alpha","versionInfo":"1.2.0","SPDXID":"SPDXRef-alpha","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/alpha@1.2.0"}]},
				{"name":"charlie","versionInfo":"3.0.0","SPDXID":"SPDXRef-charlie","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:npm/charlie@3.0.0"}]}
			]
		}`),
		HeadFormat: "spdx-json",
	})
	if err != nil {
		t.Fatalf("json.Marshal inline: %v", err)
	}
	inlineReq := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(inlineBody))
	inlineReq.Header.Set("Content-Type", "application/json")
	inlineReq = inlineReq.WithContext(newAuthenticatedRequest(t, member, http.MethodPost, path).Context())
	inlineRec := httptest.NewRecorder()

	srv.router.ServeHTTP(inlineRec, inlineReq)
	if inlineRec.Code != http.StatusOK {
		t.Fatalf("inline compare status = %d, want 200 (%s)", inlineRec.Code, inlineRec.Body.String())
	}

	var inlineResponse struct {
		Data sbom.SBOMDiff `json:"data"`
	}
	if err := json.Unmarshal(inlineRec.Body.Bytes(), &inlineResponse); err != nil {
		t.Fatalf("json.Unmarshal inline: %v", err)
	}
	if inlineResponse.Data.Summary.VersionChanged != 1 || inlineResponse.Data.Summary.Added != 1 || inlineResponse.Data.Summary.Removed != 1 {
		t.Fatalf("inline summary = %#v, want 1 changed/added/removed", inlineResponse.Data.Summary)
	}

	invalidInlineBody, err := json.Marshal(compareSBOMsRequest{
		BaseContent: encodeSBOMCompareContent(`{"bomFormat":"CycloneDX","components":[]}`),
		HeadContent: encodeSBOMCompareContent(`{"bomFormat":"CycloneDX","components":[]}`),
		HeadFormat:  "cyclonedx-json",
	})
	if err != nil {
		t.Fatalf("json.Marshal invalid inline: %v", err)
	}
	invalidInlineReq := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(invalidInlineBody))
	invalidInlineReq.Header.Set("Content-Type", "application/json")
	invalidInlineReq = invalidInlineReq.WithContext(newAuthenticatedRequest(t, member, http.MethodPost, path).Context())
	invalidInlineRec := httptest.NewRecorder()

	srv.router.ServeHTTP(invalidInlineRec, invalidInlineReq)
	if invalidInlineRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid inline status = %d, want 400 (%s)", invalidInlineRec.Code, invalidInlineRec.Body.String())
	}
}

func encodeSBOMCompareContent(content string) string {
	return base64.StdEncoding.EncodeToString([]byte(content))
}

func createSBOMCompareArtifact(t *testing.T, srv *Server, repo *store.Repository, content string) *store.SnapshotArtifact {
	t.Helper()

	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, uniqueName(t, "sbom-compare-ref"), store.RefTypeBranch, nil, nil, stringPtrForTest(uniqueName(t, "sbom-compare-sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uniqueName(t, "sbom-compare-snapshot"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	format := "cyclonedx-json"
	params := buildSnapshotArtifactParams(snapshot.ID, "sbom", format, "", "", []byte(content))
	if err := srv.objStore.Put(context.Background(), params.ObjectKey, bytes.NewReader([]byte(content)), optionalStringValue(params.ContentType)); err != nil {
		t.Fatalf("objStore.Put: %v", err)
	}
	artifact, err := srv.queries.CreateSnapshotArtifact(context.Background(), store.CreateSnapshotArtifactParams{
		SnapshotID:  snapshot.ID,
		Kind:        "sbom",
		Format:      &format,
		ObjectKey:   params.ObjectKey,
		SHA256:      params.SHA256,
		SizeBytes:   int64(len(content)),
		ContentType: params.ContentType,
	})
	if err != nil {
		t.Fatalf("CreateSnapshotArtifact: %v", err)
	}
	return artifact
}

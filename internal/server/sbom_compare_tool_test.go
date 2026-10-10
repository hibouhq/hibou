package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareLocalSBOMsNeedsNoRepository(t *testing.T) {
	srv := &Server{}
	doc := func(version string) string {
		return base64.StdEncoding.EncodeToString([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"lodash","version":"` + version + `","purl":"pkg:npm/lodash@` + version + `"}]}`))
	}
	body, _ := json.Marshal(compareSBOMsRequest{BaseContent: doc("4.17.20"), BaseFormat: "cyclonedx-json", HeadContent: doc("4.17.21"), HeadFormat: "cyclonedx-json"})
	recorder := httptest.NewRecorder()
	srv.handleCompareLocalSBOMs(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/tools/sbom/compare", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte("4.17.21")) {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}

	body, _ = json.Marshal(compareSBOMsRequest{BaseArtifactID: "11111111-1111-1111-1111-111111111111", HeadContent: doc("1"), HeadFormat: "cyclonedx-json"})
	recorder = httptest.NewRecorder()
	srv.handleCompareLocalSBOMs(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/tools/sbom/compare", bytes.NewReader(body)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("artifact ids must be refused without a repository: %d", recorder.Code)
	}
}

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Deep pages of the merged search must not turn into page*per_page row
// fetches per result type: past the window they come back empty.
func TestGlobalSearchDeepPageIsBounded(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	req := newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/search?q=a&page=1000000&per_page=100", "github", org.Slug)
	recorder := httptest.NewRecorder()
	srv.handleGlobalSearch(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data struct {
			Results    []json.RawMessage `json:"results"`
			Pagination struct {
				Page int `json:"page"`
			} `json:"pagination"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data.Results) != 0 || body.Data.Pagination.Page != 1000 {
		t.Fatalf("results = %d, page = %d; want an empty page capped at 1000", len(body.Data.Results), body.Data.Pagination.Page)
	}
}

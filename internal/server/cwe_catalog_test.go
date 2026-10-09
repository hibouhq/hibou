package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func callCatalog(t *testing.T, query string) cweCatalogResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	(&Server{}).handleSearchCWECatalog(recorder, httptest.NewRequest(http.MethodGet, "/cwe?"+query, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /cwe?%s: %d", query, recorder.Code)
	}
	var envelope struct {
		Data cweCatalogResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

// cwe-tree: completion needs a CWE's parents (to suggest CWE-74 for a view
// full of CWE-89) and the broad roots to start from when nothing is typed.
func TestCWECatalogServesHierarchyForTreeCompletion(t *testing.T) {
	byIDs := callCatalog(t, "ids=89,99999")
	if len(byIDs.Entries) != 2 || byIDs.Entries[0].ID != 89 || !slices.Contains(byIDs.Entries[0].Ancestors, 74) {
		t.Fatalf("ids lookup = %+v", byIDs.Entries)
	}
	if byIDs.Entries[1].ID != 99999 || byIDs.Entries[1].Name != "" {
		t.Fatalf("unknown id must come back untitled, got %+v", byIDs.Entries[1])
	}
	roots := callCatalog(t, "abstraction=pillar")
	if len(roots.Entries) < 5 {
		t.Fatalf("pillars = %d", len(roots.Entries))
	}
	for _, entry := range roots.Entries {
		if entry.Abstraction != "pillar" || entry.Descendants == 0 || len(entry.Ancestors) != 0 {
			t.Errorf("pillar entry = %+v", entry)
		}
	}
	if search := callCatalog(t, "q=sql&limit=5"); len(search.Entries) == 0 {
		t.Fatal("title search returned nothing")
	}
}

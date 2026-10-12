package forge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGitLabComparePatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/projects/group/app/repository/compare" && r.URL.RawPath != "/api/v4/projects/group%2Fapp/repository/compare" {
			t.Errorf("path = %s (raw %s)", r.URL.Path, r.URL.RawPath)
		}
		if r.URL.Query().Get("from") != "base" || r.URL.Query().Get("to") != "head" || r.URL.Query().Get("straight") != "true" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(gitlabCompareResponse{Diffs: []gitlabCompareDiff{
			{OldPath: "a.go", NewPath: "a.go", Diff: "@@ -1,2 +1,3 @@\n line\n+added\n line\n"},
			{OldPath: "old.go", NewPath: "new.go", RenamedFile: true},
			{OldPath: "gone.go", NewPath: "gone.go", DeletedFile: true},
			{NewPath: "huge.json", NewFile: true, TooLarge: true},
		}})
	}))
	defer server.Close()

	diff, err := NewGitLab(server.URL, "", "", "").ComparePatch(context.Background(), "group", "app", "base", "head")
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Truncated || len(diff.Files) != 4 {
		t.Fatalf("diff = %+v", diff)
	}
	if diff.Files[0].Status != "modified" || len(diff.Files[0].AddedLines) != 1 || diff.Files[0].AddedLines[0] != 2 {
		t.Fatalf("modified file = %+v", diff.Files[0])
	}
	if diff.Files[1].Status != "renamed" || diff.Files[1].OldPath != "old.go" || diff.Files[1].Path != "new.go" {
		t.Fatalf("renamed file = %+v", diff.Files[1])
	}
	if diff.Files[2].Status != "removed" || diff.Files[3].Status != "added" {
		t.Fatalf("statuses = %s %s", diff.Files[2].Status, diff.Files[3].Status)
	}
}

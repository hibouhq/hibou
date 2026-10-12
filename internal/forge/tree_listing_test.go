package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestGitLabListTreePaginates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		entries := make([]map[string]string, 0, gitlabTreePageSize)
		count := gitlabTreePageSize
		if page == 2 {
			count = 3
		}
		for i := 0; i < count; i++ {
			entries = append(entries, map[string]string{"path": fmt.Sprintf("p%d/f%d.go", page, i), "type": "blob"})
		}
		entries = append(entries, map[string]string{"path": "dir", "type": "tree"})
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer server.Close()
	listing, err := NewGitLab(server.URL, "", "", "").ListTree(context.Background(), "g", "r", "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Paths) != gitlabTreePageSize+3 || listing.Truncated {
		t.Fatalf("paths = %d truncated = %v", len(listing.Paths), listing.Truncated)
	}
}

func TestForgejoListTreeFollowsPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		body := map[string]any{"total_count": 3, "truncated": page == 1}
		if page == 1 {
			body["tree"] = []map[string]string{{"path": "a.go", "type": "blob"}, {"path": "src", "type": "tree"}}
		} else {
			body["tree"] = []map[string]string{{"path": "src/b.go", "type": "blob"}}
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	listing, err := NewForgejo(server.URL, "", "", "", "").ListTree(context.Background(), "o", "r", "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Paths) != 2 || listing.Truncated {
		t.Fatalf("listing = %+v", listing)
	}
}

func TestForgejoComparePatchPathsOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/repos/o/r/compare/base...head" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Newest commit first: a.go added then removed, b.go modified.
		_ = json.NewEncoder(w).Encode(map[string]any{"total_commits": 3, "commits": []map[string]any{
			{"files": []map[string]string{{"filename": "a.go", "status": "removed"}}},
			{"files": []map[string]string{{"filename": "b.go", "status": "modified"}, {"filename": "a.go", "status": "added"}}},
		}})
	}))
	defer server.Close()
	forgejo := NewForgejo(server.URL, "", "", "", "")
	diff, err := forgejo.ComparePatch(context.Background(), "o", "r", "base", "head")
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, file := range diff.Files {
		statuses[file.Path] = file.Status
	}
	if !diff.PathsOnly || !diff.Truncated || statuses["a.go"] != "removed" || statuses["b.go"] != "modified" {
		t.Fatalf("diff = %+v", diff)
	}
	// An instance without the endpoint: cannot compare, not an error.
	if diff, err := forgejo.ComparePatch(context.Background(), "o", "other", "base", "head"); err != nil || diff != nil {
		t.Fatalf("404 = %+v, %v", diff, err)
	}
}

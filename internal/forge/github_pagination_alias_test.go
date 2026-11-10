package forge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestObservationNextPageConfinesNumericAliases(t *testing.T) {
	for _, prefix := range []string{"", "/api/v3"} {
		for _, tc := range []struct {
			name, next string
			valid      bool
		}{
			{"same path", "/repos/acme/app/git/refs/tags?page=2", true},
			{"numeric alias", "/repositories/123/git/refs/tags?page=2", true},
			{"different suffix", "/repositories/123/pulls?page=2", false},
			{"different repository", "/repos/acme/other/git/refs/tags?page=2", false},
			{"invalid id", "/repositories/not-an-id/git/refs/tags?page=2", false},
			{"zero id", "/repositories/0/git/refs/tags?page=2", false},
			{"different host", "https://other.invalid/repositories/123/git/refs/tags?page=2", false},
			{"different scheme", "http://api.example.test/repositories/123/git/refs/tags?page=2", false},
		} {
			t.Run(prefix+"/"+tc.name, func(t *testing.T) {
				g := NewGitHub("", "", "", WithAPIURL("https://api.example.test"+prefix))
				request, err := g.newRequest(context.Background(), http.MethodGet, "/repos/acme/app/git/refs/tags?per_page=100", nil)
				if err != nil {
					t.Fatal(err)
				}
				next := tc.next
				if next[0] == '/' {
					next = "https://api.example.test" + prefix + next
				}
				response := &http.Response{Header: http.Header{"Link": {fmt.Sprintf(`<%s>; rel="next"`, next)}}}
				path, err := g.observationNextPage(response, request)
				if !tc.valid {
					if err == nil {
						t.Fatalf("unsafe pagination accepted: %s", path)
					}
					return
				}
				if err != nil || path != "/repos/acme/app/git/refs/tags?page=2" {
					t.Fatalf("next=%q err=%v", path, err)
				}
			})
		}
	}
}

func TestReconciliationReadsNumericAliasPagesThroughNamedRepository(t *testing.T) {
	for _, resource := range []string{"branches", "tags", "pulls"} {
		t.Run(resource, func(t *testing.T) {
			pages := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/repos/acme/app/"+resource {
					t.Errorf("pagination escaped named repository: %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				pages++
				if r.URL.Query().Get("page") == "" {
					w.Header().Set("Link", fmt.Sprintf(`<http://%s/repositories/123/%s?per_page=100&page=2>; rel="next"`, r.Host, resource))
				}
				fmt.Fprintf(w, `[%d]`, pages)
			}))
			defer server.Close()
			g := NewGitHub("", "", "", WithAPIURL(server.URL))
			rows, err := readGitHubPages[int](context.Background(), g, "acme", "/repos/acme/app/"+resource+"?per_page=100")
			if err != nil || len(rows) != 2 || pages != 2 {
				t.Fatalf("rows=%v pages=%d err=%v", rows, pages, err)
			}
		})
	}
}

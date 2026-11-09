package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestReconciliationPagesAndPerPageValidators(t *testing.T) {
	for _, prefix := range []string{"", "/api/v3"} {
		t.Run(prefix, func(t *testing.T) {
			failSecond := false
			validations := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case prefix + "/repos/acme/app/branches":
					page := r.URL.Query().Get("page")
					if page == "" {
						w.Header().Set("Link", fmt.Sprintf(`<http://%s%s/repos/acme/app/branches?per_page=100&page=2>; rel="next"`, r.Host, prefix))
					}
					if page == "2" && failSecond {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					etag := `"` + page + `"`
					w.Header().Set("ETag", etag)
					if r.Header.Get("If-None-Match") == etag {
						validations++
						w.WriteHeader(http.StatusNotModified)
						return
					}
					fmt.Fprintf(w, `[{"name":"branch%s","commit":{"sha":"%040d"}}]`, page, 1)
				case prefix + "/repos/acme/app/tags":
					fmt.Fprint(w, `[{"name":"v1","commit":{"sha":"0000000000000000000000000000000000000002"}}]`)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			g := NewGitHub("", "", "", WithAPIURL(server.URL+prefix))
			cache := ResponseCache{}
			ctx := WithResponseCache(context.Background(), cache)
			first, err := g.ReadRefs(ctx, "acme", "app")
			if err != nil {
				t.Fatal(err)
			}
			if len(first) != 3 {
				t.Fatalf("refs=%+v", first)
			}
			second, err := g.ReadRefs(ctx, "acme", "app")
			if err != nil || !reflect.DeepEqual(first, second) || validations != 2 {
				t.Fatalf("cached refs=%+v error=%v validators=%d", second, err, validations)
			}
			failSecond = true
			if refs, err := g.ReadRefs(ctx, "acme", "app"); err == nil || refs != nil {
				t.Fatalf("partial listing returned as complete: %+v %v", refs, err)
			}
		})
	}
}

func TestReconciliationRateLimitSharedAcrossRequests(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	g := NewGitHub("", "", "", WithAPIURL(server.URL))
	_, err := g.ReadOpenPullRequests(context.Background(), "acme", "app")
	var limited *APIError
	if !errors.As(err, &limited) || time.Until(limited.RetryAt) < time.Minute {
		t.Fatalf("rate error=%v", err)
	}
	_, err = g.ReadReleases(context.Background(), "acme", "app")
	if !errors.As(err, &limited) || calls != 1 {
		t.Fatalf("shared rate budget bypassed: calls=%d err=%v", calls, err)
	}
}

func TestReconciliationPRAndWorkflowIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/app/pulls/42":
			fmt.Fprint(w, `{"number":42,"state":"closed","title":"Merged","updated_at":"2026-11-09T12:00:00Z","closed_at":"2026-11-09T11:00:00Z","merged_at":"2026-11-09T11:00:00Z","head":{"ref":"feature","sha":"head"},"base":{"ref":"main","sha":"base"}}`)
		case "/repos/acme/app/actions/runs/99":
			fmt.Fprint(w, `{"id":99,"run_attempt":3,"head_sha":"head","status":"completed","conclusion":"cancelled"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	g := NewGitHub("", "", "", WithAPIURL(server.URL))
	pr, err := g.ReadPullRequest(context.Background(), "acme", "app", 42)
	if err != nil || !pr.Merged || pr.ClosedAt == nil || pr.BaseSHA != "base" || pr.Action != "closed" {
		t.Fatalf("PR=%+v err=%v", pr, err)
	}
	run, err := g.ReadWorkflowRun(context.Background(), "acme", "app", "99")
	if err != nil || run.Attempt != "3" || run.Conclusion != "cancelled" {
		t.Fatalf("run=%+v err=%v", run, err)
	}
}

func TestReconciliationCacheDoesNotRetainOldWorkflowHistory(t *testing.T) {
	cache := ResponseCache{"/old-run": {ETag: "old"}}
	ctx := WithResponseCache(context.Background(), cache)
	PruneResponseCache(ctx)
	if len(cache) != 0 {
		t.Fatalf("unvisited historical responses retained: %+v", cache)
	}
}

func TestReconciliationReadTierPermissions(t *testing.T) {
	for resource, permission := range map[string]string{"pulls": "pull_requests", "actions/runs/7": "actions", "tags": "contents", "releases": "contents"} {
		for _, prefix := range []string{"", "/api/v3"} {
			req, _ := http.NewRequest(http.MethodGet, "https://api.github.com"+prefix+"/repos/acme/app/"+resource, nil)
			scope := scopeForRequest(req)
			if scope.Repo != "app" {
				t.Fatalf("missing repository confinement for %s", req.URL.Path)
			}
			if !reflect.DeepEqual(scope.Permissions, map[string]string{permission: "read"}) {
				t.Fatalf("%s scope=%+v", resource, scope)
			}
			if _, err := resolveTokenPermissions(TierRead, map[string]string{permission: "read"}, scope.Permissions); err != nil {
				t.Fatal(err)
			}
		}
	}
}

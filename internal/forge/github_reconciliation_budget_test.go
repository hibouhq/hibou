package forge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPollingBoundsDecodedResponseMemory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, strings.Repeat("x", reconciliationPageBytes+1))
	}))
	defer server.Close()
	cache := ResponseCache{}
	g := NewGitHub("", "", "", WithAPIURL(server.URL))
	if _, err := g.ReadOpenPullRequests(WithResponseCache(context.Background(), cache), "acme", "app"); err == nil {
		t.Fatal("oversized page accepted")
	}
	if len(cache) != 0 {
		t.Fatal("incomplete response committed to conditional cache")
	}
}

func TestPollingCacheVersionRequiresFreshRepresentation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" {
			t.Error("old schema reused an ETag")
		}
		w.Header().Set("ETag", `"fresh"`)
		fmt.Fprint(w, `[]`)
	}))
	defer server.Close()
	path := repoReadPath("acme", "app", "pulls?state=open&per_page=100")
	cache := ResponseCache{path: {Version: 0, ETag: `"old"`, Body: []byte(`[]`)}}
	g := NewGitHub("", "", "", WithAPIURL(server.URL))
	if _, err := g.ReadOpenPullRequests(WithResponseCache(context.Background(), cache), "acme", "app"); err != nil {
		t.Fatal(err)
	}
	if cache[path].Version != reconciliationCacheVersion {
		t.Fatal("cache schema version not upgraded")
	}
}

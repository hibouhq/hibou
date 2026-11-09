package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type pollingMeteredConnection struct {
	net.Conn
	received, sent *atomic.Int64
}

func (c *pollingMeteredConnection) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.received.Add(int64(n))
	return n, err
}
func (c *pollingMeteredConnection) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.sent.Add(int64(n))
	return n, err
}

func TestPollingInventoryBandwidthAtHundredsOfRepositories(t *testing.T) {
	const perOrganization = 500
	var requests, tokens, bodyBytes atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/api/v3/app/installations":
			w.Header().Set("ETag", `"installations"`)
			if r.Header.Get("If-None-Match") == `"installations"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			body := `[{"id":7,"account":{"id":42,"login":"acme","type":"Organization"}},{"id":8,"account":{"id":43,"login":"other","type":"Organization"}}]`
			bodyBytes.Add(int64(len(body)))
			fmt.Fprint(w, body)
		case "/api/v3/app/installations/7/access_tokens", "/api/v3/app/installations/8/access_tokens":
			tokens.Add(1)
			id := "7"
			if strings.Contains(r.URL.Path, "/8/") {
				id = "8"
			}
			body := fmt.Sprintf(`{"token":"inventory-%s","expires_at":"2099-01-01T00:00:00Z"}`, id)
			bodyBytes.Add(int64(len(body)))
			fmt.Fprint(w, body)
		case "/api/v3/installation/repositories":
			owner := "acme"
			offset := 0
			if strings.Contains(r.Header.Get("Authorization"), "inventory-8") {
				owner = "other"
				offset = perOrganization
			}
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page == 0 {
				page = 1
			}
			etag := fmt.Sprintf(`"%s-%d"`, owner, page)
			w.Header().Set("ETag", etag)
			if page < perOrganization/100 {
				w.Header().Set("Link", fmt.Sprintf(`<http://%s/api/v3/installation/repositories?per_page=100&page=%d>; rel="next"`, r.Host, page+1))
			}
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			repositories := []map[string]any{}
			for i := (page - 1) * 100; i < page*100; i++ {
				name := fmt.Sprintf("repository-%04d", i)
				repositories = append(repositories, map[string]any{"id": 10000 + offset + i, "name": name, "full_name": owner + "/" + name,
					"owner": map[string]any{"login": owner}, "default_branch": "main", "private": true,
					"description": strings.Repeat("fixture-only metadata; ", 100)})
			}
			body, err := json.Marshal(map[string]any{"total_count": perOrganization, "repositories": repositories})
			if err != nil {
				t.Error(err)
				http.Error(w, "fixture error", http.StatusInternalServerError)
				return
			}
			bodyBytes.Add(int64(len(body)))
			if _, err := w.Write(body); err != nil {
				t.Error(err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	var received, sent atomic.Int64
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &pollingMeteredConnection{Conn: connection, received: &received, sent: &sent}, nil
	}}
	defer transport.CloseIdleConnections()
	g := NewGitHub("", "", "", WithAPIURL(server.URL+"/api/v3"), WithAppCredentials(1, testAppKeyPEM(t)), WithHTTPClient(&http.Client{Transport: transport, Timeout: 10 * time.Second}))
	cache := ResponseCache{}
	observe := func() {
		ctx := WithResponseCache(context.Background(), cache)
		installations, err := g.Installations(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(installations) != 2 {
			t.Fatalf("installations=%d", len(installations))
		}
		for _, installation := range installations {
			repositories, err := g.ListInstallationRepositories(ctx, installation.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(repositories) != perOrganization {
				t.Fatalf("repository count=%d", len(repositories))
			}
			for _, repo := range repositories {
				if repo.Owner != installation.AccountName {
					t.Fatal("conditional cache mixed installation identities")
				}
			}
		}
		PruneResponseCache(ctx)
	}
	observe()
	coldRequests, coldBodies, coldTokens := requests.Load(), bodyBytes.Load(), tokens.Load()
	coldReceived, coldSent := received.Load(), sent.Load()
	retained := 0
	for _, response := range cache {
		retained += len(response.Body)
	}
	if int64(retained) >= coldBodies/3 {
		t.Fatalf("conditional cache retained irrelevant response fields: %d bytes for %d received", retained, coldBodies)
	}
	observe()
	warmRequests, warmBodies, warmTokens := requests.Load()-coldRequests, bodyBytes.Load()-coldBodies, tokens.Load()-coldTokens
	if coldRequests != 13 || warmRequests != 11 || coldTokens != 2 || warmTokens != 0 || warmBodies != 0 {
		t.Fatalf("unexpected inventory traffic: cold requests=%d tokens=%d bytes=%d; warm requests=%d tokens=%d bytes=%d",
			coldRequests, coldTokens, coldBodies, warmRequests, warmTokens, warmBodies)
	}
	t.Logf("%d repositories across 2 organizations: cold %d requests, %d response-body bytes; unchanged warm %d requests, %d response-body bytes, %d token mints (headers/TLS excluded)",
		2*perOrganization, coldRequests, coldBodies, warmRequests, warmBodies, warmTokens)
	t.Logf("Measured HTTP/1.1 TCP bytes including headers, excluding TLS: cold received=%d sent=%d; warm received=%d sent=%d (synthetic metadata, uncompressed fixture)",
		coldReceived, coldSent, received.Load()-coldReceived, sent.Load()-coldSent)
	t.Logf("Projected conditional-cache metadata retained=%d bytes (unused fixture descriptions omitted)", retained)
}

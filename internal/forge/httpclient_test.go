package forge

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The forge client has deadlines: a server that never sends headers is
// abandoned instead of blocking a background job forever.
func TestNewHTTPClientHasDeadlines(t *testing.T) {
	t.Parallel()

	client := NewHTTPClient()
	if client.Timeout <= 0 {
		t.Fatal("no overall timeout")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.ResponseHeaderTimeout <= 0 || transport.TLSHandshakeTimeout <= 0 {
		t.Fatalf("transport without header/TLS deadlines: %+v", client.Transport)
	}

	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer server.Close()
	defer close(release)
	short := NewHTTPClient()
	short.Timeout = 200 * time.Millisecond
	started := time.Now()
	response, err := short.Get(server.URL)
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("a hung server answered")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("gave up after %s", elapsed)
	}
}

// A response larger than MaxResponseBytes fails to decode instead of being
// read into memory whole.
func TestLimitResponse(t *testing.T) {
	t.Parallel()

	var out any
	big := io.MultiReader(strings.NewReader(`"`), bytes.NewReader(bytes.Repeat([]byte("a"), MaxResponseBytes+10)), strings.NewReader(`"`))
	if err := json.NewDecoder(LimitResponse(big)).Decode(&out); err == nil {
		t.Fatal("an oversized response decoded")
	}
	if err := json.NewDecoder(LimitResponse(strings.NewReader(`{"ok":true}`))).Decode(&out); err != nil {
		t.Fatalf("a small response failed: %v", err)
	}
}

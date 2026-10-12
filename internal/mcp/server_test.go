package mcp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestHTTPServerHasTimeoutsAndBodyLimit(t *testing.T) {
	t.Parallel()

	_, httpSrv := newHTTPServer(New(nil, nil, zerolog.Nop(), "test"), nil, zerolog.Nop())
	if httpSrv.ReadHeaderTimeout == 0 || httpSrv.ReadTimeout == 0 || httpSrv.WriteTimeout == 0 || httpSrv.IdleTimeout == 0 {
		t.Fatalf("MCP http.Server is missing timeouts: %+v", httpSrv)
	}
	if httpSrv.MaxHeaderBytes != mcpMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", httpSrv.MaxHeaderBytes, mcpMaxHeaderBytes)
	}

	body := bytes.Repeat([]byte("a"), mcpMaxBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, mcpEndpointPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	httpSrv.Handler.ServeHTTP(recorder, req)
	if recorder.Code == http.StatusOK || recorder.Code == http.StatusAccepted {
		t.Fatalf("oversized body status = %d, want a rejection", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	httpSrv.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/other", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", recorder.Code)
	}
}

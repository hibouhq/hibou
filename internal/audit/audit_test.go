package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
)

func TestRequestContext(t *testing.T) {
	tests := []struct {
		name      string
		remote    string
		forwarded string
		userAgent string
		wantIP    string
		wantAgent string
	}{
		{name: "basic request", remote: "192.168.1.1:1234", wantIP: "192.168.1.1:1234"},
		{name: "forwarded for", remote: "192.168.1.1:1234", forwarded: "10.0.0.1", wantIP: "10.0.0.1"},
		{name: "user agent", remote: "192.168.1.1:1234", userAgent: "hibou-cli/1.0", wantIP: "192.168.1.1:1234", wantAgent: "hibou-cli/1.0"},
		{name: "forwarded and user agent", remote: "192.168.1.1:1234", forwarded: "10.0.0.1", userAgent: "hibou-web/2.0", wantIP: "10.0.0.1", wantAgent: "hibou-web/2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf("http.NewRequest() error = %v", err)
			}
			r.RemoteAddr = tt.remote
			if tt.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			if tt.userAgent != "" {
				r.Header.Set("User-Agent", tt.userAgent)
			}

			var gotIP, gotAgent string
			handler := middleware.ClientIPFromXFFTrustedProxies(1)(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				gotIP, gotAgent = RequestContext(req)
			}))
			handler.ServeHTTP(httptest.NewRecorder(), r)
			if gotIP != tt.wantIP {
				t.Fatalf("ip = %q, want %q", gotIP, tt.wantIP)
			}
			if gotAgent != tt.wantAgent {
				t.Fatalf("userAgent = %q, want %q", gotAgent, tt.wantAgent)
			}
		})
	}
}

func TestChangedFieldsNamesFieldsNotValues(t *testing.T) {
	type gate struct {
		Name      string   `json:"name"`
		MaxHigh   int      `json:"max_high"`
		Tags      []string `json:"tags"`
		UpdatedAt string   `json:"updated_at"`
	}
	before := gate{Name: "prod", MaxHigh: 0, Tags: []string{"a"}, UpdatedAt: "t1"}
	after := gate{Name: "prod", MaxHigh: 3, Tags: []string{"a", "b"}, UpdatedAt: "t2"}

	got := ChangedFields(before, after, "updated_at")
	if len(got) != 2 || got[0] != "max_high" || got[1] != "tags" {
		t.Fatalf("ChangedFields = %v, want [max_high tags]", got)
	}
	if fields := ChangedFields(before, before); len(fields) != 0 {
		t.Fatalf("identical snapshots reported %v", fields)
	}
	if fields := ChangedFields(map[string]any{"a": 1}, map[string]any{"b": 1}); len(fields) != 2 {
		t.Fatalf("added+removed keys = %v, want both", fields)
	}
	if fields := ChangedFields("x", before); fields != nil {
		t.Fatalf("non-object input = %v, want nil", fields)
	}
}

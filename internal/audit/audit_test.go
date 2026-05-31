package audit

import (
	"net/http"
	"testing"
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

			gotIP, gotAgent := RequestContext(r)
			if gotIP != tt.wantIP {
				t.Fatalf("ip = %q, want %q", gotIP, tt.wantIP)
			}
			if gotAgent != tt.wantAgent {
				t.Fatalf("userAgent = %q, want %q", gotAgent, tt.wantAgent)
			}
		})
	}
}

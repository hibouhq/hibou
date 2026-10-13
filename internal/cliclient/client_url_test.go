package cliclient

import (
	"strings"
	"testing"
)

// Q15: the token never goes over plain HTTP to a remote host unless the
// operator opts in.
func TestNewWithOverridesRefusesRemotePlainHTTP(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HIBOU_SERVER", "")
	t.Setenv("HIBOU_TOKEN", "")
	t.Setenv(InsecureHTTPEnv, "")
	cases := []struct {
		server   string
		insecure string
		ok       bool
	}{
		{"https://hibou.example.com", "", true},
		{"http://localhost:8080", "", true},
		{"http://127.0.0.1:8080", "", true},
		{"http://[::1]:8080", "", true},
		{"http://hibou.example.com", "", false},
		{"http://hibou.example.com", "1", true},
		{"http://hibou.example.com", "true", false},
		{"ftp://hibou.example.com", "1", false},
		{"hibou.example.com", "", false},
	}
	for _, tc := range cases {
		t.Setenv(InsecureHTTPEnv, tc.insecure)
		_, err := NewWithOverrides(tc.server, "tok")
		if (err == nil) != tc.ok {
			t.Errorf("NewWithOverrides(%q, %s=%q) = %v, want ok=%v", tc.server, InsecureHTTPEnv, tc.insecure, err, tc.ok)
		}
		if err != nil && strings.HasPrefix(tc.server, "http://") && !strings.Contains(err.Error(), InsecureHTTPEnv) {
			t.Errorf("error should name the opt-in: %v", err)
		}
	}
}

package cmd

import "testing"

// A14: a token is never sent over plain HTTP except to a loopback server or
// with an explicit opt-in.
func TestCheckLoginServerURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		server   string
		insecure bool
		ok       bool
	}{
		{"https://hibou.example.com", false, true},
		{"http://localhost:8585", false, true},
		{"http://127.0.0.1:8585", false, true},
		{"http://[::1]:8585", false, true},
		{"http://hibou.example.com", false, false},
		{"http://localhost.evil.example", false, false},
		{"http://hibou.example.com", true, true},
		{"ftp://hibou.example.com", false, false},
		{"hibou.example.com", false, false},
	} {
		err := checkLoginServerURL(tc.server, tc.insecure)
		if (err == nil) != tc.ok {
			t.Errorf("checkLoginServerURL(%q, insecure=%v) = %v, want ok=%v", tc.server, tc.insecure, err, tc.ok)
		}
	}
}

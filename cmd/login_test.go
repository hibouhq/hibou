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

func TestNormalizeServerURL(t *testing.T) {
	cases := map[string]string{
		"hibouhq.com":                      "https://hibouhq.com",
		"  hibouhq.com/  ":                 "https://hibouhq.com",
		"https://hibou.example.com/":       "https://hibou.example.com",
		"HTTPS://hibou.example.com/sub/":   "https://hibou.example.com/sub",
		"http://localhost:8585":            "http://localhost:8585",
		"localhost:8585":                   "http://localhost:8585",
		"127.0.0.1:8585/":                  "http://127.0.0.1:8585",
		"https://u:p@hibou.example/?x=1#y": "https://hibou.example",
	}
	for in, want := range cases {
		got, err := normalizeServerURL(in)
		if err != nil || got != want {
			t.Errorf("normalizeServerURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "https://", "://nohost"} {
		if got, err := normalizeServerURL(bad); err == nil {
			t.Errorf("normalizeServerURL(%q) = %q, want error", bad, got)
		}
	}
	if !sameServer("hibouhq.com", "https://HIBOUHQ.com/") {
		t.Error("sameServer should ignore scheme default, case and trailing slash")
	}
}

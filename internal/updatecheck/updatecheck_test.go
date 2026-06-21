package updatecheck

import "testing"

func TestIsNewer(t *testing.T) {
	cases := []struct {
		name    string
		current string
		latest  string
		want    bool
	}{
		{"prerelease bump", "v0.1.0-alpha.30", "v0.1.0-alpha.31", true},
		{"prerelease bump no v prefix", "0.1.0-alpha.30", "0.1.0-alpha.31", true},
		{"same version", "v0.1.0-alpha.30", "v0.1.0-alpha.30", false},
		{"latest older", "v0.1.0-alpha.31", "v0.1.0-alpha.30", false},
		{"stable over prerelease", "v0.1.0-alpha.30", "v0.1.0", true},
		{"minor bump", "v0.1.0", "v0.2.0", true},
		{"dev build never nags", "dev", "v0.1.0-alpha.31", false},
		{"empty latest", "v0.1.0-alpha.30", "", false},
		{"garbage latest", "v0.1.0-alpha.30", "not-a-version", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNewer(tc.current, tc.latest); got != tc.want {
				t.Fatalf("isNewer(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
			}
		})
	}
}

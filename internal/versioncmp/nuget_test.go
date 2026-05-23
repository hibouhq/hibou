package versioncmp

import "testing"

func TestNuGetCompare(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{"1.0.0", "1.0.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.0-beta", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0.1", "1.0.0.2", -1},
		{"1.0.0.0", "1.0.0.1", -1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.1", "1.0.0.9", 1},
		{"1.2.3", "1.2.3", 0},
		{"1.2.3.4", "1.2.3", 1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0+build1", "1.0.0+build2", 0},
		{"v1.0.0", "1.0.0", 0},
		{"2.0.0", "10.0.0", -1},
		{"1.0.0.10", "1.0.0.2", 1},
		{"1.0.0-beta", "1.0.0-beta.1", -1},
		{"1.0.0-beta.2", "1.0.0-beta.10", -1},
		{"1.0.0", "1.0.0-beta", 1},
		{"1.0.0.0", "1.0.0.0", 0},
		{"1.0.0-alpha", "1.0.0-alpha", 0},
		{"1.0.0.0-alpha", "1.0.0-alpha", 0},
		{"1.0.0.1-alpha", "1.0.0.1", -1},
		{"1.0.0.1", "1.0.0", 1},
		{"1.0.0-zeta", "1.0.0-rc", 1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
	}

	cmp := &NuGet{}
	for _, tt := range tests {
		if got := cmp.Compare(tt.a, tt.b); got != tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := cmp.Compare(tt.b, tt.a); got != -tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

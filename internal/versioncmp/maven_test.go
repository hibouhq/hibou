package versioncmp

import "testing"

func TestMavenCompare(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{"1.0", "1.1", -1},
		{"1.0", "1.0", 0},
		{"2.0", "1.0", 1},
		{"1.0-alpha-1", "1.0-beta-1", -1},
		{"1.0-beta-1", "1.0-rc-1", -1},
		{"1.0-rc-1", "1.0", -1},
		{"1.0-SNAPSHOT", "1.0", -1},
		{"1.0", "1.0-sp-1", -1},
		{"1.0-alpha", "1.0-a", 0},
		{"1.0.1", "1.0.2", -1},
		{"1.0.2", "1.0.10", -1},
		{"1.0-m1", "1.0-rc1", -1},
		{"1.0-final", "1.0", 0},
		{"1.0-ga", "1.0", 0},
		{"1.0-cr-1", "1.0-rc-1", 0},
		{"1.0-alpha-1", "1.0-alpha-2", -1},
		{"1.0-beta", "1.0-beta-1", -1},
		{"1.0-sp", "1.0-sp-1", -1},
		{"1.0.0", "1.0", 0},
		{"1.0.0-0", "1.0.0", 1},
		{"1.0-zeta", "1.0-sp", 1},
		{"1.0-zeta", "1.0-alpha", 1},
		{"1.0-milestone-1", "1.0-rc-1", -1},
		{"1.0-rc-1", "1.0-snapshot", -1},
		{"1.0-1", "1.0-alpha", 1},
		{"1.0-1", "1.0-2", -1},
		{"1.0.0.0", "1.0", 0},
	}

	cmp := &Maven{}
	for _, tt := range tests {
		if got := cmp.Compare(tt.a, tt.b); got != tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := cmp.Compare(tt.b, tt.a); got != -tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

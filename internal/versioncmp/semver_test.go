package versioncmp

import "testing"

func TestSemverCompare(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.2.3", "1.3.0", -1},
		{"0.1.0", "0.2.0", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-1", "1.0.0-2", -1},
		{"1.0.0-2", "1.0.0-10", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0+build1", "1.0.0+build2", 0},
		{"1.0.0+build", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"v1.0.0", "v1.0.1", -1},
		{"1.2", "1.2.0", 0},
		{"1.2", "1.2.1", -1},
		{"1.2", "1.3", -1},
		{"0.0.0", "0.0.1", -1},
		{"10.0.0", "9.0.0", 1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.0-alpha", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"v2.1", "2.1.0", 0},
		{"2.1.0", "2.1.0-alpha", 1},
		{"1.0.0-alpha.10", "1.0.0-alpha.2", 1},
		{"1.0.0-alpha-1", "1.0.0-alpha-2", -1},
	}

	cmp := &Semver{}
	for _, tt := range tests {
		if got := cmp.Compare(tt.a, tt.b); got != tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := cmp.Compare(tt.b, tt.a); got != -tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestSemverValid(t *testing.T) {
	cmp := &Semver{}
	valid := []string{"1.0.0", "1.2", "v1.2.3", "1.0.0-alpha.1", "1.0.0+build"}
	invalid := []string{"", "1", "1.2.3.4", "1.2.x", "1.0.0-"}
	for _, v := range valid {
		if !cmp.Valid(v) {
			t.Fatalf("expected %q to be valid", v)
		}
	}
	for _, v := range invalid {
		if cmp.Valid(v) {
			t.Fatalf("expected %q to be invalid", v)
		}
	}
}

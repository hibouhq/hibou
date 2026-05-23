package versioncmp

import "testing"

func TestRubyGemsCompare(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{"1.0", "1.1", -1},
		{"1.0", "1.0", 0},
		{"1.0.0", "1.0", 0},
		{"1.0.pre", "1.0", -1},
		{"1.0.alpha", "1.0.beta", -1},
		{"1.0.0.rc1", "1.0.0", -1},
		{"1.0.1", "1.0.2", -1},
		{"1.0.0.pre1", "1.0.0.pre2", -1},
		{"1.0.0.a", "1.0.0.b", -1},
		{"2.0", "1.9.9", 1},
		{"1.0.0", "1.0.0.0", 0},
		{"1.0.0.1", "1.0.0", 1},
		{"1.0.beta", "1.0.rc", -1},
		{"1.0.rc1", "1.0.rc2", -1},
		{"1.0.0.preview", "1.0.0", -1},
		{"1.0.10", "1.0.2", 1},
		{"1.0.0.pre", "1.0.0.rc", -1},
		{"1.0.0.z", "1.0.0.zz", -1},
		{"1.0.0.0.0", "1.0", 0},
		{"1.0.0alpha", "1.0.0beta", -1},
		{"1.0.0alpha1", "1.0.0alpha2", -1},
		{"1.0.0alpha1", "1.0.0", -1},
		{"1.0.0", "1.0.0beta1", 1},
		{"1.0.0.1", "1.0.0.2", -1},
		{"1.0.0.pre", "1.0.0.pre", 0},
		{"1.0.0.pre", "1.0.1", -1},
	}

	cmp := &RubyGems{}
	for _, tt := range tests {
		if got := cmp.Compare(tt.a, tt.b); got != tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := cmp.Compare(tt.b, tt.a); got != -tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

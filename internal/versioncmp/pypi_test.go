package versioncmp

import "testing"

func TestPyPICompare(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{"1.0", "1.1", -1},
		{"1.0", "1.0", 0},
		{"1.0.0", "1.0", 0},
		{"1.0a1", "1.0b1", -1},
		{"1.0b1", "1.0rc1", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0.dev1", "1.0a1", -1},
		{"1.0a1", "1.0a2", -1},
		{"1.0", "1.0.post1", -1},
		{"1.0.post1", "1.0.post2", -1},
		{"1.0.post1", "1.1", -1},
		{"1!1.0", "2.0", 1},
		{"1.0+local1", "1.0+local2", 0},
		{"1.0+local", "1.0", 0},
		{"1.0a1", "1.0.alpha1", 0},
		{"1.0b1", "1.0.beta1", 0},
		{"1.0c1", "1.0rc1", 0},
		{"0!1.0", "1.0", 0},
		{"1.0.dev1", "1.0.dev2", -1},
		{"1.0rc1", "1.0rc2", -1},
		{"1.0.post0", "1.0", 1},
		{"1.0.0.0", "1.0", 0},
		{"1.0a1", "1.0", -1},
		{"1.0a1.dev1", "1.0a1", -1},
		{"1.0b1.dev1", "1.0b1", -1},
		{"1.0.post1.dev1", "1.0.post1", -1},
		{"1.0a1", "1.0b1.dev1", -1},
		{"2!0.1", "1!9.9", 1},
		{"1.0.post1", "1.0.post1", 0},
		{"1.0a10", "1.0a2", 1},
		{"1.0rc1", "1.0.post1", -1},
	}

	cmp := &PyPI{}
	for _, tt := range tests {
		if got := cmp.Compare(tt.a, tt.b); got != tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := cmp.Compare(tt.b, tt.a); got != -tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

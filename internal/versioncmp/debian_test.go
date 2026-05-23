package versioncmp

import "testing"

func TestDebianCompare(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{"1.0-1", "1.0-2", -1},
		{"1.0-1", "1.0-1", 0},
		{"2.0-1", "1.0-1", 1},
		{"1:1.0-1", "2:1.0-1", -1},
		{"1:1.0-1", "1.0-1", 1},
		{"1.0~beta1", "1.0", -1},
		{"1.0~alpha", "1.0~beta", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.2.3-1+deb12u1", "1.2.3-1", 1},
		{"1.2.3-1+deb12u1", "1.2.4-1", -1},
		{"1.2.3-1+deb12u2", "1.2.3-1+deb12u1", 1},
		{"1.0-1", "1.0-1.1", -1},
		{"1.0-2", "1.0-10", -1},
		{"1.0", "1.0-1", -1},
		{"0:1.0", "1.0", 0},
		{"1.000", "1.0", 0},
		{"1.0+really1", "1.0+really2", -1},
		{"1.0a", "1.0b", -1},
		{"1.0a", "1.0~a", 1},
		{"1.0-0", "1.0", 1},
		{"2:0", "1:999", 1},
		{"1.0.0", "1.0", 1},
		{"1.0", "1.0.0", -1},
		{"1.0.0.0", "1.0.0", 1},
		{"1.0~~", "1.0~", -1},
		{"1.0-1ubuntu1", "1.0-1deb1", 1},
		{"1.0-1ubuntu1", "1.0-1ubuntu2", -1},
		{"1.0~rc1-1", "1.0~rc1-2", -1},
		{"1.0.0-1", "1.0.0-1+b1", -1},
	}

	cmp := &Debian{}
	for _, tt := range tests {
		if got := cmp.Compare(tt.a, tt.b); got != tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := cmp.Compare(tt.b, tt.a); got != -tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

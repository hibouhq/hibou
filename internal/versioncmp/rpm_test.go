package versioncmp

import "testing"

func TestRPMCompare(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{"1.0-1.el9", "1.0-2.el9", -1},
		{"1.0-1.el9", "1.0-1.el9", 0},
		{"2.0-1.el9", "1.0-1.el9", 1},
		{"1:1.0-1", "2:1.0-1", -1},
		{"2:1.0-1", "1:2.0-1", 1},
		{"0:1.0-1", "1.0-1", 0},
		{"1.0", "1.1", -1},
		{"1.001", "1.1", 0},
		{"1.0a", "1.0b", -1},
		{"2.0.1", "2.0.10", -1},
		{"1.0.0a", "1.0.0", 1},
		{"1.0.2", "1.0.2a", -1},
		{"1.2.3-1.el9.x86_64", "1.2.3-1.el9", 0},
		{"1.2.3-1.el9.aarch64", "1.2.3-1.el9", 0},
		{"1.0-1.el8", "1.0-1.el9", -1},
		{"1.0-2.el9", "1.0-10.el9", -1},
		{"1.0~beta", "1.0", -1},
		{"1.0-1", "1.0", 1},
		{"1.0_1", "1.0-1", 0},
		{"3:0.1", "2:99.9", 1},
		{"1.01a", "1.1a", 0},
		{"1.0z", "1.0aa", 1},
		{"1.0.0", "1.0", 0},
		{"1.0.0-0", "1.0.0-1", -1},
		{"1.0.0-1.fc39", "1.0.0-1.fc40", -1},
		{"1.0b", "1.0", 1},
		{"1.0", "1.0a", -1},
	}

	cmp := &RPM{}
	for _, tt := range tests {
		if got := cmp.Compare(tt.a, tt.b); got != tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := cmp.Compare(tt.b, tt.a); got != -tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

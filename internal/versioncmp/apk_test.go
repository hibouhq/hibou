package versioncmp

import "testing"

func TestAPKCompare(t *testing.T) {
	tests := []struct {
		a    string
		b    string
		want int
	}{
		{"1.0.0", "1.0.1", -1},
		{"1.0.0", "1.0.0", 0},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0_alpha1", "1.0.0_beta1", -1},
		{"1.0.0_rc1", "1.0.0", -1},
		{"1.0.0_alpha1", "1.0.0", -1},
		{"1.0.0_p1", "1.0.0", 1},
		{"1.0.0-r0", "1.0.0-r1", -1},
		{"1.0.0-r2", "1.0.0-r10", -1},
		{"1.0.0_pre1", "1.0.0_rc1", -1},
		{"1.0.0_beta2", "1.0.0_beta10", -1},
		{"1.0.0~git1", "1.0.0", -1},
		{"1.0.0a", "1.0.0b", -1},
		{"1.0.01", "1.0.1", 0},
		{"1.2.0", "1.10.0", -1},
		{"1.0.0_p1-r0", "1.0.0_p1-r1", -1},
		{"1.0.0_alpha1-r2", "1.0.0_alpha1-r10", -1},
		{"1.0.0_rc1", "1.0.0_p1", -1},
		{"1.0.0_beta1", "1.0.0_rc1", -1},
		{"1.0.0_pre1", "1.0.0_beta1", 1},
		{"1.0.0_p2", "1.0.0_p10", -1},
		{"1.0.0-r5", "1.0.0", 1},
		{"1.0.0.1", "1.0.0.2", -1},
		{"1.0.0_alpha", "1.0.0_alpha1", -1},
		{"1.0.0", "1.0.0_p1", -1},
		{"1.0.0_beta1", "1.0.0_beta1", 0},
	}

	cmp := &APK{}
	for _, tt := range tests {
		if got := cmp.Compare(tt.a, tt.b); got != tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := cmp.Compare(tt.b, tt.a); got != -tt.want {
			t.Fatalf("Compare(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

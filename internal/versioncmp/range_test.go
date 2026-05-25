package versioncmp

import (
	"errors"
	"testing"
)

func TestInRange(t *testing.T) {
	tests := []struct {
		ecosystem    string
		version      string
		introduced   string
		fixed        string
		lastAffected string
		want         bool
		wantErr      bool
	}{
		{"npm", "1.1.5", "1.0.0", "1.2.3", "", true, false},
		{"npm", "1.2.3", "1.0.0", "1.2.3", "", false, false},
		{"npm", "0.9.0", "1.0.0", "1.2.3", "", false, false},
		{"npm", "2.0.0", "1.0.0", "", "1.5.0", false, false},
		{"npm", "1.5.0", "1.0.0", "", "1.5.0", true, false},
		{"npm", "2.0.0", "1.0.0", "", "", true, false},
		{"rpm", "1.2.3-1.el9", "1.0.0-1.el9", "1.2.4-1.el9", "", true, false},
		{"rpm", "1.2.3-1.el9.x86_64", "1.0.0-1.el9", "1.2.4-1.el9", "", true, false},
		{"deb", "1.2.3-1+deb12u1", "1.0.0-1", "1.2.4-1", "", true, false},
		{"apk", "1.0.0_beta1", "1.0.0_alpha1", "1.0.0", "", true, false},
		{"apk", "1.0.0_p1", "1.0.0", "", "1.0.0_p2", true, false},
		{"maven", "1.0-rc-1", "1.0-alpha-1", "1.0", "", true, false},
		{"maven", "1.0-sp-1", "1.0", "", "1.0-sp-2", true, false},
		{"pypi", "1.0rc1", "1.0a1", "1.0", "", true, false},
		{"pypi", "1.0.post1", "1.0", "", "1.0.post1", true, false},
		{"rubygems", "1.0.pre", "1.0.pre", "1.0", "", true, false},
		{"rubygems", "1.0", "1.0.pre", "1.0", "", false, false},
		{"nuget", "1.0.0-beta", "1.0.0-alpha", "1.0.0", "", true, false},
		{"nuget", "1.0.0.1", "1.0.0", "", "1.0.0.1", true, false},
		{"go", "v1.2.0", "1.0.0", "1.3.0", "", true, false},
		{"cargo", "1.4.0", "1.0.0", "", "1.3.9", false, false},
		{"unknown", "1.0", "0.9", "1.1", "", false, true},
	}

	for _, tt := range tests {
		got, err := InRange(tt.ecosystem, tt.version, tt.introduced, tt.fixed, tt.lastAffected)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("InRange(%q, %q, ...) error = nil, want error", tt.ecosystem, tt.version)
			}
			var ecosystemErr *EcosystemError
			if !errors.As(err, &ecosystemErr) {
				t.Fatalf("InRange(%q, %q, ...) error type = %T, want *EcosystemError", tt.ecosystem, tt.version, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("InRange(%q, %q, ...) error = %v", tt.ecosystem, tt.version, err)
		}
		if got != tt.want {
			t.Fatalf("InRange(%q, %q, %q, %q, %q) = %v, want %v", tt.ecosystem, tt.version, tt.introduced, tt.fixed, tt.lastAffected, got, tt.want)
		}
	}
}

func TestStripArch(t *testing.T) {
	tests := map[string]string{
		"1.2.3-1.el9.x86_64":  "1.2.3-1.el9",
		"1.2.3-1.el9.aarch64": "1.2.3-1.el9",
		"1.2.3-1.el9.noarch":  "1.2.3-1.el9",
		"1.2.3-1.el9":         "1.2.3-1.el9",
	}
	for in, want := range tests {
		if got := StripArch(in); got != want {
			t.Fatalf("StripArch(%q) = %q, want %q", in, got, want)
		}
	}
}

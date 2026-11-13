package config

import (
	"slices"
	"testing"
)

func TestManagedMaintenanceOperatorAllowlistIsExplicit(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{" ,  , ", nil},
		{" release/*,maintenance/* ", []string{"release/*", "maintenance/*"}},
	} {
		t.Setenv("HIBOU_REMEDIATION_MAINTENANCE_BRANCH_ALLOWLIST", tt.raw)
		if got := ManagedMaintenanceBranchAllowlist(); !slices.Equal(got, tt.want) {
			t.Fatalf("operator allowlist=%v want=%v", got, tt.want)
		}
	}
}

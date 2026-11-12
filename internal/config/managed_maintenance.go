package config

import (
	"os"
	"strings"
)

func ManagedMaintenanceBranchAllowlist() []string {
	return managedMaintenanceAllowlist(os.Getenv("HIBOU_REMEDIATION_MAINTENANCE_BRANCH_ALLOWLIST"))
}

func managedMaintenanceAllowlist(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var values []string
	for _, entry := range strings.Split(raw, ",") {
		if value := strings.TrimSpace(entry); value != "" {
			values = append(values, value)
		}
	}
	return values
}

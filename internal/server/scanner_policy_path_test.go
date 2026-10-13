package server

import "testing"

func TestValidScopeOverridePath(t *testing.T) {
	for path, want := range map[string]bool{
		"java":         true,
		"web/app":      true,
		"":             false,
		".":            false,
		"../etc":       false,
		"a/../b":       false,
		"-x":           false,
		"--exclude=*":  false,
		"src/-literal": true,
	} {
		if got := validScopeOverridePath(path); got != want {
			t.Errorf("validScopeOverridePath(%q) = %v, want %v", path, got, want)
		}
	}
}

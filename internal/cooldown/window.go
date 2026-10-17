// Package cooldown holds the release cooldown window vocabulary shared by
// the repository config, the package policy and the gate (ADR-048 §3). It
// has no dependencies so every layer can import it.
package cooldown

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// WindowAuto uses the publisher's own cooldown end (deps.dev).
	WindowAuto = "auto"
	// WindowOff disables the check.
	WindowOff = "off"
	// WindowDuration counts a fixed duration from the publish date.
	WindowDuration = "duration"
)

// ParseWindow reads a window value: auto, off, or a duration with an
// optional day suffix ("7d", "72h"). ok is false for an empty value.
func ParseWindow(value string) (mode string, duration time.Duration, ok bool, err error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "":
		return "", 0, false, nil
	case WindowAuto, WindowOff:
		return value, 0, true, nil
	}
	if strings.HasSuffix(value, "d") {
		days, convErr := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if convErr != nil || days <= 0 {
			return "", 0, false, fmt.Errorf("cooldown window %q: want auto, off, or a duration such as 7d or 72h", value)
		}
		return WindowDuration, time.Duration(days) * 24 * time.Hour, true, nil
	}
	parsed, parseErr := time.ParseDuration(value)
	if parseErr != nil || parsed <= 0 {
		return "", 0, false, fmt.Errorf("cooldown window %q: want auto, off, or a duration such as 7d or 72h", value)
	}
	return WindowDuration, parsed, true, nil
}

// OrgDefaults is the organization's dependency policy (ADR-048 §3,
// ADR-045 §6), stored in the organization settings JSON. A repository can
// be stricter than its organization, never looser (ADR-035).
type OrgDefaults struct {
	Window            string   `json:"dependency_cooldown_window,omitempty"`
	Enforcement       string   `json:"dependency_cooldown_enforcement,omitempty"`
	InstallConfig     string   `json:"dependency_install_config,omitempty"`
	PrivateNamespaces []string `json:"dependency_private_namespaces,omitempty"`
	// TrustedDeclaredScopes lists the ecosystems whose declared dev and
	// test scopes count as not shipped (ADR-045 §6).
	TrustedDeclaredScopes []string `json:"trusted_declared_scopes,omitempty"`
}

// ParseOrgDefaults reads the dependency keys out of an organization's
// settings document; anything else in it is ignored.
func ParseOrgDefaults(raw []byte) OrgDefaults {
	var out OrgDefaults
	if len(raw) == 0 {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	out.Window = strings.ToLower(strings.TrimSpace(out.Window))
	out.Enforcement = strings.ToLower(strings.TrimSpace(out.Enforcement))
	out.InstallConfig = strings.ToLower(strings.TrimSpace(out.InstallConfig))
	return out
}

// enforcement and install-config ranks: a higher rank is stricter.
var enforcementRank = map[string]int{"": 0, "inherit": 0, "advisory": 1, "blocking": 2}
var installConfigRank = map[string]int{"": 0, "off": 0, "warn": 1, "require": 2}

// StricterWindow picks the stricter of two windows: "off" is the loosest,
// "auto" sits below any duration, and between durations the longer wins.
// An empty value defers to the other.
func StricterWindow(a, b string) string {
	modeA, durA, okA, errA := ParseWindow(a)
	modeB, durB, okB, errB := ParseWindow(b)
	if !okA || errA != nil {
		return b
	}
	if !okB || errB != nil {
		return a
	}
	rank := func(mode string) int {
		switch mode {
		case WindowOff:
			return 0
		case WindowAuto:
			return 1
		default:
			return 2
		}
	}
	switch {
	case rank(modeA) > rank(modeB):
		return a
	case rank(modeB) > rank(modeA):
		return b
	case modeA == WindowDuration && durA >= durB:
		return a
	case modeA == WindowDuration:
		return b
	default:
		return a
	}
}

// StricterEnforcement picks the stricter of inherit, advisory, blocking.
func StricterEnforcement(a, b string) string {
	if enforcementRank[strings.ToLower(strings.TrimSpace(b))] > enforcementRank[strings.ToLower(strings.TrimSpace(a))] {
		return b
	}
	return a
}

// StricterInstallConfig picks the stricter of off, warn, require.
func StricterInstallConfig(a, b string) string {
	if installConfigRank[strings.ToLower(strings.TrimSpace(b))] > installConfigRank[strings.ToLower(strings.TrimSpace(a))] {
		return b
	}
	return a
}

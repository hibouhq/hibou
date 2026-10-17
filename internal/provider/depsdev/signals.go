package depsdev

import (
	"encoding/json"
	"strings"
	"time"
)

// Finding types GOSSIP documents (docs.deps.dev, 2026-10). REMEDIATION is
// listed there but undocumented and is left in the raw document only.
const (
	FindingNotFound   = "NOT_FOUND"
	FindingMalicious  = "MALICIOUS"
	FindingDeprecated = "DEPRECATED"
	FindingCooldown   = "COOLDOWN"
	FindingLowUsage   = "LOW_USAGE"
	FindingVulnerable = "VULNERABLE"
)

// Signals is what Hibou keeps per package version (ADR-048 §2). Risk
// levels are not mapped to Hibou severities: signals have their own
// vocabulary, and only vulnerabilities carry a severity.
type Signals struct {
	Key                VersionKey
	Purl               string
	PublishedAt        *time.Time
	CooldownEnd        *time.Time
	Deprecated         bool
	DeprecatedReason   string
	LowUsage           bool
	Alternatives       []string
	NotFound           bool
	Malicious          bool
	VulnerableCritical bool
	RecommendedVersion string
	Raw                json.RawMessage
}

// InCooldown reports whether the version is still inside its cooldown at
// the given instant. A past end means the version has matured; no end
// means deps.dev gave none, which is "not evaluated", not "mature".
func (s Signals) InCooldown(now time.Time) bool {
	return s.CooldownEnd != nil && s.CooldownEnd.After(now)
}

// Normalize folds one findings response and one version lookup into
// Signals. Either input may be nil: the version lookup is what says
// "published at"; the findings say the rest. "Unpublished" comes only from
// deps.dev's own NOT_FOUND finding, never from an empty version lookup: a
// purl the lookup fails to parse would otherwise look like a takedown.
func Normalize(purl string, key VersionKey, findings *FindingsResult, info *VersionInfo, now time.Time) Signals {
	out := Signals{Key: key, Purl: purl}
	if findings != nil {
		out.Raw = findings.Raw
	}
	if info != nil {
		out.PublishedAt = parseTime(info.PublishedAt)
		if info.Cooldown != nil {
			out.CooldownEnd = parseTime(info.Cooldown.End)
		}
		if info.IsDeprecated {
			out.Deprecated = true
			out.DeprecatedReason = strings.TrimSpace(info.DeprecatedReason)
		}
	}
	if findings == nil {
		return out
	}
	f := findings.Findings
	var versionFindings []Finding
	if f.RequestedVersion != nil {
		versionFindings = append(versionFindings, f.RequestedVersion.Findings...)
		if end := parseTime(f.RequestedVersion.CooldownEnd); end != nil {
			out.CooldownEnd = end
		}
	}
	for _, finding := range append(versionFindings, f.PackageFindings...) {
		switch strings.ToUpper(strings.TrimSpace(finding.Type)) {
		case FindingNotFound:
			out.NotFound = true
		case FindingMalicious:
			out.Malicious = true
		case FindingVulnerable:
			out.VulnerableCritical = true
		case FindingDeprecated:
			out.Deprecated = true
			if finding.DeprecatedContext != nil && strings.TrimSpace(finding.DeprecatedContext.Reason) != "" {
				out.DeprecatedReason = strings.TrimSpace(finding.DeprecatedContext.Reason)
			}
		case FindingCooldown:
			if finding.CooldownContext != nil {
				if end := parseTime(finding.CooldownContext.End); end != nil {
					out.CooldownEnd = end
				}
			}
		case FindingLowUsage:
			out.LowUsage = true
			if finding.LowUsageContext != nil {
				out.Alternatives = appendUnique(out.Alternatives, alternativeNames(finding.LowUsageContext.AlternativePackages)...)
			}
		}
	}
	out.RecommendedVersion = recommendedVersion(f, key, now)
	return out
}

// recommendedVersion picks the first recommended version that is mature
// and carries no finding, then the first recommended one at all. The
// requested version itself is never recommended.
func recommendedVersion(f Findings, key VersionKey, now time.Time) string {
	first := ""
	for _, candidate := range f.RecommendedVersions {
		v := strings.TrimSpace(candidate.VersionKey.Version)
		if v == "" || v == key.Version {
			continue
		}
		if first == "" {
			first = v
		}
		end := parseTime(candidate.CooldownEnd)
		mature := end == nil || !end.After(now)
		if len(candidate.Findings) == 0 && mature {
			return v
		}
	}
	return first
}

// alternativeNames reads the undocumented alternatives shape leniently: a
// string, an object with a name, or an object with a packageKey.
func alternativeNames(items []json.RawMessage) []string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		var asString string
		if json.Unmarshal(item, &asString) == nil && strings.TrimSpace(asString) != "" {
			names = append(names, strings.TrimSpace(asString))
			continue
		}
		var asObject struct {
			Name       string      `json:"name"`
			PackageKey *PackageKey `json:"packageKey"`
			VersionKey *VersionKey `json:"versionKey"`
		}
		if json.Unmarshal(item, &asObject) != nil {
			continue
		}
		switch {
		case asObject.PackageKey != nil && asObject.PackageKey.Name != "":
			names = append(names, asObject.PackageKey.Name)
		case asObject.VersionKey != nil && asObject.VersionKey.Name != "":
			names = append(names, asObject.VersionKey.Name)
		case strings.TrimSpace(asObject.Name) != "":
			names = append(names, strings.TrimSpace(asObject.Name))
		}
	}
	return names
}

func appendUnique(dst []string, values ...string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		seen[v] = struct{}{}
	}
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		dst = append(dst, v)
	}
	return dst
}

func parseTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, value)
	}
	if err != nil {
		return nil
	}
	parsed = parsed.UTC()
	return &parsed
}

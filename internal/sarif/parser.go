package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const maxDocumentSize = 50 << 20

var cwePattern = regexp.MustCompile(`(?i)\bCWE-\d+\b`)

func Parse(r io.Reader) (*Document, error) {
	if r == nil {
		return nil, errors.New("reader is required")
	}

	var doc Document
	decoder := json.NewDecoder(io.LimitReader(r, maxDocumentSize))
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

// advisoryRuleIDPattern matches rule IDs that are dependency-advisory
// identifiers (CVE and the OSV/distro advisory namespaces) rather than
// static-analysis rules. Scanners that also do dependency scanning (Trivy,
// Grype, …) reuse the advisory ID as the SARIF rule ID, which is what makes
// these recognizable regardless of tool.
var advisoryRuleIDPattern = regexp.MustCompile(`^(?i)(` +
	`CVE-\d{4}-\d+` +
	`|GHSA(-[23456789cfghjmpqrvwx]{4}){3}` +
	`|(RUSTSEC|PYSEC|OSV|MAL|GO|GSD|DSA|DLA|ELSA|ALSA|ALBA|USN)-\d{2,6}[\w.:-]*` +
	`|CGA(-[23456789cfghjmpqrvwx]{4}){3}` +
	`)$`)

// IsAdvisoryFinding reports whether a SARIF result is a dependency advisory
// rather than a static-analysis finding: its rule ID sits in an advisory
// namespace, or the scanner tagged the rule as a vulnerability. Dependency
// advisories are matched server-side from the SBOM with full component
// context, so ingesting them as SAST would double-count every one.
func IsAdvisoryFinding(ruleID string, rule *RuleDescriptor) bool {
	if advisoryRuleIDPattern.MatchString(strings.TrimSpace(ruleID)) {
		return true
	}
	if rule == nil {
		return false
	}
	for _, tag := range rule.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), "vulnerability") {
			return true
		}
	}
	return false
}

// IsSecretFinding reports whether a SARIF result is a leaked-secret
// detection rather than a static-analysis finding. Trivy tags every rule with
// its result type ("vulnerability", "misconfiguration", "secret", "license");
// secrets are reported by the dedicated secret scanner, so ingesting Trivy's
// copies as SAST would duplicate each one. Only the exact tag counts: a SAST
// rule tagged "secrets" or "hardcoded-secret" is still a code finding.
func IsSecretFinding(rule *RuleDescriptor) bool {
	if rule == nil {
		return false
	}
	for _, tag := range rule.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), "secret") {
			return true
		}
	}
	return false
}

func ExtractFindings(doc *Document, repoID string) ([]Finding, error) {
	if doc == nil {
		return nil, errors.New("document is required")
	}

	findings := make([]Finding, 0)
	for _, run := range doc.Runs {
		// Lowercased so the same scanner keys identically wherever the name
		// appears (SARIF driver "Trivy", server-side provider "trivy").
		toolName := strings.ToLower(strings.TrimSpace(run.Tool.Driver.Name))
		for _, result := range run.Results {
			rule := resolveRule(run.Tool.Driver.Rules, result)
			filePath, startLine, endLine := resultLocation(result)
			ruleID := strings.TrimSpace(result.RuleID)
			if ruleID == "" {
				ruleID = strings.TrimSpace(rule.ID)
			}
			fingerprint := producerFingerprint(result)
			if fingerprint == "" {
				fingerprint = sha256Hex(repoID + "/" + toolName + "/" + ruleID + "/" + filePath + "/" + strconv.Itoa(int(startLine)))
			}

			finding := Finding{
				Tool:         toolName,
				RuleID:       ruleID,
				Severity:     mapSeverity(result.Level),
				FilePath:     filePath,
				StartLine:    startLine,
				EndLine:      endLine,
				Message:      strings.TrimSpace(result.Message.Text),
				Fingerprint:  fingerprint,
				LocationHash: sha256Hex(toolName + "/" + ruleID + "/" + filePath + "/" + strconv.Itoa(int(startLine))),
				Rule:         ruleDescriptor(ruleID, rule),
			}
			applySuppression(&finding, result.Suppressions)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// ruleDescriptor normalizes a SARIF reportingDescriptor into the per-rule
// catalog record. Returns nil when there is no rule id to key on.
func ruleDescriptor(ruleID string, rule ReportingDescriptor) *RuleDescriptor {
	if ruleID == "" {
		return nil
	}

	var props reportingDescriptorProperties
	if len(rule.Properties) > 0 {
		_ = json.Unmarshal(rule.Properties, &props)
	}

	desc := &RuleDescriptor{
		RuleID:           ruleID,
		Name:             strings.TrimSpace(rule.Name),
		HelpURI:          strings.TrimSpace(rule.HelpURI),
		SecuritySeverity: strings.TrimSpace(props.SecuritySeverity),
		Precision:        strings.TrimSpace(props.Precision),
		CWEs:             extractCWEs(props.Tags),
		Tags:             props.Tags,
		Properties:       rule.Properties,
	}
	if rule.ShortDescription != nil {
		desc.ShortDescription = strings.TrimSpace(rule.ShortDescription.Text)
	}
	if rule.FullDescription != nil {
		desc.FullDescription = strings.TrimSpace(rule.FullDescription.Text)
	}
	if rule.Help != nil {
		desc.HelpMarkdown = strings.TrimSpace(rule.Help.Markdown)
	}
	if rule.DefaultConfiguration != nil {
		desc.DefaultLevel = strings.TrimSpace(rule.DefaultConfiguration.Level)
	}
	return desc
}

// applySuppression marks a finding suppressed when the result carries at
// least one non-rejected suppression (SARIF §3.27.23: an empty array means
// the result is active; a rejected suppression does not suppress). checkov
// downgrades suppressed results to level=warning, so classification keys on
// this field, never on level.
func applySuppression(finding *Finding, suppressions []Suppression) {
	for _, suppression := range suppressions {
		if strings.EqualFold(suppression.Status, "rejected") {
			continue
		}
		finding.Suppressed = true
		finding.SuppressionKind = suppression.Kind
		finding.SuppressionJustification = strings.TrimSpace(suppression.Justification)
		return
	}
}

func resolveRule(rules []ReportingDescriptor, result Result) ReportingDescriptor {
	if result.RuleIndex != nil {
		idx := *result.RuleIndex
		if idx >= 0 && idx < len(rules) {
			return rules[idx]
		}
	}

	if result.RuleID == "" {
		return ReportingDescriptor{}
	}

	for _, rule := range rules {
		if strings.EqualFold(rule.ID, result.RuleID) {
			return rule
		}
	}

	return ReportingDescriptor{}
}

func resultLocation(result Result) (string, int32, int32) {
	if len(result.Locations) == 0 {
		return "", 0, 0
	}

	location := result.Locations[0].PhysicalLocation
	return strings.TrimSpace(location.ArtifactLocation.URI), location.Region.StartLine, location.Region.EndLine
}

func mapSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	case "none":
		return "info"
	default:
		return "info"
	}
}

func extractCWEs(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}

	seen := map[string]struct{}{}
	cwes := make([]string, 0)
	for _, tag := range tags {
		for _, match := range cwePattern.FindAllString(tag, -1) {
			normalized := strings.ToUpper(match)
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			cwes = append(cwes, normalized)
		}
	}
	return cwes
}

func producerFingerprint(result Result) string {
	if fingerprint := firstFingerprintValue(result.Fingerprints); fingerprint != "" {
		return fingerprint
	}

	return firstFingerprintValue(result.PartialFingerprints)
}

func firstFingerprintValue(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}

	return ""
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

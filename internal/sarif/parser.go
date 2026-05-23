package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
		return nil, fmt.Errorf("reader is required")
	}

	var doc Document
	decoder := json.NewDecoder(io.LimitReader(r, maxDocumentSize))
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

func ExtractFindings(doc *Document, repoID string) ([]Finding, error) {
	if doc == nil {
		return nil, fmt.Errorf("document is required")
	}

	findings := make([]Finding, 0)
	for _, run := range doc.Runs {
		toolName := strings.TrimSpace(run.Tool.Driver.Name)
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
				Metadata: map[string]any{
					"cwes":      extractCWEs(rule.Properties.Tags),
					"rule_name": strings.TrimSpace(rule.Name),
					"help_uri":  strings.TrimSpace(rule.HelpURI),
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
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

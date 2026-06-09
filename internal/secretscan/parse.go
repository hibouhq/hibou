package secretscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type trufflehogRow struct {
	DetectorName string `json:"DetectorName"`
	DetectorType string `json:"DetectorType"`
	Raw          string `json:"Raw"`
	Line         int32  `json:"Line"`
	StartLine    int32  `json:"StartLine"`
	EndLine      int32  `json:"EndLine"`
	Verified     bool   `json:"Verified"`
	SourceMeta   struct {
		Data struct {
			Git struct {
				File      string `json:"file"`
				Commit    string `json:"commit"`
				Email     string `json:"email"`
				Line      int32  `json:"line"`
				StartLine int32  `json:"start_line"`
				EndLine   int32  `json:"end_line"`
			} `json:"git"`
			Filesystem struct {
				File      string `json:"file"`
				Line      int32  `json:"line"`
				StartLine int32  `json:"start_line"`
				EndLine   int32  `json:"end_line"`
			} `json:"filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	File string         `json:"file"`
	Meta map[string]any `json:"-"`
}

func HashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func ComputeFingerprint(filePath string, startLine int32, secretHash string) string {
	filePath = strings.TrimSpace(filePath)
	if startLine > 0 {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", filePath, startLine)))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%s", filePath, strings.TrimSpace(secretHash))))
	return hex.EncodeToString(sum[:])
}

func NormalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	default:
		return "high"
	}
}

func ParseGitleaksReport(content []byte) ([]SecretFinding, error) {
	type gitleaksRow struct {
		RuleID      string         `json:"RuleID"`
		Description string         `json:"Description"`
		File        string         `json:"File"`
		StartLine   int32          `json:"StartLine"`
		EndLine     int32          `json:"EndLine"`
		Commit      string         `json:"Commit"`
		Author      string         `json:"Author"`
		Email       string         `json:"Email"`
		Match       string         `json:"Match"`
		Secret      string         `json:"Secret"`
		Tags        []string       `json:"Tags"`
		Entropy     float64        `json:"Entropy"`
		Metadata    map[string]any `json:"-"`
	}

	var rows []map[string]any
	if err := json.Unmarshal(content, &rows); err != nil {
		return nil, fmt.Errorf("decode gitleaks report: %w", err)
	}

	findings := make([]SecretFinding, 0, len(rows))
	for _, raw := range rows {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("marshal gitleaks finding: %w", err)
		}
		var row gitleaksRow
		if err := json.Unmarshal(encoded, &row); err != nil {
			return nil, fmt.Errorf("decode gitleaks finding: %w", err)
		}
		match := strings.TrimSpace(row.Match)
		if match == "" {
			match = strings.TrimSpace(row.Secret)
		}
		if match == "" {
			continue
		}
		secretType := strings.TrimSpace(row.RuleID)
		if len(row.Tags) > 0 && strings.TrimSpace(row.Tags[0]) != "" {
			secretType = strings.TrimSpace(row.Tags[0])
		}
		severity := severityFromTags(row.Tags)
		secretHash := HashSecret(match)
		finding := SecretFinding{
			Tool:        "gitleaks",
			RuleID:      strings.TrimSpace(row.RuleID),
			Description: strings.TrimSpace(row.Description),
			Severity:    severity,
			FilePath:    strings.TrimSpace(row.File),
			StartLine:   row.StartLine,
			EndLine:     row.EndLine,
			SecretType:  secretType,
			SecretHash:  secretHash,
			CommitSHA:   strings.TrimSpace(row.Commit),
			AuthorEmail: strings.TrimSpace(row.Email),
			Verified:    false,
			Metadata:    raw,
		}
		finding.Fingerprint = ComputeFingerprint(finding.FilePath, finding.StartLine, finding.SecretHash)
		findings = append(findings, finding)
	}
	if len(findings) == 0 {
		return nil, nil
	}

	return findings, nil
}

func ParseTruffleHogReport(content []byte) ([]SecretFinding, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		return parseTruffleHogJSONArray(trimmed)
	}
	return parseTruffleHogJSONL(trimmed)
}

func parseTruffleHogJSONArray(content []byte) ([]SecretFinding, error) {
	var rows []map[string]any
	if err := json.Unmarshal(content, &rows); err != nil {
		return nil, fmt.Errorf("decode trufflehog report: %w", err)
	}
	return collectTruffleHogFindings(rows)
}

func parseTruffleHogJSONL(content []byte) ([]SecretFinding, error) {
	rows := make([]map[string]any, 0)
	for _, line := range bytes.Split(content, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			return nil, fmt.Errorf("decode trufflehog jsonl row: %w", err)
		}
		rows = append(rows, raw)
	}
	return collectTruffleHogFindings(rows)
}

func collectTruffleHogFindings(rows []map[string]any) ([]SecretFinding, error) {
	findings := make([]SecretFinding, 0, len(rows))
	for _, raw := range rows {
		finding, ok, err := decodeTruffleHogRow(raw)
		if err != nil {
			return nil, err
		}
		if ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func decodeTruffleHogRow(raw map[string]any) (SecretFinding, bool, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return SecretFinding{}, false, fmt.Errorf("marshal trufflehog finding: %w", err)
	}
	var row trufflehogRow
	if err := json.Unmarshal(encoded, &row); err != nil {
		return SecretFinding{}, false, fmt.Errorf("decode trufflehog finding: %w", err)
	}
	match := strings.TrimSpace(row.Raw)
	if match == "" {
		return SecretFinding{}, false, nil
	}
	ruleID := trufflehogRuleID(row)
	startLine := trufflehogStartLine(row)
	secretHash := HashSecret(match)
	finding := SecretFinding{
		Tool:        "trufflehog",
		RuleID:      ruleID,
		Description: ruleID,
		Severity:    mapVerifiedSeverity(row.Verified),
		FilePath:    trufflehogFilePath(row),
		StartLine:   startLine,
		EndLine:     trufflehogEndLine(row, startLine),
		SecretType:  ruleID,
		SecretHash:  secretHash,
		CommitSHA:   strings.TrimSpace(row.SourceMeta.Data.Git.Commit),
		AuthorEmail: strings.TrimSpace(row.SourceMeta.Data.Git.Email),
		Verified:    row.Verified,
		Metadata:    raw,
	}
	finding.Fingerprint = ComputeFingerprint(finding.FilePath, finding.StartLine, finding.SecretHash)
	return finding, true, nil
}

func trufflehogFilePath(row trufflehogRow) string {
	for _, candidate := range []string{row.File, row.SourceMeta.Data.Git.File, row.SourceMeta.Data.Filesystem.File} {
		if value := strings.TrimSpace(candidate); value != "" {
			return value
		}
	}
	return ""
}

func trufflehogRuleID(row trufflehogRow) string {
	ruleID := strings.TrimSpace(row.DetectorName)
	if ruleID == "" {
		ruleID = strings.TrimSpace(row.DetectorType)
	}
	return ruleID
}

func trufflehogStartLine(row trufflehogRow) int32 {
	for _, candidate := range []int32{row.StartLine, row.Line, row.SourceMeta.Data.Git.StartLine, row.SourceMeta.Data.Git.Line, row.SourceMeta.Data.Filesystem.StartLine, row.SourceMeta.Data.Filesystem.Line} {
		if candidate != 0 {
			return candidate
		}
	}
	return 0
}

func trufflehogEndLine(row trufflehogRow, startLine int32) int32 {
	for _, candidate := range []int32{row.EndLine, row.SourceMeta.Data.Git.EndLine, row.SourceMeta.Data.Filesystem.EndLine} {
		if candidate != 0 {
			return candidate
		}
	}
	return startLine
}

func severityFromTags(tags []string) string {
	for _, tag := range tags {
		normalized := NormalizeSeverity(tag)
		if normalized != "high" || strings.EqualFold(strings.TrimSpace(tag), "high") {
			return normalized
		}
	}
	return "high"
}

func mapVerifiedSeverity(verified bool) string {
	if verified {
		return "critical"
	}
	return "high"
}

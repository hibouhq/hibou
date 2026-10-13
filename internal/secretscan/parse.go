package secretscan

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
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

// HashSecret is the dedup digest stored as secret_hash: HMAC-SHA256 under an
// instance pepper, so a leaked hash cannot be brute-forced offline against
// candidate secrets (an unsalted SHA-256 of a low-entropy password or a
// known-format token can). Every provider must hash the same bare bytes for
// cross-tool dedup to work.
func HashSecret(value string) string {
	mac := hmac.New(sha256.New, hashPepper())
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// secretHashPepperLabel domain-separates the pepper from every other use of
// the instance secret it is derived from.
const secretHashPepperLabel = "hibou/secret-hash/v1"

// defaultPepperSource keys development instances that set no secret.
const defaultPepperSource = "hibou-development-secret-hash-pepper"

var (
	pepperMu     sync.RWMutex
	pepperValue  []byte
	pepperLoaded sync.Once
)

// SetHashPepperSource derives the secret-hash pepper from an instance secret
// (the session secret: present and shared by every replica in production).
// Call it at startup; without a call the pepper is derived from
// HIBOU_SESSION_SECRET. Changing the source changes every new secret_hash,
// and with it the fingerprint of findings that have no line number.
func SetHashPepperSource(secret string) {
	pepperLoaded.Do(func() {})
	pepperMu.Lock()
	pepperValue = derivePepper(secret)
	pepperMu.Unlock()
}

func hashPepper() []byte {
	pepperLoaded.Do(func() {
		pepperMu.Lock()
		if pepperValue == nil {
			pepperValue = derivePepper(os.Getenv("HIBOU_SESSION_SECRET"))
		}
		pepperMu.Unlock()
	})
	pepperMu.RLock()
	defer pepperMu.RUnlock()
	return pepperValue
}

func derivePepper(secret string) []byte {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		secret = defaultPepperSource
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(secretHashPepperLabel))
	return mac.Sum(nil)
}

// safeMetadataKeys is the closed set of scanner report fields persisted into
// a secret finding's metadata (ADR-010). Anything else — raw values (Raw,
// RawV2, Match, Secret), structured secret material (SecretParts,
// StructuredData, ExtraData), surrounding content (Line, Fragment,
// MatchContext), commit messages, and every field a future scanner version
// adds — is dropped: an allowlist cannot be outrun by a new field name.
var safeMetadataKeys = map[string]bool{
	// gitleaks / betterleaks
	"RuleID":           true,
	"Description":      true,
	"File":             true,
	"SymlinkFile":      true,
	"StartLine":        true,
	"EndLine":          true,
	"StartColumn":      true,
	"EndColumn":        true,
	"Commit":           true,
	"Date":             true,
	"Entropy":          true,
	"Tags":             true,
	"Fingerprint":      true,
	"Link":             true,
	"ValidationStatus": true,
	// trufflehog
	"DetectorName":   true,
	"DetectorType":   true,
	"DecoderName":    true,
	"Verified":       true,
	"Redacted":       true,
	"SourceMetadata": true,
	"SourceID":       true,
	"SourceType":     true,
	"SourceName":     true,
}

// SafeMetadata keeps only the allowlisted report fields of a scanner row.
func SafeMetadata(raw map[string]any) map[string]any {
	safe := make(map[string]any, len(raw))
	for key, value := range raw {
		if safeMetadataKeys[key] {
			safe[key] = value
		}
	}
	return safe
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
		// Hash the bare secret, not the surrounding match text: every provider
		// must hash the same bytes or cross-tool fingerprint dedup can't work.
		match := strings.TrimSpace(row.Secret)
		if match == "" {
			match = strings.TrimSpace(row.Match)
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
		// ADR-010: never store the raw secret. The row carries it twice —
		// Match (the matched text) and Secret (the extracted value) — and
		// Metadata is persisted verbatim into the finding.
		delete(raw, "Match")
		delete(raw, "Secret")
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
			Metadata:    SafeMetadata(raw),
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
		// trufflehog interleaves human-readable log lines on stdout; only
		// object lines are findings.
		if len(line) == 0 || line[0] != '{' {
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
	// ADR-010: never store the raw secret. The row carries it in Raw/RawV2 and
	// Metadata is persisted verbatim into the finding.
	delete(raw, "Raw")
	delete(raw, "RawV2")
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
		Metadata:    SafeMetadata(raw),
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

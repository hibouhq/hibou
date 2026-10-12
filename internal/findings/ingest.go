package findings

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/sanitize"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type GenericFinding struct {
	Tool        string
	ToolVersion string
	// TraceFiles are the files a taint finding's flow passes through, kept in
	// metadata.trace_files for the resolution rule of ADR-036 §6.
	TraceFiles  []string
	RuleID      string
	Severity    string
	FilePath    string
	StartLine   int32
	EndLine     int32
	Message     string
	Fingerprint string
	Rule        *ScanRuleInput
	// ResultCWEs are this occurrence's own classification (SARIF
	// result.taxa); stored per finding, never on the rule (ADR-037 §2.2).
	ResultCWEs []int
	// Suppressed: the scanner excluded this result in-source (SARIF
	// suppressions[], ADR-023). Ingested with status 'suppressed' —
	// visible, never open, never gating.
	Suppressed               bool
	SuppressionKind          string
	SuppressionJustification string
}

// ScanRuleInput is the per-rule descriptor extracted from scanner output. It is
// upserted into the scan_rules catalog once per (tool, rule_id); the resulting
// vulnerability references it by FK instead of embedding the rule text.
type ScanRuleInput struct {
	Name             string
	ShortDescription string
	FullDescription  string
	HelpURI          string
	HelpMarkdown     string
	DefaultLevel     string
	SecuritySeverity string
	Precision        string
	// CWEs classify every result of the rule; they replace the rule's stored
	// set, since the scanner's current definition is authoritative.
	CWEs       []int
	Tags       []string
	Properties json.RawMessage
}

type Ingester struct {
	store IngestStore
	log   zerolog.Logger
}

type IngestStore interface {
	CreateVulnerability(ctx context.Context, params dbgen.CreateVulnerabilityParams) (*store.Vulnerability, error)
	UpsertScanRule(ctx context.Context, params dbgen.UpsertScanRuleParams) (uuid.UUID, error)
	SyncScanRuleCWEs(ctx context.Context, byRule map[uuid.UUID][]int) error
	ReplaceSnapshotSARIFResultCWEs(ctx context.Context, snapshotID uuid.UUID, fingerprints []string, cwes map[string][]int) error
}

func NewIngester(store IngestStore, log zerolog.Logger) *Ingester {
	return &Ingester{store: store, log: log.With().Str("component", "findings.ingester").Logger()}
}

func (i *Ingester) Ingest(ctx context.Context, snapshotID uuid.UUID, findings []GenericFinding) (int, error) {
	if i == nil || i.store == nil {
		return 0, errors.New("store is required")
	}

	created := 0
	// A SARIF log repeats the same rule for every occurrence: upsert each rule
	// once per ingest (an ON CONFLICT DO UPDATE per result rewrote the row,
	// one dead tuple per occurrence) and write all rule CWEs in one batch.
	ruleRefs := map[string]uuid.NullUUID{}
	ruleCWEs := map[uuid.UUID][]int{}
	fingerprints := make([]string, 0, len(findings))
	resultCWEs := map[string][]int{}
	for _, finding := range findings {
		severity, err := severityFromString(finding.Severity)
		if err != nil {
			return created, err
		}

		ruleKey := strings.TrimSpace(finding.Tool) + "\x00" + strings.TrimSpace(finding.RuleID)
		ruleRef, seen := ruleRefs[ruleKey]
		if !seen {
			ruleRef, err = i.upsertRule(ctx, finding)
			if err != nil {
				return created, err
			}
			ruleRefs[ruleKey] = ruleRef
			if ruleRef.Valid {
				ruleCWEs[ruleRef.UUID] = finding.Rule.CWEs
			}
		}

		startLine := finding.StartLine
		endLine := finding.EndLine
		locationHash := hashSegments(finding.Tool, finding.RuleID, finding.FilePath, strconv.Itoa(int(startLine)))
		fingerprint := strings.TrimSpace(finding.Fingerprint)
		if fingerprint == "" {
			fingerprint = locationHash
		}
		fingerprints = append(fingerprints, fingerprint)
		if len(finding.ResultCWEs) > 0 {
			resultCWEs[fingerprint] = append(resultCWEs[fingerprint], finding.ResultCWEs...)
		}
		status := "detected"
		metadata := json.RawMessage(`{}`)
		fields := map[string]any{}
		if finding.Suppressed {
			// A scanner-suppressed result never opens a finding (ADR-023);
			// kind + justification ride the metadata for the detail view.
			status = "suppressed"
			fields["suppression"] = map[string]string{
				"kind":          finding.SuppressionKind,
				"justification": finding.SuppressionJustification,
			}
		}
		if len(finding.TraceFiles) > 0 {
			fields["trace_files"] = finding.TraceFiles
		}
		if len(fields) > 0 {
			encoded, marshalErr := json.Marshal(fields)
			if marshalErr != nil {
				return created, marshalErr
			}
			metadata = encoded
		}
		_, err = i.store.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
			Type:                   "sast",
			SnapshotID:             snapshotID,
			Title:                  truncateMessage(sanitize.Text(finding.Message), 200),
			Description:            sanitize.Text(finding.Message),
			PrimaryIdentifierKind:  "rule",
			PrimaryIdentifierValue: strings.TrimSpace(finding.RuleID),
			OriginalSeverity:       severity,
			Severity:               severity,
			Status:                 status,
			ScannerName:            strings.TrimSpace(finding.Tool),
			ScannerVersion:         strings.TrimSpace(finding.ToolVersion),
			FilePath:               nullString(strings.TrimSpace(finding.FilePath)),
			StartLine:              sql.NullInt32{Int32: startLine, Valid: startLine > 0},
			EndLine:                sql.NullInt32{Int32: endLine, Valid: endLine > 0},
			LocationHash:           nullString(locationHash),
			Fingerprint:            fingerprint,
			Metadata:               metadata,
			RuleRefID:              ruleRef,
		})
		if err != nil {
			if isDuplicateFinding(err) {
				continue
			}
			return created, err
		}
		created++
	}

	if err := i.store.SyncScanRuleCWEs(ctx, ruleCWEs); err != nil {
		return created, fmt.Errorf("store rule cwes: %w", err)
	}
	if err := i.store.ReplaceSnapshotSARIFResultCWEs(ctx, snapshotID, fingerprints, resultCWEs); err != nil {
		return created, fmt.Errorf("store result cwes: %w", err)
	}
	return created, nil
}

// upsertRule stores the finding's rule descriptor once in the scan_rules catalog
// and returns the FK to link from the vulnerability. Returns a null ref when the
// finding carries no rule descriptor.
func (i *Ingester) upsertRule(ctx context.Context, finding GenericFinding) (uuid.NullUUID, error) {
	if finding.Rule == nil {
		return uuid.NullUUID{}, nil
	}

	properties := finding.Rule.Properties
	if len(properties) == 0 {
		properties = json.RawMessage(`{}`)
	}

	id, err := i.store.UpsertScanRule(ctx, dbgen.UpsertScanRuleParams{
		Tool:             strings.TrimSpace(finding.Tool),
		RuleID:           strings.TrimSpace(finding.RuleID),
		Name:             finding.Rule.Name,
		ShortDescription: finding.Rule.ShortDescription,
		FullDescription:  finding.Rule.FullDescription,
		HelpUri:          finding.Rule.HelpURI,
		HelpMarkdown:     finding.Rule.HelpMarkdown,
		DefaultLevel:     finding.Rule.DefaultLevel,
		SecuritySeverity: finding.Rule.SecuritySeverity,
		RulePrecision:    finding.Rule.Precision,
		Tags:             nonNilSlice(finding.Rule.Tags),
		Properties:       properties,
	})
	if err != nil {
		return uuid.NullUUID{}, fmt.Errorf("upsert scan rule %s/%s: %w", finding.Tool, finding.RuleID, err)
	}
	return uuid.NullUUID{UUID: id, Valid: true}, nil
}

// nonNilSlice guarantees a non-nil slice so pq.Array writes '{}' (the column is
// NOT NULL) rather than NULL.
func nonNilSlice(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func severityFromString(value string) (store.SeverityLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return store.SeverityLevelCritical, nil
	case "high":
		return store.SeverityLevelHigh, nil
	case "medium":
		return store.SeverityLevelMedium, nil
	case "low":
		return store.SeverityLevelLow, nil
	case "info", "informational":
		return store.SeverityLevelInfo, nil
	default:
		return "", errors.New("finding severity must be one of critical, high, medium, low, info")
	}
}

func isDuplicateFinding(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

func hashSegments(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "/")))
	return hex.EncodeToString(sum[:])
}

func truncateMessage(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func nullString(value string) sql.NullString {
	if strings.TrimSpace(value) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

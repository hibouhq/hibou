package secretscan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

const (
	secretStatusOpen          = "open"
	secretStatusRevoked       = "revoked"
	secretStatusFalsePositive = "false_positive"
	secretStatusRotating      = "rotating"
)

type IngestStore interface {
	CreateVulnerability(ctx context.Context, params dbgen.CreateVulnerabilityParams) (*store.Vulnerability, error)
}

type Ingester struct {
	store IngestStore
	log   zerolog.Logger
}

func NewIngester(store IngestStore, log zerolog.Logger) *Ingester {
	return &Ingester{store: store, log: log.With().Str("component", "secretscan.ingester").Logger()}
}

func (i *Ingester) Ingest(ctx context.Context, snapshotID uuid.UUID, findings []SecretFinding, discoveryContext string) (int, error) {
	if i == nil || i.store == nil {
		return 0, errors.New("store is required")
	}
	discoveryContext = strings.TrimSpace(discoveryContext)
	if discoveryContext == "" {
		discoveryContext = "full_scan"
	}

	created := 0
	for _, finding := range findings {
		tool := strings.TrimSpace(finding.Tool)
		if tool == "" {
			return created, errors.New("secret finding tool is required")
		}
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID == "" {
			return created, errors.New("secret finding rule_id is required")
		}
		secretHash := strings.TrimSpace(finding.SecretHash)

		severity, err := severityFromString(finding.Severity)
		if err != nil {
			return created, err
		}

		metadata, err := json.Marshal(finding.Metadata)
		if err != nil {
			return created, fmt.Errorf("marshal secret finding metadata: %w", err)
		}

		fingerprint := strings.TrimSpace(finding.Fingerprint)
		if fingerprint == "" {
			fingerprint = ComputeFingerprint(finding.FilePath, finding.StartLine, secretHash)
		}
		sourceMetadata, err := json.Marshal(map[string]any{
			"rule_id":      ruleID,
			"severity":     finding.Severity,
			"description":  finding.Description,
			"secret_type":  finding.SecretType,
			"secret_hash":  secretHash,
			"verified":     finding.Verified,
			"commit_sha":   finding.CommitSHA,
			"author_email": finding.AuthorEmail,
		})
		if err != nil {
			return created, fmt.Errorf("marshal secret finding source metadata: %w", err)
		}

		var startLine *int32
		var endLine *int32
		if finding.StartLine > 0 {
			startLine = &finding.StartLine
		}
		if finding.EndLine > 0 {
			endLine = &finding.EndLine
		}

		metadata = mergeSecretMetadata(metadata, discoveryContext, sourceMetadata)
		_, err = i.store.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
			Type:              "secret",
			SnapshotID:        snapshotID,
			Title:             truncateSecretTitle(strings.TrimSpace(finding.Description), strings.TrimSpace(finding.SecretType), 200),
			Description:       strings.TrimSpace(finding.Description),
			PrimaryIdentifier: json.RawMessage(fmt.Sprintf(`{"type":"rule","value":%q}`, ruleID)),
			Identifiers:       json.RawMessage(`[]`),
			OriginalSeverity:  severity,
			Severity:          severity,
			Status:            secretStatusToVulnerabilityStatus(secretStatusOpen),
			ScannerName:       tool,
			FilePath:          nullString(strings.TrimSpace(finding.FilePath)),
			StartLine:         nullInt32(startLine),
			EndLine:           nullInt32(endLine),
			Fingerprint:       fingerprint,
			SecretType:        nullString(strings.TrimSpace(finding.SecretType)),
			SecretHash:        nullString(secretHash),
			CommitSha:         nullString(strings.TrimSpace(finding.CommitSHA)),
			AuthorEmail:       nullString(strings.TrimSpace(finding.AuthorEmail)),
			Verified:          sql.NullBool{Bool: finding.Verified, Valid: true},
			Metadata:          metadata,
		})
		if err != nil {
			if isDuplicateSecretFinding(err) {
				// TODO(adr-012): merge multi-tool secret sources into vulnerability metadata on duplicate fingerprints.
				continue
			}
			return created, err
		}
		created++
	}

	return created, nil
}

func severityFromString(value string) (store.SeverityLevel, error) {
	switch NormalizeSeverity(value) {
	case "critical":
		return store.SeverityLevelCritical, nil
	case "high":
		return store.SeverityLevelHigh, nil
	case "medium":
		return store.SeverityLevelMedium, nil
	case "low":
		return store.SeverityLevelLow, nil
	case "info":
		return store.SeverityLevelInfo, nil
	default:
		return "", errors.New("secret severity must be one of critical, high, medium, low, info")
	}
}

func isDuplicateSecretFinding(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}

func secretStatusToVulnerabilityStatus(status string) string {
	switch status {
	case secretStatusFalsePositive:
		return "dismissed"
	case secretStatusRevoked, secretStatusRotating:
		return "resolved"
	default:
		return "detected"
	}
}

func truncateSecretTitle(description, secretType string, limit int) string {
	if description != "" {
		return truncateText(description, limit)
	}
	return truncateText(secretType, limit)
}

func truncateText(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func mergeSecretMetadata(base json.RawMessage, discoveryContext string, sourceMetadata json.RawMessage) json.RawMessage {
	payload := map[string]any{}
	if len(base) > 0 {
		_ = json.Unmarshal(base, &payload)
	}
	payload["discovery_context"] = discoveryContext
	if len(sourceMetadata) > 0 {
		var source any
		if err := json.Unmarshal(sourceMetadata, &source); err == nil {
			payload["source"] = source
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return base
	}
	return encoded
}

func nullString(value string) sql.NullString {
	if strings.TrimSpace(value) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func nullInt32(value *int32) sql.NullInt32 {
	if value == nil {
		return sql.NullInt32{}
	}
	return sql.NullInt32{Int32: *value, Valid: true}
}

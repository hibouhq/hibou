package secretscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
)

type IngestStore interface {
	CreateSecretFinding(ctx context.Context, snapshotID uuid.UUID, tool, ruleID string, severity store.SeverityLevel, status store.SecretStatus, discoveryContext, filePath string, startLine, endLine *int32, secretType, secretHash, commitSHA, authorEmail string, verified bool, metadata json.RawMessage, fingerprint string) (*store.SecretFinding, error)
	GetSecretFindingByFingerprint(ctx context.Context, snapshotID uuid.UUID, fingerprint string) (*store.SecretFinding, error)
	UpsertSecretFindingSource(ctx context.Context, findingID uuid.UUID, tool, ruleID string, metadata json.RawMessage) error
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
		existing, err := i.store.GetSecretFindingByFingerprint(ctx, snapshotID, fingerprint)
		if err != nil {
			return created, err
		}
		if existing != nil {
			if err := i.store.UpsertSecretFindingSource(ctx, existing.ID, tool, ruleID, sourceMetadata); err != nil {
				return created, err
			}
			continue
		}

		var startLine *int32
		var endLine *int32
		if finding.StartLine > 0 {
			startLine = &finding.StartLine
		}
		if finding.EndLine > 0 {
			endLine = &finding.EndLine
		}

		createdFinding, err := i.store.CreateSecretFinding(
			ctx,
			snapshotID,
			tool,
			ruleID,
			severity,
			store.SecretStatusOpen,
			discoveryContext,
			strings.TrimSpace(finding.FilePath),
			startLine,
			endLine,
			strings.TrimSpace(finding.SecretType),
			secretHash,
			strings.TrimSpace(finding.CommitSHA),
			strings.TrimSpace(finding.AuthorEmail),
			finding.Verified,
			metadata,
			fingerprint,
		)
		if err != nil {
			if isDuplicateSecretFinding(err) {
				existing, lookupErr := i.store.GetSecretFindingByFingerprint(ctx, snapshotID, fingerprint)
				if lookupErr != nil {
					return created, lookupErr
				}
				if existing != nil {
					if upsertErr := i.store.UpsertSecretFindingSource(ctx, existing.ID, tool, ruleID, sourceMetadata); upsertErr != nil {
						return created, upsertErr
					}
				}
				continue
			}
			return created, err
		}
		if err := i.store.UpsertSecretFindingSource(ctx, createdFinding.ID, tool, ruleID, sourceMetadata); err != nil {
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

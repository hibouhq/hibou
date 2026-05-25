package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
)

type GenericFinding struct {
	Tool        string
	RuleID      string
	Severity    string
	FilePath    string
	StartLine   int32
	EndLine     int32
	Message     string
	Fingerprint string
	Metadata    map[string]any
}

type Ingester struct {
	store IngestStore
	log   zerolog.Logger
}

type IngestStore interface {
	CreateFinding(ctx context.Context, snapshotID uuid.UUID, tool, ruleID string, severity store.SeverityLevel, status, filePath string, startLine, endLine *int32, locationHash, message string, fingerprint *string, metadata json.RawMessage) (*store.Finding, error)
}

func NewIngester(store IngestStore, log zerolog.Logger) *Ingester {
	return &Ingester{store: store, log: log.With().Str("component", "findings.ingester").Logger()}
}

func (i *Ingester) Ingest(ctx context.Context, snapshotID uuid.UUID, findings []GenericFinding) (int, error) {
	if i == nil || i.store == nil {
		return 0, errors.New("store is required")
	}

	created := 0
	for _, finding := range findings {
		severity, err := severityFromString(finding.Severity)
		if err != nil {
			return created, err
		}

		metadata, err := json.Marshal(finding.Metadata)
		if err != nil {
			return created, fmt.Errorf("marshal finding metadata: %w", err)
		}

		startLine := finding.StartLine
		endLine := finding.EndLine
		locationHash := hashSegments(finding.Tool, finding.RuleID, finding.FilePath, strconv.Itoa(int(startLine)))
		fingerprint := strings.TrimSpace(finding.Fingerprint)
		if fingerprint == "" {
			fingerprint = locationHash
		}

		_, err = i.store.CreateFinding(
			ctx,
			snapshotID,
			strings.TrimSpace(finding.Tool),
			strings.TrimSpace(finding.RuleID),
			severity,
			"open",
			strings.TrimSpace(finding.FilePath),
			&startLine,
			&endLine,
			locationHash,
			strings.TrimSpace(finding.Message),
			&fingerprint,
			metadata,
		)
		if err != nil {
			if isDuplicateFinding(err) {
				continue
			}
			return created, err
		}
		created++
	}

	return created, nil
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

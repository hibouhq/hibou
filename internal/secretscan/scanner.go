package secretscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/audit"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type eventPublisher interface {
	Publish(ctx context.Context, evt events.Event)
}

type ScanStore interface {
	IngestStore
	CreateAuditLog(ctx context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error)
}

type Scanner struct {
	providers []SecretScanProvider
	store     ScanStore
	bus       eventPublisher
	log       zerolog.Logger
	tempDir   string
}

func NewScanner(providers []SecretScanProvider, store ScanStore, bus eventPublisher, log zerolog.Logger, tempDir string) *Scanner {
	return &Scanner{
		providers: append([]SecretScanProvider(nil), providers...),
		store:     store,
		bus:       bus,
		log:       log.With().Str("component", "secretscan.scanner").Logger(),
		tempDir:   strings.TrimSpace(tempDir),
	}
}

func (s *Scanner) RunFullScan(ctx context.Context, repoID, snapshotID uuid.UUID, cloneURL, branch, authToken string) (int, error) {
	findings, err := s.collectRepoFindings(ctx, ScanRepoOptions{
		CloneURL:  cloneURL,
		Branch:    branch,
		AuthToken: authToken,
		TempDir:   s.tempDir,
	})
	if err != nil {
		s.publishFailure(ctx, repoID, snapshotID, err)
		return 0, err
	}

	ingester := NewIngester(s.store, s.log)
	created, err := ingester.Ingest(ctx, snapshotID, findings, "full_scan")
	if err != nil {
		s.publishFailure(ctx, repoID, snapshotID, err)
		return created, err
	}

	s.publishScanEvents(ctx, repoID, snapshotID, findings, created, "full")
	s.logDiscoveryAudit(ctx, snapshotID, created, "full_scan")
	return created, nil
}

func (s *Scanner) RunIncrementalScan(ctx context.Context, repoID, snapshotID uuid.UUID, cloneURL, branch, fromCommit, toCommit, authToken string) (int, error) {
	findings, err := s.collectDiffFindings(ctx, ScanDiffOptions{
		CloneURL:   cloneURL,
		Branch:     branch,
		FromCommit: fromCommit,
		ToCommit:   toCommit,
		AuthToken:  authToken,
		TempDir:    s.tempDir,
	})
	if err != nil {
		s.publishFailure(ctx, repoID, snapshotID, err)
		return 0, err
	}

	ingester := NewIngester(s.store, s.log)
	created, err := ingester.Ingest(ctx, snapshotID, findings, "incremental_scan")
	if err != nil {
		s.publishFailure(ctx, repoID, snapshotID, err)
		return created, err
	}

	s.publishScanEvents(ctx, repoID, snapshotID, findings, created, "incremental")
	s.logDiscoveryAudit(ctx, snapshotID, created, "incremental_scan")
	return created, nil
}

func (s *Scanner) CheckPush(ctx context.Context, cloneURL, branch, fromCommit, toCommit, authToken string) ([]SecretFinding, error) {
	if s == nil {
		return nil, errors.New("secret scanner is not configured")
	}
	return s.collectDiffFindings(ctx, ScanDiffOptions{
		CloneURL:   cloneURL,
		Branch:     branch,
		FromCommit: fromCommit,
		ToCommit:   toCommit,
		AuthToken:  authToken,
		TempDir:    s.tempDir,
	})
}

func (s *Scanner) collectRepoFindings(ctx context.Context, opts ScanRepoOptions) ([]SecretFinding, error) {
	if s == nil {
		return nil, errors.New("secret scanner is not configured")
	}
	findings := make([]SecretFinding, 0)
	seen := make(map[string]struct{})
	for _, provider := range s.providers {
		if !provider.Capabilities().FullScan {
			continue
		}
		providerFindings, err := provider.ScanRepo(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("provider %s full scan: %w", provider.Name(), err)
		}
		appendUniqueSecretFindings(&findings, seen, providerFindings)
	}
	return findings, nil
}

func (s *Scanner) collectDiffFindings(ctx context.Context, opts ScanDiffOptions) ([]SecretFinding, error) {
	if s == nil {
		return nil, errors.New("secret scanner is not configured")
	}
	findings := make([]SecretFinding, 0)
	seen := make(map[string]struct{})
	for _, provider := range s.providers {
		var providerFindings []SecretFinding
		var err error
		if provider.Capabilities().IncrementalScan {
			providerFindings, err = provider.ScanDiff(ctx, opts)
		} else if provider.Capabilities().FullScan {
			providerFindings, err = provider.ScanRepo(ctx, ScanRepoOptions{
				CloneURL:  opts.CloneURL,
				Branch:    opts.Branch,
				AuthToken: opts.AuthToken,
				TempDir:   opts.TempDir,
			})
		} else {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("provider %s incremental scan: %w", provider.Name(), err)
		}
		appendUniqueSecretFindings(&findings, seen, providerFindings)
	}
	return findings, nil
}

func (s *Scanner) publishScanEvents(ctx context.Context, repoID, snapshotID uuid.UUID, findings []SecretFinding, created int, mode string) {
	if s == nil || s.bus == nil {
		return
	}
	for _, finding := range findings {
		s.bus.Publish(ctx, events.Event{
			Type: events.SecretDiscovered,
			Payload: map[string]any{
				"repo_id":     repoID,
				"snapshot_id": snapshotID,
				"tool":        finding.Tool,
				"rule_id":     finding.RuleID,
				"severity":    finding.Severity,
				"file_path":   finding.FilePath,
				"fingerprint": finding.Fingerprint,
				"secret_type": finding.SecretType,
			},
		})
	}
	s.bus.Publish(ctx, events.Event{
		Type: events.SecretScanCompleted,
		Payload: map[string]any{
			"repo_id":     repoID,
			"snapshot_id": snapshotID,
			"mode":        mode,
			"created":     created,
			"total":       len(findings),
		},
	})
}

func (s *Scanner) publishFailure(ctx context.Context, repoID, snapshotID uuid.UUID, err error) {
	if s == nil || s.bus == nil || err == nil {
		return
	}
	s.bus.Publish(ctx, events.Event{
		Type: events.SecretScanFailed,
		Payload: map[string]any{
			"repo_id":     repoID,
			"snapshot_id": snapshotID,
			"error":       err.Error(),
		},
	})
}

func (s *Scanner) logDiscoveryAudit(ctx context.Context, snapshotID uuid.UUID, created int, mode string) {
	if s == nil || s.store == nil {
		return
	}

	auditCtx, err := json.Marshal(map[string]any{
		"count":       created,
		"mode":        mode,
		"snapshot_id": snapshotID.String(),
	})
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", snapshotID.String()).Msg("marshal secret discovery audit context")
		return
	}

	if _, err := s.store.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorType:    audit.ActorSystem,
		ActorDisplay: "secret-scanner",
		Action:       audit.ActionSecretDiscovered,
		ResourceType: "snapshot",
		ResourceID:   snapshotID.String(),
		Context:      auditCtx,
	}); err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", snapshotID.String()).Str("mode", mode).Msg("create secret discovery audit log")
	}
}

func appendUniqueSecretFindings(dst *[]SecretFinding, seen map[string]struct{}, findings []SecretFinding) {
	for _, finding := range findings {
		fingerprint := strings.TrimSpace(finding.Fingerprint)
		if fingerprint == "" {
			fingerprint = ComputeFingerprint(finding.FilePath, finding.StartLine, finding.SecretHash)
			finding.Fingerprint = fingerprint
		}
		key := fingerprint + "/" + strings.TrimSpace(finding.Tool)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		*dst = append(*dst, finding)
	}
}

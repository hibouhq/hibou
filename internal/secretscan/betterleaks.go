package secretscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
)

// BetterleaksProvider execs the betterleaks binary (a gitleaks descendant with
// an expression-based validation engine). Like trufflehog it can verify
// findings against the live service; unlike it, validation can also prove a
// credential dead ("invalid"/"revoked"), which demotes instead of escalates.
type BetterleaksProvider struct {
	log zerolog.Logger
	bin string
}

func NewBetterleaksProvider(log zerolog.Logger) (*BetterleaksProvider, error) {
	bin, err := exec.LookPath("betterleaks")
	if err != nil {
		return nil, fmt.Errorf("betterleaks binary not found: %w", err)
	}
	return &BetterleaksProvider{log: log.With().Str("component", "secretscan.betterleaks").Logger(), bin: bin}, nil
}

func (p *BetterleaksProvider) Name() string {
	return "betterleaks"
}

func (p *BetterleaksProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{FullScan: true, IncrementalScan: true, Verification: true}
}

func (p *BetterleaksProvider) ScanRepo(ctx context.Context, opts ScanRepoOptions) ([]SecretFinding, error) {
	repoDir, cleanup, err := cloneRepositoryOptions(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken, 0, opts.AllBranches)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return p.runBetterleaks(ctx, repoDir, "git", repoDir)
}

func (p *BetterleaksProvider) ScanDiff(ctx context.Context, opts ScanDiffOptions) ([]SecretFinding, error) {
	repoDir, cleanup, err := cloneRepository(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken, incrementalCloneDepth)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if err := ensureCommitPresent(ctx, repoDir, opts.FromCommit); err != nil {
		return nil, err
	}
	return p.runBetterleaks(ctx, repoDir, "git", repoDir, "--log-opts="+opts.FromCommit+".."+opts.ToCommit)
}

// ScanFilesystem scans a plain directory with no git history — the push-check
// path, where the commits exist only as a materialized patch.
func (p *BetterleaksProvider) ScanFilesystem(ctx context.Context, dir string) ([]SecretFinding, error) {
	reportDir, err := os.MkdirTemp(filepath.Dir(filepath.Clean(dir)), "hibou-betterleaks-report-*")
	if err != nil {
		return nil, fmt.Errorf("create betterleaks report dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(reportDir) }()

	return p.runBetterleaks(ctx, reportDir, "dir", dir)
}

// runBetterleaks executes betterleaks with the shared report flags, writing the
// report into reportDir. --exit-code=0 matters for the same reason as gitleaks:
// the default exit 1 on findings would record every detection as a failed scan.
func (p *BetterleaksProvider) runBetterleaks(ctx context.Context, reportDir string, args ...string) ([]SecretFinding, error) {
	reportPath := filepath.Join(reportDir, "betterleaks-report.json")
	args = append(args, "--report-format=json", "--report-path="+reportPath, "--exit-code=0")
	// #nosec G204 -- binary path comes from LookPath during provider construction.
	cmd := exec.CommandContext(ctx, p.bin, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("run betterleaks %s: %w: %s", args[0], err, string(output))
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read betterleaks report: %w", err)
	}
	return ParseBetterleaksReport(content)
}

type betterleaksRow struct {
	RuleID           string `json:"RuleID"`
	Description      string `json:"Description"`
	StartLine        int32  `json:"StartLine"`
	EndLine          int32  `json:"EndLine"`
	Match            string `json:"Match"`
	Secret           string `json:"Secret"`
	File             string `json:"File"`
	Commit           string `json:"Commit"`
	Email            string `json:"Email"`
	Tags             []string
	ValidationStatus string `json:"ValidationStatus"`
}

// ParseBetterleaksReport parses betterleaks' JSON report (array of findings,
// gitleaks-shaped plus a validation verdict). Raw secret material — Secret,
// Match, MatchContext, capture groups, fragments and required-set components —
// is hashed and discarded per ADR-010.
func ParseBetterleaksReport(content []byte) ([]SecretFinding, error) {
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return nil, nil
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
		return nil, fmt.Errorf("decode betterleaks report: %w", err)
	}

	findings := make([]SecretFinding, 0, len(rows))
	for _, raw := range rows {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("marshal betterleaks finding: %w", err)
		}
		var row betterleaksRow
		if err := json.Unmarshal(encoded, &row); err != nil {
			return nil, fmt.Errorf("decode betterleaks finding: %w", err)
		}

		// Hash the bare secret first — cross-tool dedup needs every provider
		// hashing the same bytes.
		secret := strings.TrimSpace(row.Secret)
		if secret == "" {
			secret = strings.TrimSpace(row.Match)
		}
		if secret == "" {
			continue
		}

		// ADR-010: metadata is persisted verbatim; nothing carrying the raw
		// value may survive. RequiredSets nests Secret/Match per component,
		// Fragment carries raw scanned content.
		for _, key := range []string{"Match", "Secret", "MatchContext", "CaptureGroups", "Fragment", "RequiredSets", "Line"} {
			delete(raw, key)
		}

		verified := row.ValidationStatus == "valid"
		severity := severityFromTags(row.Tags)
		switch row.ValidationStatus {
		case "valid":
			// Confirmed live against the real service.
			severity = "critical"
		case "invalid", "revoked":
			// Confirmed dead: still a hygiene finding, no longer an incident.
			severity = "low"
		}

		secretType := strings.TrimSpace(row.RuleID)
		if len(row.Tags) > 0 && strings.TrimSpace(row.Tags[0]) != "" {
			secretType = strings.TrimSpace(row.Tags[0])
		}

		secretHash := HashSecret(secret)
		finding := SecretFinding{
			Tool:        "betterleaks",
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
			Verified:    verified,
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

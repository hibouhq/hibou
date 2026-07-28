package secretscan

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/rs/zerolog"
)

// TruffleHogProvider execs the trufflehog binary. Its distinguishing feature
// over gitleaks is live verification: a Verified finding means the credential
// authenticated against the real service, not just matched a pattern.
type TruffleHogProvider struct {
	log zerolog.Logger
	bin string
}

func NewTruffleHogProvider(log zerolog.Logger) (*TruffleHogProvider, error) {
	bin, err := exec.LookPath("trufflehog")
	if err != nil {
		return nil, fmt.Errorf("trufflehog binary not found: %w", err)
	}
	return &TruffleHogProvider{log: log.With().Str("component", "secretscan.trufflehog").Logger(), bin: bin}, nil
}

func (p *TruffleHogProvider) Name() string {
	return "trufflehog"
}

func (p *TruffleHogProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{FullScan: true, IncrementalScan: true, Verification: true}
}

func (p *TruffleHogProvider) ScanRepo(ctx context.Context, opts ScanRepoOptions) ([]SecretFinding, error) {
	repoDir, cleanup, err := cloneRepositoryOptions(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken, 0, opts.AllBranches)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return p.runGitScan(ctx, repoDir, "")
}

func (p *TruffleHogProvider) ScanDiff(ctx context.Context, opts ScanDiffOptions) ([]SecretFinding, error) {
	repoDir, cleanup, err := cloneRepository(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken, incrementalCloneDepth)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// The range base must exist locally or --since-commit walks nothing.
	if err := ensureCommitPresent(ctx, repoDir, opts.FromCommit); err != nil {
		return nil, err
	}
	return p.runGitScan(ctx, repoDir, opts.FromCommit)
}

func (p *TruffleHogProvider) runGitScan(ctx context.Context, repoDir, sinceCommit string) ([]SecretFinding, error) {
	args := []string{"git", "file://" + repoDir}
	if sinceCommit != "" {
		args = append(args, "--since-commit", sinceCommit)
	}
	return p.run(ctx, args)
}

// ScanFilesystem scans a plain directory with no git history — the push-check
// path, where the commits exist only as a materialized patch.
func (p *TruffleHogProvider) ScanFilesystem(ctx context.Context, dir string) ([]SecretFinding, error) {
	return p.run(ctx, []string{"filesystem", dir})
}

func (p *TruffleHogProvider) run(ctx context.Context, args []string) ([]SecretFinding, error) {
	args = append(args, "--json", "--no-update")
	//nolint:gosec // G204: binary path comes from LookPath during provider construction.
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run trufflehog %s: %w: %s", args[0], err, stderr.String())
	}

	return ParseTruffleHogReport(stdout.Bytes())
}

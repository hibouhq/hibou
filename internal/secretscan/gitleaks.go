package secretscan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/rs/zerolog"
)

type GitleaksProvider struct {
	log zerolog.Logger
	bin string
}

func NewGitleaksProvider(log zerolog.Logger) (*GitleaksProvider, error) {
	bin, err := exec.LookPath("gitleaks")
	if err != nil {
		return nil, fmt.Errorf("gitleaks binary not found: %w", err)
	}
	return &GitleaksProvider{log: log.With().Str("component", "secretscan.gitleaks").Logger(), bin: bin}, nil
}

func (p *GitleaksProvider) Name() string {
	return "gitleaks"
}

func (p *GitleaksProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{FullScan: true, IncrementalScan: true, Verification: false}
}

func (p *GitleaksProvider) ScanRepo(ctx context.Context, opts ScanRepoOptions) ([]SecretFinding, error) {
	repoDir, cleanup, err := cloneRepository(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	reportPath := filepath.Join(repoDir, "gitleaks-report.json")
	cmd := exec.CommandContext(ctx, p.bin,
		"detect",
		"--source="+repoDir,
		"--report-format=json",
		"--report-path="+reportPath,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("run gitleaks detect: %w: %s", err, string(output))
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read gitleaks report: %w", err)
	}

	return ParseGitleaksReport(content)
}

func (p *GitleaksProvider) ScanDiff(ctx context.Context, opts ScanDiffOptions) ([]SecretFinding, error) {
	repoDir, cleanup, err := cloneRepository(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	reportPath := filepath.Join(repoDir, "gitleaks-report.json")
	cmd := exec.CommandContext(ctx, p.bin,
		"detect",
		"--source="+repoDir,
		"--log-opts="+opts.FromCommit+".."+opts.ToCommit,
		"--report-format=json",
		"--report-path="+reportPath,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("run gitleaks diff detect: %w: %s", err, string(output))
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read gitleaks report: %w", err)
	}

	return ParseGitleaksReport(content)
}

func cloneRepository(ctx context.Context, parentDir, cloneURL, branch, authToken string) (string, func(), error) {
	tempRoot := parentDir
	if tempRoot == "" {
		tempRoot = os.TempDir()
	}
	repoDir, err := os.MkdirTemp(tempRoot, "hibou-secret-scan-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp repo dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(repoDir) }

	cloneTarget := cloneURL
	if authToken != "" {
		cloneTarget = injectTokenIntoCloneURL(cloneURL, authToken)
	}

	args := []string{"clone", cloneTarget, repoDir}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("clone repository: %w: %s", err, string(output))
	}

	return repoDir, cleanup, nil
}

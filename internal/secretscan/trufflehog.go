package secretscan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/rs/zerolog"
)

// TruffleHogProvider execs the trufflehog binary. Its distinguishing feature
// over gitleaks is live verification: a Verified finding means the credential
// authenticated against the real service, not just matched a pattern.
//
// CURRENTLY UNREACHABLE: buildSecretScanProviders refuses to construct this
// provider, and the binary is not in the runtime image. TruffleHog re-clones the
// checkout we hand it through a file:// URI, and git's local transport needs
// /bin/sh for that — a shell we deliberately do not ship in a security
// scanner's image. betterleaks covers live verification without one.
// Kept compiling (and tested) so re-enabling is a small change once the provider
// can scan in place or take the remote URL directly.
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
	// FromCommit becomes --since-commit: only full SHAs get there.
	if err := validateCommitRange(opts.FromCommit, opts.ToCommit); err != nil {
		return nil, err
	}
	repoDir, cleanup, err := cloneRepository(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken, incrementalCloneDepth)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// The range base must exist locally or --since-commit walks nothing.
	if err := ensureCommitPresent(ctx, repoDir, opts.FromCommit, opts.CloneURL, opts.AuthToken); err != nil {
		return nil, err
	}
	return p.runGitScan(ctx, repoDir, opts.FromCommit)
}

func (p *TruffleHogProvider) runGitScan(ctx context.Context, repoDir, sinceCommit string) ([]SecretFinding, error) {
	args := []string{"git", "file://" + repoDir}
	if sinceCommit != "" {
		args = append(args, "--since-commit", sinceCommit)
	}
	return p.run(ctx, scanHome(repoDir), args)
}

// ScanFilesystem scans a plain directory with no git history — the push-check
// path, where the commits exist only as a materialized patch.
func (p *TruffleHogProvider) ScanFilesystem(ctx context.Context, dir string) ([]SecretFinding, error) {
	home, err := os.MkdirTemp(filepath.Dir(filepath.Clean(dir)), "hibou-trufflehog-home-*")
	if err != nil {
		return nil, fmt.Errorf("create trufflehog home dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(home) }()
	return p.run(ctx, home, []string{"filesystem", dir})
}

// run executes trufflehog with the minimal scanner environment; home is a
// Hibou-created directory used as HOME (see scannerEnv).
func (p *TruffleHogProvider) run(ctx context.Context, home string, args []string) ([]SecretFinding, error) {
	args = append(args, "--json", "--no-update")
	// #nosec G204 -- binary path comes from LookPath during provider construction.
	cmd := exec.CommandContext(ctx, p.bin, args...)
	cmd.Env = scannerEnv(home)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run trufflehog %s: %w: %s", args[0], err, scrubSecrets(stderr.String()))
	}

	return ParseTruffleHogReport(stdout.Bytes())
}

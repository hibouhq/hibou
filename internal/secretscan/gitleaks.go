package secretscan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

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
	repoDir, cleanup, err := cloneRepositoryOptions(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken, 0, opts.AllBranches)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return p.runGitleaks(ctx, repoDir, "detect", "--source="+repoDir)
}

func (p *GitleaksProvider) ScanDiff(ctx context.Context, opts ScanDiffOptions) ([]SecretFinding, error) {
	repoDir, cleanup, err := cloneRepository(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken, incrementalCloneDepth)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// The pushed range's base must exist locally or gitleaks' log walk fails;
	// a burst-coalesced job can reach past the shallow depth.
	if err := ensureCommitPresent(ctx, repoDir, opts.FromCommit); err != nil {
		return nil, err
	}

	return p.runGitleaks(ctx, repoDir, "detect", "--source="+repoDir, "--log-opts="+opts.FromCommit+".."+opts.ToCommit)
}

// ScanFilesystem scans a plain directory with no git history — the push-check
// path, where the commits exist only as a materialized patch.
func (p *GitleaksProvider) ScanFilesystem(ctx context.Context, dir string) ([]SecretFinding, error) {
	// The report goes next to the scanned dir, not os.TempDir(): on the
	// read-only-rootfs pods only the scratch mount (which dir lives under) is
	// guaranteed writable.
	reportDir, err := os.MkdirTemp(filepath.Dir(filepath.Clean(dir)), "hibou-gitleaks-report-*")
	if err != nil {
		return nil, fmt.Errorf("create gitleaks report dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(reportDir) }()

	return p.runGitleaks(ctx, reportDir, "dir", dir)
}

// runGitleaks executes gitleaks with the shared report flags, writing the
// report into reportDir. --exit-code=0 matters: gitleaks exits 1 when it finds
// leaks, which would otherwise record every successful detection as a failed
// scan.
func (p *GitleaksProvider) runGitleaks(ctx context.Context, reportDir string, args ...string) ([]SecretFinding, error) {
	reportPath := filepath.Join(reportDir, "gitleaks-report.json")
	args = append(args, "--report-format=json", "--report-path="+reportPath, "--exit-code=0")
	//nolint:gosec // G204: binary path comes from LookPath during provider construction.
	cmd := exec.CommandContext(ctx, p.bin, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("run gitleaks %s: %w: %s", args[0], err, string(output))
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read gitleaks report: %w", err)
	}

	return ParseGitleaksReport(content)
}

// incrementalCloneDepth bounds an incremental scan's clone. Deep enough that a
// coalesced push burst rarely reaches past it; ensureCommitPresent deepens on
// the rare miss.
const incrementalCloneDepth = 1000

// depth 0 clones full history; a positive depth clones shallow and
// single-branch (a range scan only reads one branch).
func cloneRepository(ctx context.Context, parentDir, cloneURL, branch, authToken string, depth int) (string, func(), error) {
	return cloneRepositoryOptions(ctx, parentDir, cloneURL, branch, authToken, depth, false)
}

// allBranches fetches every ref so gitleaks' and trufflehog's --all history
// walks cover branch-only commits — the enrolment baseline needs the whole
// repo, not just the default branch's history.
func cloneRepositoryOptions(ctx context.Context, parentDir, cloneURL, branch, authToken string, depth int, allBranches bool) (string, func(), error) {
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
	if !allBranches {
		args = append(args, "--single-branch")
	}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	if depth > 0 {
		args = append(args, "--depth", strconv.Itoa(depth))
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("clone repository: %w: %s", err, string(output))
	}

	return repoDir, cleanup, nil
}

// ensureCommitPresent deepens a shallow clone until the commit exists locally.
func ensureCommitPresent(ctx context.Context, repoDir, sha string) error {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return nil
	}
	if exec.CommandContext(ctx, "git", "-C", repoDir, "cat-file", "-e", sha+"^{commit}").Run() == nil {
		return nil
	}

	shallow, err := exec.CommandContext(ctx, "git", "-C", repoDir, "rev-parse", "--is-shallow-repository").Output()
	if err != nil {
		return fmt.Errorf("inspect clone for %s: %w", sha, err)
	}
	if strings.TrimSpace(string(shallow)) != "true" {
		return fmt.Errorf("commit %s not found in repository", sha)
	}

	if output, err := exec.CommandContext(ctx, "git", "-C", repoDir, "fetch", "--unshallow", "origin").CombinedOutput(); err != nil {
		return fmt.Errorf("deepen clone for %s: %w: %s", sha, err, string(output))
	}
	if exec.CommandContext(ctx, "git", "-C", repoDir, "cat-file", "-e", sha+"^{commit}").Run() != nil {
		return fmt.Errorf("commit %s not found after unshallow", sha)
	}
	return nil
}

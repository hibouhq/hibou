package secretscan

import (
	"context"
	"errors"
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

	return p.runGitleaks(ctx, scanHome(repoDir), repoDir, "detect", "--source="+repoDir)
}

func (p *GitleaksProvider) ScanDiff(ctx context.Context, opts ScanDiffOptions) ([]SecretFinding, error) {
	// The range is interpolated into --log-opts: only full SHAs get there.
	if err := validateCommitRange(opts.FromCommit, opts.ToCommit); err != nil {
		return nil, err
	}
	repoDir, cleanup, err := cloneRepository(ctx, opts.TempDir, opts.CloneURL, opts.Branch, opts.AuthToken, incrementalCloneDepth)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// The pushed range's base must exist locally or gitleaks' log walk fails;
	// a burst-coalesced job can reach past the shallow depth.
	if err := ensureCommitPresent(ctx, repoDir, opts.FromCommit, opts.CloneURL, opts.AuthToken); err != nil {
		return nil, err
	}

	return p.runGitleaks(ctx, scanHome(repoDir), repoDir, "detect", "--source="+repoDir, "--log-opts="+opts.FromCommit+".."+opts.ToCommit)
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

	return p.runGitleaks(ctx, reportDir, reportDir, "dir", dir)
}

// runGitleaks executes gitleaks with the shared report flags, writing the
// report into reportDir. --exit-code=0 matters: gitleaks exits 1 when it finds
// leaks, which would otherwise record every successful detection as a failed
// scan. home is a Hibou-created directory used as HOME (see scannerEnv).
func (p *GitleaksProvider) runGitleaks(ctx context.Context, home, reportDir string, args ...string) ([]SecretFinding, error) {
	reportPath := filepath.Join(reportDir, "gitleaks-report.json")
	args = append(args, "--report-format=json", "--report-path="+reportPath, "--exit-code=0")
	// #nosec G204 -- binary path comes from LookPath during provider construction.
	cmd := exec.CommandContext(ctx, p.bin, args...)
	cmd.Env = scannerEnv(home)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("run gitleaks %s: %w: %s", args[0], err, scrubSecrets(string(output)))
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
//
// The clone lands in <work>/repo next to a private <work>/home used as HOME
// for every subprocess, so no tool ever treats the attacker-controlled
// checkout as its home directory. The token travels as an env-scoped
// Authorization header (gitAuthEnv), never in argv or .git/config.
func cloneRepositoryOptions(ctx context.Context, parentDir, cloneURL, branch, authToken string, depth int, allBranches bool) (string, func(), error) {
	tempRoot := parentDir
	if tempRoot == "" {
		tempRoot = os.TempDir()
	}
	workDir, err := os.MkdirTemp(tempRoot, "hibou-secret-scan-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp repo dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(workDir) }
	home := filepath.Join(workDir, scanHomeDirName)
	if err := os.Mkdir(home, 0o700); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("create scanner home: %w", err)
	}
	repoDir := filepath.Join(workDir, "repo")

	cloneURL = stripURLCredentials(cloneURL)
	authEnv, err := gitAuthEnv(cloneURL, authToken)
	if err != nil {
		cleanup()
		return "", nil, err
	}

	args := []string{"clone"}
	if !allBranches {
		args = append(args, "--single-branch")
	}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	if depth > 0 {
		args = append(args, "--depth", strconv.Itoa(depth))
	}
	// "--" stops a hostile clone URL from being parsed as an option.
	args = append(args, "--", cloneURL, repoDir)
	if output, err := gitCommand(ctx, home, authEnv, args...).CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("clone repository: %w: %s", err, scrubSecrets(string(output), authToken))
	}

	return repoDir, cleanup, nil
}

// scanHomeDirName is the private HOME created next to every clone.
const scanHomeDirName = "home"

// scanHome returns the private HOME that cloneRepositoryOptions created for
// repoDir.
func scanHome(repoDir string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(repoDir)), scanHomeDirName)
}

// gitCommand builds a git invocation with the minimal scanner environment.
func gitCommand(ctx context.Context, home string, extraEnv []string, args ...string) *exec.Cmd {
	// #nosec G204 -- fixed binary; arguments are built by Hibou, with "--" before untrusted positionals.
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = scannerEnv(home, extraEnv...)
	return cmd
}

// ErrBaseCommitUnreachable marks an incremental scan whose diff base no
// longer exists (force-push rewrote it away) — full history no longer
// contains the anchor, so only a full-branch scan is correct.
var ErrBaseCommitUnreachable = errors.New("diff base commit unreachable")

// ensureCommitPresent deepens a shallow clone until the commit exists locally.
// cloneURL and authToken authenticate the deepening fetch the same way as the
// clone, since the remote URL in .git/config carries no credentials.
func ensureCommitPresent(ctx context.Context, repoDir, sha, cloneURL, authToken string) error {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return nil
	}
	if !validCommitSHA(sha) {
		return fmt.Errorf("invalid diff base commit %q", truncateText(sha, 80))
	}
	home := scanHome(repoDir)
	if gitCommand(ctx, home, nil, "-C", repoDir, "cat-file", "-e", sha+"^{commit}").Run() == nil {
		return nil
	}

	shallow, err := gitCommand(ctx, home, nil, "-C", repoDir, "rev-parse", "--is-shallow-repository").Output()
	if err != nil {
		return fmt.Errorf("inspect clone for %s: %w", sha, err)
	}
	if strings.TrimSpace(string(shallow)) != "true" {
		return fmt.Errorf("%w: commit %s not found in repository", ErrBaseCommitUnreachable, sha)
	}

	authEnv, err := gitAuthEnv(stripURLCredentials(cloneURL), authToken)
	if err != nil {
		return err
	}
	if output, err := gitCommand(ctx, home, authEnv, "-C", repoDir, "fetch", "--unshallow", "origin").CombinedOutput(); err != nil {
		return fmt.Errorf("deepen clone for %s: %w: %s", sha, err, scrubSecrets(string(output), authToken))
	}
	if gitCommand(ctx, home, nil, "-C", repoDir, "cat-file", "-e", sha+"^{commit}").Run() != nil {
		return fmt.Errorf("%w: commit %s not found after unshallow", ErrBaseCommitUnreachable, sha)
	}
	return nil
}

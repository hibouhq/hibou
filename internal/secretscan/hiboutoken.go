package secretscan

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/apitoken"
)

// HibouTokenProvider detects Hibou's own API tokens. The hibou_pat_ prefix and
// checksum were designed for exactly this (ADR-020): a leaked Hibou token in a
// scanned repo must be Hibou's easiest catch. The checksum makes detection
// exact — a match that validates IS a structurally real token, reported
// Verified with zero false positives; external scanners cannot know the
// checksum algorithm.
type HibouTokenProvider struct {
	log zerolog.Logger
}

var hibouTokenPattern = regexp.MustCompile(regexp.QuoteMeta(apitoken.Prefix) + `[0-9A-Za-z]{36}`)

// Filesystem-scan bounds: the provider runs on materialized patch files and on
// clones; skipping big/binary blobs keeps it O(source code).
const hibouTokenMaxFileSize = 4 << 20

func NewHibouTokenProvider(log zerolog.Logger) *HibouTokenProvider {
	return &HibouTokenProvider{log: log.With().Str("component", "secretscan.hiboutoken").Logger()}
}

func (p *HibouTokenProvider) Name() string { return "hibou-token" }

func (p *HibouTokenProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{Verification: true}
}

// ScanRepo and ScanDiff are intentionally unimplemented: repository scans
// already run gitleaks/betterleaks over a clone, and this provider's regex adds
// nothing there without git-history walking of its own. Its value is the
// synchronous push-check path, which uses ScanFilesystem.
func (p *HibouTokenProvider) ScanRepo(context.Context, ScanRepoOptions) ([]SecretFinding, error) {
	return nil, errors.New("hibou-token provider only scans filesystems")
}

func (p *HibouTokenProvider) ScanDiff(context.Context, ScanDiffOptions) ([]SecretFinding, error) {
	return nil, errors.New("hibou-token provider only scans filesystems")
}

func (p *HibouTokenProvider) ScanFilesystem(ctx context.Context, dir string) ([]SecretFinding, error) {
	findings := make([]SecretFinding, 0)

	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.IsDir() {
			return nil
		}
		if info, err := entry.Info(); err != nil || info.Size() > hibouTokenMaxFileSize {
			return nil //nolint:nilerr // unreadable or oversized files are skipped, not fatal
		}

		fileFindings, scanErr := p.scanFile(path)
		if scanErr != nil {
			p.log.Debug().Err(scanErr).Str("path", path).Msg("skip unreadable file")
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func (p *HibouTokenProvider) scanFile(path string) ([]SecretFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var findings []SecretFinding
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	lineNumber := int32(0)
	for scanner.Scan() {
		lineNumber++
		for _, match := range hibouTokenPattern.FindAllString(scanner.Text(), -1) {
			verified := apitoken.HasValidChecksum(match)
			secretHash := HashSecret(match)
			finding := SecretFinding{
				Tool:        p.Name(),
				RuleID:      "hibou-pat",
				Description: "Hibou API token",
				Severity:    "critical",
				FilePath:    path,
				StartLine:   lineNumber,
				EndLine:     lineNumber,
				SecretType:  "hibou_pat",
				SecretHash:  secretHash,
				Verified:    verified,
			}
			finding.Fingerprint = ComputeFingerprint(finding.FilePath, finding.StartLine, finding.SecretHash)
			findings = append(findings, finding)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

package secretscan

import "context"

// SecretScanProvider is the interface all secret scanning tools must implement.
type SecretScanProvider interface {
	Name() string
	ScanRepo(ctx context.Context, opts ScanRepoOptions) ([]SecretFinding, error)
	ScanDiff(ctx context.Context, opts ScanDiffOptions) ([]SecretFinding, error)
	Capabilities() ProviderCapabilities
}

type ScanRepoOptions struct {
	CloneURL  string
	Branch    string
	AuthToken string
	TempDir   string
}

type ScanDiffOptions struct {
	CloneURL   string
	Branch     string
	FromCommit string
	ToCommit   string
	AuthToken  string
	TempDir    string
}

type ProviderCapabilities struct {
	FullScan        bool
	IncrementalScan bool
	Verification    bool
}

type SecretFinding struct {
	Tool        string         `json:"tool"`
	RuleID      string         `json:"rule_id"`
	Description string         `json:"description"`
	Severity    string         `json:"severity"`
	FilePath    string         `json:"file_path"`
	StartLine   int32          `json:"start_line"`
	EndLine     int32          `json:"end_line"`
	SecretType  string         `json:"secret_type"`
	SecretHash  string         `json:"secret_hash"`
	CommitSHA   string         `json:"commit_sha"`
	AuthorEmail string         `json:"author_email"`
	Verified    bool           `json:"verified"`
	Fingerprint string         `json:"fingerprint"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

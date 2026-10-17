package secretscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/forge"
)

type GitHubProvider struct {
	client  *http.Client
	baseURL string
	log     zerolog.Logger
}

func NewGitHubProvider(client *http.Client, apiURL string, log zerolog.Logger) *GitHubProvider {
	if client == nil {
		client = forge.NewHTTPClient()
	}
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	return &GitHubProvider{
		client:  client,
		baseURL: strings.TrimRight(apiURL, "/"),
		log:     log.With().Str("component", "secretscan.github").Logger(),
	}
}

func (p *GitHubProvider) Name() string {
	return "github"
}

func (p *GitHubProvider) Capabilities() ProviderCapabilities {
	return ProviderCapabilities{FullScan: true, IncrementalScan: false, Verification: true}
}

func (p *GitHubProvider) ScanRepo(ctx context.Context, opts ScanRepoOptions) ([]SecretFinding, error) {
	owner, repo, err := parseGitHubCloneURL(opts.CloneURL)
	if err != nil {
		return nil, err
	}
	alerts, err := p.listAlerts(ctx, owner, repo, opts.AuthToken)
	if err != nil {
		return nil, err
	}

	findings := make([]SecretFinding, 0, len(alerts))
	for _, alert := range alerts {
		filePath, startLine, commitSHA, err := p.loadFirstLocation(ctx, alert.LocationsURL, opts.AuthToken)
		if err != nil {
			return nil, err
		}
		secretType := strings.TrimSpace(alert.SecretType)
		if secretType == "" {
			secretType = strings.TrimSpace(alert.SecretTypeDisplayName)
		}
		secretHash := HashSecret(strings.TrimSpace(alert.HTMLURL))
		finding := SecretFinding{
			Tool:        "github",
			RuleID:      strings.TrimSpace(alert.SecretType),
			Description: strings.TrimSpace(alert.SecretTypeDisplayName),
			Severity:    githubSeverity(alert),
			FilePath:    filePath,
			StartLine:   startLine,
			EndLine:     startLine,
			SecretType:  secretType,
			SecretHash:  secretHash,
			CommitSHA:   commitSHA,
			Verified:    strings.EqualFold(strings.TrimSpace(alert.Validity), "active") || strings.EqualFold(strings.TrimSpace(alert.Validity), "valid"),
			Metadata: map[string]any{
				"number":                      alert.Number,
				"state":                       alert.State,
				"resolution":                  alert.Resolution,
				"resolution_comment":          alert.ResolutionComment,
				"html_url":                    alert.HTMLURL,
				"created_at":                  alert.CreatedAt,
				"push_protection_bypassed_at": alert.PushProtectionBypassedAt,
				"push_protection_bypassed_by": alert.PushProtectionBypassedBy,
				"validity":                    alert.Validity,
			},
		}
		finding.Fingerprint = ComputeFingerprint(finding.FilePath, finding.StartLine, finding.SecretHash)
		findings = append(findings, finding)
	}

	return findings, nil
}

func (p *GitHubProvider) ScanDiff(ctx context.Context, opts ScanDiffOptions) ([]SecretFinding, error) {
	return nil, errors.New("github secret scanning provider does not support incremental commit-range scans")
}

type gitHubSecretAlert struct {
	Number                   int       `json:"number"`
	State                    string    `json:"state"`
	SecretType               string    `json:"secret_type"`
	SecretTypeDisplayName    string    `json:"secret_type_display_name"`
	Resolution               string    `json:"resolution"`
	ResolutionComment        string    `json:"resolution_comment"`
	Validity                 string    `json:"validity"`
	HTMLURL                  string    `json:"html_url"`
	LocationsURL             string    `json:"locations_url"`
	CreatedAt                time.Time `json:"created_at"`
	PushProtectionBypassedAt time.Time `json:"push_protection_bypassed_at"`
	PushProtectionBypassedBy any       `json:"push_protection_bypassed_by"`
}

type gitHubSecretLocation struct {
	Type    string `json:"type"`
	Details struct {
		Path      string `json:"path"`
		StartLine int32  `json:"start_line"`
		BlobSHA   string `json:"blob_sha"`
	} `json:"details"`
}

func (p *GitHubProvider) listAlerts(ctx context.Context, owner, repo, token string) ([]gitHubSecretAlert, error) {
	alerts := make([]gitHubSecretAlert, 0)
	for page := 1; ; page++ {
		endpoint := fmt.Sprintf("%s/repos/%s/%s/secret-scanning/alerts?per_page=100&page=%d", p.baseURL, owner, repo, page)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("build github alerts request: %w", err)
		}
		request.Header.Set("Accept", "application/vnd.github+json")
		if strings.TrimSpace(token) != "" {
			request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
		}

		response, err := p.client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("call github alerts API: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode >= http.StatusBadRequest {
			return nil, fmt.Errorf("github alerts API returned %s", response.Status)
		}

		var pageAlerts []gitHubSecretAlert
		if err := json.NewDecoder(forge.LimitResponse(response.Body)).Decode(&pageAlerts); err != nil {
			return nil, fmt.Errorf("decode github alerts response: %w", err)
		}
		alerts = append(alerts, pageAlerts...)
		if len(pageAlerts) < 100 {
			break
		}
	}

	return alerts, nil
}

func (p *GitHubProvider) loadFirstLocation(ctx context.Context, locationsURL, token string) (string, int32, string, error) {
	if strings.TrimSpace(locationsURL) == "" {
		return "", 0, "", nil
	}
	// locations_url comes from the API response: the bearer token is only
	// ever sent back to the configured API origin.
	if !sameOrigin(locationsURL, p.baseURL) {
		return "", 0, "", errors.New("github secret locations URL is not on the configured API host")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, locationsURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("build github secret locations request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	if strings.TrimSpace(token) != "" {
		request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}

	response, err := p.client.Do(request)
	if err != nil {
		return "", 0, "", fmt.Errorf("call github secret locations API: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		return "", 0, "", fmt.Errorf("github secret locations API returned %s", response.Status)
	}

	var locations []gitHubSecretLocation
	if err := json.NewDecoder(forge.LimitResponse(response.Body)).Decode(&locations); err != nil {
		return "", 0, "", fmt.Errorf("decode github secret locations response: %w", err)
	}
	if len(locations) == 0 {
		return "", 0, "", nil
	}

	return strings.TrimSpace(locations[0].Details.Path), locations[0].Details.StartLine, strings.TrimSpace(locations[0].Details.BlobSHA), nil
}

func parseGitHubCloneURL(cloneURL string) (string, string, error) {
	trimmed := strings.TrimSpace(cloneURL)
	if strings.HasPrefix(trimmed, "git@") {
		hostAndPath := strings.TrimPrefix(trimmed, "git@")
		separator := strings.Index(hostAndPath, ":")
		if separator <= 0 || separator == len(hostAndPath)-1 {
			return "", "", fmt.Errorf("invalid github clone URL %q", cloneURL)
		}
		repoPath := hostAndPath[separator+1:]
		repoPath = strings.TrimSuffix(repoPath, ".git")
		parts := strings.Split(repoPath, "/")
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid github clone URL %q", cloneURL)
		}
		return parts[0], parts[1], nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("parse github clone URL: %w", err)
	}
	if parsed.Host == "" {
		return "", "", fmt.Errorf("clone URL %q is not a github repository", cloneURL)
	}
	repoPath := strings.Trim(path.Clean(parsed.Path), "/")
	repoPath = strings.TrimSuffix(repoPath, ".git")
	parts := strings.Split(repoPath, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid github clone URL %q", cloneURL)
	}
	return parts[0], parts[1], nil
}

func githubSeverity(alert gitHubSecretAlert) string {
	if strings.EqualFold(strings.TrimSpace(alert.Validity), "active") || strings.EqualFold(strings.TrimSpace(alert.Validity), "valid") {
		return "critical"
	}
	return "high"
}

// sameOrigin reports whether candidate has the same scheme and host[:port] as
// base, and carries no userinfo.
func sameOrigin(candidate, base string) bool {
	c, err := url.Parse(strings.TrimSpace(candidate))
	if err != nil || c.User != nil || c.Host == "" {
		return false
	}
	b, err := url.Parse(strings.TrimSpace(base))
	if err != nil || b.Host == "" {
		return false
	}
	return strings.EqualFold(c.Scheme, b.Scheme) && strings.EqualFold(c.Host, b.Host)
}

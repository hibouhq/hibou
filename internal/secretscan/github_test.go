package secretscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestNewGitHubProviderDefaults(t *testing.T) {
	provider := NewGitHubProvider(nil, "", zerolog.Nop())
	if provider.client != http.DefaultClient {
		t.Fatal("client = nil, want http.DefaultClient")
	}
	if provider.baseURL != "https://api.github.com" {
		t.Fatalf("baseURL = %q, want %q", provider.baseURL, "https://api.github.com")
	}
	if provider.Name() != "github" {
		t.Fatalf("Name() = %q, want %q", provider.Name(), "github")
	}
	capabilities := provider.Capabilities()
	if !capabilities.FullScan || capabilities.IncrementalScan || !capabilities.Verification {
		t.Fatalf("Capabilities() = %#v, want full scan + verification only", capabilities)
	}
}

func TestParseGitHubCloneURL(t *testing.T) {
	cases := []struct {
		url       string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{url: "https://github.com/acme/repo.git", wantOwner: "acme", wantRepo: "repo"},
		{url: "https://github.com/acme/repo", wantOwner: "acme", wantRepo: "repo"},
		{url: "git@github.com:acme/repo.git", wantOwner: "acme", wantRepo: "repo"},
		{url: "git@github.com:acme/repo", wantOwner: "acme", wantRepo: "repo"},
		{url: "https://github.example.com/org/project.git", wantOwner: "org", wantRepo: "project"},
		{url: "git@github.example.com:org/project.git", wantOwner: "org", wantRepo: "project"},
		{url: "not-a-url", wantErr: true},
		{url: "https://github.com/only-one-part", wantErr: true},
		{url: "git@github.com:", wantErr: true},
	}

	for _, tc := range cases {
		owner, repo, err := parseGitHubCloneURL(tc.url)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseGitHubCloneURL(%q) error = nil, want error", tc.url)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseGitHubCloneURL(%q) returned error: %v", tc.url, err)
		}
		if owner != tc.wantOwner || repo != tc.wantRepo {
			t.Fatalf("parseGitHubCloneURL(%q) = (%q, %q), want (%q, %q)", tc.url, owner, repo, tc.wantOwner, tc.wantRepo)
		}
	}
}

func TestGithubSeverity(t *testing.T) {
	cases := []struct {
		name string
		in   gitHubSecretAlert
		want string
	}{
		{name: "active", in: gitHubSecretAlert{Validity: "active"}, want: "critical"},
		{name: "valid", in: gitHubSecretAlert{Validity: "valid"}, want: "critical"},
		{name: "empty", in: gitHubSecretAlert{Validity: ""}, want: "high"},
		{name: "unknown", in: gitHubSecretAlert{Validity: "unknown"}, want: "high"},
	}

	for _, tc := range cases {
		if got := githubSeverity(tc.in); got != tc.want {
			t.Fatalf("%s: githubSeverity(%q) = %q, want %q", tc.name, tc.in.Validity, got, tc.want)
		}
	}
}

func TestInjectTokenIntoCloneURL(t *testing.T) {
	cases := []struct {
		url   string
		token string
		want  string
	}{
		{url: "https://github.com/acme/repo.git", token: "ghp_123", want: "https://x-access-token:ghp_123@github.com/acme/repo.git"},
		{url: "https://github.com/acme/repo.git", token: "", want: "https://x-access-token:@github.com/acme/repo.git"},
		{url: "not-a-url", token: "token", want: "not-a-url"},
	}

	for _, tc := range cases {
		if got := injectTokenIntoCloneURL(tc.url, tc.token); got != tc.want {
			t.Fatalf("injectTokenIntoCloneURL(%q, %q) = %q, want %q", tc.url, tc.token, got, tc.want)
		}
	}
}

func TestGitHubProviderScanRepo(t *testing.T) {
	var authHeaders []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		switch {
		case r.URL.Path == "/repos/acme/repo/secret-scanning/alerts":
			if got := r.URL.Query().Get("page"); got != "1" {
				t.Fatalf("page = %q, want %q", got, "1")
			}
			if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
				t.Fatalf("Accept = %q, want github accept header", got)
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"number":                   7,
				"secret_type":              "",
				"secret_type_display_name": "GitHub PAT",
				"validity":                 "active",
				"html_url":                 "https://github.com/acme/repo/security/secret-scanning/7",
				"locations_url":            server.URL + "/locations/7",
			}})
		case r.URL.Path == "/locations/7":
			if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
				t.Fatalf("Accept = %q, want github accept header", got)
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"type": "commit",
				"details": map[string]any{
					"path":       "app.env",
					"start_line": 14,
					"blob_sha":   "abc123",
				},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewGitHubProvider(server.Client(), server.URL, zerolog.Nop())
	findings, err := provider.ScanRepo(context.Background(), ScanRepoOptions{
		CloneURL:  "https://github.com/acme/repo.git",
		AuthToken: "ghp_test",
	})
	if err != nil {
		t.Fatalf("ScanRepo returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if len(authHeaders) != 2 {
		t.Fatalf("len(authHeaders) = %d, want 2", len(authHeaders))
	}
	for _, header := range authHeaders {
		if header != "Bearer ghp_test" {
			t.Fatalf("Authorization = %q, want %q", header, "Bearer ghp_test")
		}
	}

	finding := findings[0]
	if finding.Tool != "github" {
		t.Fatalf("Tool = %q, want %q", finding.Tool, "github")
	}
	if finding.RuleID != "" {
		t.Fatalf("RuleID = %q, want empty string", finding.RuleID)
	}
	if finding.Description != "GitHub PAT" {
		t.Fatalf("Description = %q, want %q", finding.Description, "GitHub PAT")
	}
	if finding.Severity != "critical" {
		t.Fatalf("Severity = %q, want %q", finding.Severity, "critical")
	}
	if finding.FilePath != "app.env" {
		t.Fatalf("FilePath = %q, want %q", finding.FilePath, "app.env")
	}
	if finding.StartLine != 14 || finding.EndLine != 14 {
		t.Fatalf("lines = %d-%d, want 14-14", finding.StartLine, finding.EndLine)
	}
	if finding.SecretType != "GitHub PAT" {
		t.Fatalf("SecretType = %q, want %q", finding.SecretType, "GitHub PAT")
	}
	if finding.SecretHash != HashSecret("https://github.com/acme/repo/security/secret-scanning/7") {
		t.Fatalf("SecretHash = %q, want hash of html_url", finding.SecretHash)
	}
	if finding.CommitSHA != "abc123" {
		t.Fatalf("CommitSHA = %q, want %q", finding.CommitSHA, "abc123")
	}
	if !finding.Verified {
		t.Fatal("Verified = false, want true")
	}
	if finding.Fingerprint != ComputeFingerprint("app.env", 14, finding.SecretHash) {
		t.Fatalf("Fingerprint = %q, want computed fingerprint", finding.Fingerprint)
	}
	if got := finding.Metadata["validity"]; got != "active" {
		t.Fatalf("Metadata[validity] = %v, want %q", got, "active")
	}
}

func TestGitHubProviderListAlertsPagination(t *testing.T) {
	requests := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		page := r.URL.Query().Get("page")
		if page == "1" {
			alerts := make([]map[string]any, 100)
			for index := range alerts {
				alerts[index] = map[string]any{
					"number":        index + 1,
					"secret_type":   fmt.Sprintf("type-%d", index+1),
					"locations_url": server.URL + "/locations/none",
				}
			}
			_ = json.NewEncoder(w).Encode(alerts)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"number":        101,
			"secret_type":   "final",
			"locations_url": server.URL + "/locations/none",
		}})
	}))
	defer server.Close()

	provider := NewGitHubProvider(server.Client(), server.URL, zerolog.Nop())
	alerts, err := provider.listAlerts(context.Background(), "acme", "repo", "")
	if err != nil {
		t.Fatalf("listAlerts returned error: %v", err)
	}
	if len(alerts) != 101 {
		t.Fatalf("len(alerts) = %d, want 101", len(alerts))
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestGitHubProviderLoadFirstLocationEmptyURL(t *testing.T) {
	provider := NewGitHubProvider(http.DefaultClient, "https://api.github.com", zerolog.Nop())
	filePath, startLine, commitSHA, err := provider.loadFirstLocation(context.Background(), "", "")
	if err != nil {
		t.Fatalf("loadFirstLocation returned error: %v", err)
	}
	if filePath != "" || startLine != 0 || commitSHA != "" {
		t.Fatalf("loadFirstLocation() = (%q, %d, %q), want zero values", filePath, startLine, commitSHA)
	}
}

func TestGitHubProviderLoadFirstLocationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	provider := NewGitHubProvider(server.Client(), server.URL, zerolog.Nop())
	_, _, _, err := provider.loadFirstLocation(context.Background(), server.URL+"/locations/7", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGitHubProviderScanRepoInvalidCloneURL(t *testing.T) {
	provider := NewGitHubProvider(http.DefaultClient, "https://api.github.com", zerolog.Nop())
	_, err := provider.ScanRepo(context.Background(), ScanRepoOptions{CloneURL: "not-a-url"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGitHubProviderScanDiffUnsupported(t *testing.T) {
	provider := NewGitHubProvider(http.DefaultClient, "https://api.github.com", zerolog.Nop())
	_, err := provider.ScanDiff(context.Background(), ScanDiffOptions{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

package forge

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const defaultGitHubAPIURL = "https://api.github.com"
const githubBearerPrefix = "Bearer "

type GitHub struct {
	httpClient    *http.Client
	apiURL        string
	clientID      string
	clientSecret  string
	webhookSecret string
	appID         int64
	privateKey    []byte

	// ownerTokens caches installation tokens per account so repo-level REST
	// calls authenticate. Without this every contents/tree/compare call ran
	// anonymously — 60 requests/hour per IP, which is why source browsing
	// intermittently returned rate-limit errors.
	tokenMu     sync.Mutex
	ownerTokens map[string]ownerToken
}

type ownerToken struct {
	value     string
	expiresAt time.Time
}

type GitHubOption func(*GitHub)

func WithAPIURL(rawURL string) GitHubOption {
	return func(g *GitHub) {
		g.apiURL = strings.TrimRight(rawURL, "/")
	}
}

func WithHTTPClient(client *http.Client) GitHubOption {
	return func(g *GitHub) {
		if client != nil {
			g.httpClient = client
		}
	}
}

func WithAppCredentials(appID int64, privateKey []byte) GitHubOption {
	return func(g *GitHub) {
		g.appID = appID
		g.privateKey = append([]byte(nil), privateKey...)
	}
}

func NewGitHub(clientID, clientSecret, webhookSecret string, opts ...GitHubOption) *GitHub {
	github := &GitHub{
		httpClient:    http.DefaultClient,
		apiURL:        defaultGitHubAPIURL,
		clientID:      clientID,
		clientSecret:  clientSecret,
		webhookSecret: webhookSecret,
		ownerTokens:   make(map[string]ownerToken),
	}

	for _, opt := range opts {
		opt(github)
	}

	return github
}

func (g *GitHub) ID() string {
	return "github"
}

func (g *GitHub) Installations(ctx context.Context) ([]Installation, error) {
	if !g.isAppMode() {
		return nil, nil
	}

	installations, err := g.listInstallations(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]Installation, 0, len(installations))
	for _, installation := range installations {
		result = append(result, Installation{
			ID:          installation.ID,
			AccountName: installation.Account.Login,
			AccountType: installation.Account.Type,
		})
	}

	return result, nil
}

func (g *GitHub) ListRepositories(ctx context.Context, opts ListReposOptions) ([]Repository, error) {
	if g.isAppMode() {
		return g.listAppRepositories(ctx, opts)
	}
	return g.listUserRepositories(ctx, opts)
}

func (g *GitHub) listAppRepositories(ctx context.Context, opts ListReposOptions) ([]Repository, error) {
	installations, err := g.listInstallations(ctx)
	if err != nil {
		return nil, err
	}

	repositories := make([]Repository, 0)
	seen := make(map[string]struct{})
	for _, installation := range installations {
		installationRepos, err := g.ListInstallationRepositories(ctx, installation.ID)
		if err != nil {
			return nil, err
		}
		repositories = appendUniqueRepositories(repositories, installationRepos, seen)
	}

	return paginateRepositories(repositories, opts), nil
}

func (g *GitHub) listUserRepositories(ctx context.Context, opts ListReposOptions) ([]Repository, error) {

	path := "/user/repos"
	values := url.Values{}
	if opts.Page > 0 {
		values.Set("page", strconv.Itoa(opts.Page))
	}
	if opts.PerPage > 0 {
		values.Set("per_page", strconv.Itoa(opts.PerPage))
	}
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}

	var payload []githubRepository
	if err := g.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	repositories := make([]Repository, 0, len(payload))
	for _, repo := range payload {
		repositories = append(repositories, repo.toRepository())
	}

	return repositories, nil
}

func appendUniqueRepositories(target []Repository, repositories []Repository, seen map[string]struct{}) []Repository {
	for _, repo := range repositories {
		if _, ok := seen[repo.FullName]; ok {
			continue
		}
		seen[repo.FullName] = struct{}{}
		target = append(target, repo)
	}
	return target
}

// CloneURL implements CloneURLProvider without an API call: github.com's web
// host is fixed, and a GHES web host is the API URL minus its /api/v3 suffix.
func (g *GitHub) CloneURL(owner, name string) string {
	owner = strings.TrimSpace(owner)
	name = strings.TrimSpace(name)
	if owner == "" || name == "" {
		return ""
	}
	base := "https://github.com"
	if g.apiURL != "" && g.apiURL != defaultGitHubAPIURL {
		base = strings.TrimSuffix(strings.TrimRight(g.apiURL, "/"), "/api/v3")
	}
	return base + "/" + owner + "/" + name + ".git"
}

func (g *GitHub) GetRepository(ctx context.Context, owner, name string) (*Repository, error) {
	var payload githubRepository
	path := fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(name))
	if err := g.doJSONOwner(ctx, owner, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	repo := payload.toRepository()
	return &repo, nil
}

func (g *GitHub) ListBranches(ctx context.Context, owner, repo string) ([]Branch, error) {
	var payload []githubBranch
	path := fmt.Sprintf("/repos/%s/%s/branches", url.PathEscape(owner), url.PathEscape(repo))
	if err := g.doJSONOwner(ctx, owner, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	branches := make([]Branch, 0, len(payload))
	for _, branch := range payload {
		branches = append(branches, branch.toBranch())
	}

	return branches, nil
}

func (g *GitHub) GetBranch(ctx context.Context, owner, repo, branch string) (*Branch, error) {
	var payload githubBranch
	path := fmt.Sprintf(
		"/repos/%s/%s/branches/%s",
		url.PathEscape(owner),
		url.PathEscape(repo),
		url.PathEscape(branch),
	)
	if err := g.doJSONOwner(ctx, owner, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	result := payload.toBranch()
	return &result, nil
}

func (g *GitHub) GetFileContent(ctx context.Context, owner, repo, filePath, ref string) ([]byte, error) {
	requestPath := fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", url.PathEscape(owner), url.PathEscape(repo), escapeContentPath(filePath), url.QueryEscape(ref))
	request, err := g.newRequest(ctx, http.MethodGet, requestPath, nil)
	if err != nil {
		return nil, err
	}
	g.authorizeForOwner(ctx, request, owner)

	var payload githubContentFile
	status, err := g.doWithStatus(request, &payload)
	if status == http.StatusNotFound {
		return nil, ErrFileNotFound
	}
	if err != nil {
		return nil, err
	}

	decoded, err := decodeBase64Content(payload.Content)
	if err != nil {
		return nil, fmt.Errorf("decode github file content: %w", err)
	}
	return decoded, nil
}

// ListTreePaths returns every blob path at a ref via the git trees API. A
// truncated tree (GitHub caps ~100k entries) returns what was received —
// resolution then degrades to exact-path matches for anything missing.
func (g *GitHub) ListTreePaths(ctx context.Context, owner, repo, ref string) ([]string, error) {
	listing, err := g.ListTree(ctx, owner, repo, ref)
	if err != nil {
		return nil, err
	}
	return listing.Paths, nil
}

// ListTree is ListTreePaths with GitHub's truncation flag kept.
func (g *GitHub) ListTree(ctx context.Context, owner, repo, ref string) (*TreeListing, error) {
	requestPath := fmt.Sprintf(
		"/repos/%s/%s/git/trees/%s?recursive=1",
		url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(ref),
	)
	request, err := g.newRequest(ctx, http.MethodGet, requestPath, nil)
	if err != nil {
		return nil, err
	}
	g.authorizeForOwner(ctx, request, owner)

	var payload struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	status, err := g.doWithStatus(request, &payload)
	if status == http.StatusNotFound {
		return nil, ErrFileNotFound
	}
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(payload.Tree))
	for _, entry := range payload.Tree {
		if entry.Type == "blob" {
			paths = append(paths, entry.Path)
		}
	}
	return &TreeListing{Paths: paths, Truncated: payload.Truncated}, nil
}

func (g *GitHub) CreateOrUpdateFile(ctx context.Context, owner, repo, filePath, branch, message string, content []byte) error {
	sha, err := g.lookupContentSHA(ctx, owner, repo, filePath, branch)
	if err != nil {
		return err
	}

	payload := map[string]string{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(content),
		"branch":  branch,
	}
	if sha != "" {
		payload["sha"] = sha
	}

	requestPath := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), escapeContentPath(filePath))
	return g.doJSONOwner(ctx, owner, http.MethodPut, requestPath, payload, nil)
}

func (g *GitHub) CreateBranch(ctx context.Context, owner, repo, branch, fromSHA string) error {
	requestPath := fmt.Sprintf("/repos/%s/%s/git/refs", url.PathEscape(owner), url.PathEscape(repo))
	return g.doJSONOwner(ctx, owner, http.MethodPost, requestPath, map[string]string{
		"ref": "refs/heads/" + branch,
		"sha": fromSHA,
	}, nil)
}

func (g *GitHub) CreatePullRequest(ctx context.Context, owner, repo string, opts CreatePROptions) (*PullRequest, error) {
	requestPath := fmt.Sprintf("/repos/%s/%s/pulls", url.PathEscape(owner), url.PathEscape(repo))
	var payload githubPullRequestResource
	if err := g.doJSONOwner(ctx, owner, http.MethodPost, requestPath, map[string]string{
		"title": opts.Title,
		"body":  opts.Body,
		"head":  opts.Head,
		"base":  opts.Base,
	}, &payload); err != nil {
		return nil, err
	}
	return &PullRequest{Number: payload.Number, Title: payload.Title, HTMLURL: payload.HTMLURL}, nil
}

func (g *GitHub) CreateCommitStatus(ctx context.Context, owner, repo, sha string, status CommitStatus) error {
	payload := map[string]string{
		"state":       status.State,
		"context":     status.Context,
		"target_url":  status.TargetURL,
		"description": status.Description,
	}

	path := fmt.Sprintf(
		"/repos/%s/%s/statuses/%s",
		url.PathEscape(owner),
		url.PathEscape(repo),
		url.PathEscape(sha),
	)

	return g.doJSONOwner(ctx, owner, http.MethodPost, path, payload, nil)
}

// githubCompareResponse is the subset of GitHub's compare API we consume.
type githubCompareResponse struct {
	Files []githubCompareFile `json:"files"`
}

type githubCompareFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"`
	Status           string `json:"status"`
	Patch            string `json:"patch"`
}

// ComparePatch fetches the changed-file line map between base and head via
// GitHub's compare API (GET /repos/{o}/{r}/compare/{base}...{head}) and parses
// each file's unified-diff patch into new-side changed line numbers. GitHub
// returns at most 300 files per response; when more exist the result is marked
// Truncated so callers never treat a partial patch coverage number as complete.
func (g *GitHub) ComparePatch(ctx context.Context, owner, repo, base, head string) (*PatchDiff, error) {
	path := fmt.Sprintf(
		"/repos/%s/%s/compare/%s...%s",
		url.PathEscape(owner),
		url.PathEscape(repo),
		url.PathEscape(base),
		url.PathEscape(head),
	)

	var payload githubCompareResponse
	if err := g.doJSONOwner(ctx, owner, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	diff := &PatchDiff{
		Files:     make([]PatchFile, 0, len(payload.Files)),
		Truncated: len(payload.Files) >= 300,
	}
	for _, file := range payload.Files {
		if strings.TrimSpace(file.Filename) == "" {
			continue
		}
		diff.Files = append(diff.Files, PatchFile{
			Path:       file.Filename,
			OldPath:    file.PreviousFilename,
			Status:     file.Status,
			AddedLines: sortedUniqueLines(ParseUnifiedPatch(file.Patch)),
			Hunks:      file.Patch,
		})
	}
	return diff, nil
}

func (g *GitHub) ValidateWebhookPayload(r *http.Request, secret string) ([]byte, error) {
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read github webhook payload: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(payload))

	activeSecret := secret
	if activeSecret == "" {
		activeSecret = g.webhookSecret
	}
	if activeSecret == "" {
		return payload, nil
	}

	signature := r.Header.Get("X-Hub-Signature-256")
	const prefix = "sha256="
	if !strings.HasPrefix(signature, prefix) {
		return nil, errors.New("github webhook signature missing or malformed")
	}

	expectedMAC := hmac.New(sha256.New, []byte(activeSecret))
	if _, err := expectedMAC.Write(payload); err != nil {
		return nil, fmt.Errorf("hash github webhook payload: %w", err)
	}
	expected := expectedMAC.Sum(nil)

	provided, err := hex.DecodeString(strings.TrimPrefix(signature, prefix))
	if err != nil {
		return nil, fmt.Errorf("decode github webhook signature: %w", err)
	}
	if !hmac.Equal(provided, expected) {
		return nil, errors.New("github webhook signature mismatch")
	}

	return payload, nil
}

type githubWorkflowRunEvent struct {
	Action      string           `json:"action"`
	Repository  githubRepository `json:"repository"`
	WorkflowRun struct {
		ID         int64  `json:"id"`
		HeadSHA    string `json:"head_sha"`
		HeadBranch string `json:"head_branch"`
		RunAttempt int    `json:"run_attempt"`
		Conclusion string `json:"conclusion"`
	} `json:"workflow_run"`
}

func (g *GitHub) ParseWebhookEvent(eventType string, payload []byte) (WebhookEvent, error) {
	switch eventType {
	case "push":
		var event githubPushEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode github push event: %w", err)
		}
		parsed := PushEvent{
			Ref:    event.Ref,
			Before: event.Before,
			After:  event.After,
			Repo:   event.Repository.toRepository(),
			Sender: event.Sender.toUserInfo(),
		}
		return parsed, nil
	case "workflow_run":
		var event githubWorkflowRunEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode github workflow_run event: %w", err)
		}
		if !strings.EqualFold(event.Action, "completed") {
			return nil, ErrUnsupportedWebhookEvent
		}
		return BuildEvent{
			Repo:       event.Repository.toRepository(),
			CommitSHA:  event.WorkflowRun.HeadSHA,
			Ref:        event.WorkflowRun.HeadBranch,
			RunID:      strconv.FormatInt(event.WorkflowRun.ID, 10),
			RunAttempt: strconv.Itoa(event.WorkflowRun.RunAttempt),
			Succeeded:  strings.EqualFold(event.WorkflowRun.Conclusion, "success"),
			Conclusion: event.WorkflowRun.Conclusion,
		}, nil
	case "pull_request":
		var event githubPullRequestEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode github pull request event: %w", err)
		}
		parsed := PullRequestEvent{
			Action:       event.Action,
			Merged:       event.PullRequest.Merged,
			Number:       event.Number,
			Title:        event.PullRequest.Title,
			SourceBranch: event.PullRequest.Head.Ref,
			TargetBranch: event.PullRequest.Base.Ref,
			HeadSHA:      event.PullRequest.Head.SHA,
			Repo:         event.Repository.toRepository(),
		}
		return parsed, nil
	case "release":
		var event githubReleaseEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode github release event: %w", err)
		}
		return ReleaseEvent{
			Action:      event.Action,
			TagName:     event.Release.TagName,
			Name:        event.Release.Name,
			HTMLURL:     event.Release.HTMLURL,
			Draft:       event.Release.Draft,
			Prerelease:  event.Release.Prerelease,
			PublishedAt: event.Release.PublishedAt,
			Repo:        event.Repository.toRepository(),
			Sender:      event.Sender.toUserInfo(),
		}, nil
	case "installation":
		var event githubInstallationEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode github installation event: %w", err)
		}
		repositories := make([]Repository, 0, len(event.Repositories))
		for _, repo := range event.Repositories {
			repositories = append(repositories, repo.toRepository(event.Installation.Account.Login))
		}
		return InstallationEvent{
			Action:       event.Action,
			Installation: event.Installation.toInstallation(),
			Repositories: repositories,
			Sender:       event.Sender.toUserInfo(),
		}, nil
	case "installation_repositories":
		var event githubInstallationRepositoriesEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode github installation_repositories event: %w", err)
		}
		added := make([]Repository, 0, len(event.RepositoriesAdded))
		for _, repo := range event.RepositoriesAdded {
			added = append(added, repo.toRepository(event.Installation.Account.Login))
		}
		removed := make([]Repository, 0, len(event.RepositoriesRemoved))
		for _, repo := range event.RepositoriesRemoved {
			removed = append(removed, repo.toRepository(event.Installation.Account.Login))
		}
		return InstallationRepositoriesEvent{
			Action:              event.Action,
			Installation:        event.Installation.toInstallation(),
			RepositoriesAdded:   added,
			RepositoriesRemoved: removed,
			Sender:              event.Sender.toUserInfo(),
		}, nil
	case "repository":
		var event githubRepositoryEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode github repository event: %w", err)
		}
		return RepositoryEvent{
			Action:      event.Action,
			Repo:        event.Repository.toRepository(),
			OldFullName: event.oldFullName(),
			Sender:      event.Sender.toUserInfo(),
		}, nil
	default:
		return nil, fmt.Errorf("%w: github webhook event %q", ErrUnsupportedWebhookEvent, eventType)
	}
}

func (g *GitHub) OAuth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"read:user", "user:email", "repo"},
		// #nosec G101 -- OAuth endpoint URLs are constants, not credentials.
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}
}

func (g *GitHub) UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	if token == nil || token.AccessToken == "" {
		return nil, errors.New("github user info requires access token")
	}

	request, err := g.newRequest(ctx, http.MethodGet, "/user", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", githubBearerPrefix+token.AccessToken)

	var payload githubUser
	if err := g.do(request, &payload); err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload.Email) == "" {
		email, err := g.primaryEmail(ctx, token.AccessToken)
		if err != nil {
			return nil, err
		}
		payload.Email = email
	}

	user := payload.toUserInfo()
	return &user, nil
}

func (g *GitHub) ListUserAccess(ctx context.Context, token *oauth2.Token) (UserAccess, error) {
	if !g.isAppMode() || token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return UserAccess{}, nil
	}

	installations, err := g.listUserInstallations(ctx, token.AccessToken)
	if err != nil {
		return UserAccess{}, err
	}

	access := UserAccess{
		Orgs:  make([]UserOrgAccess, 0, len(installations)),
		Repos: make([]UserRepoAccess, 0),
	}
	for _, installation := range installations {
		accountLogin := strings.TrimSpace(installation.Account.Login)
		if accountLogin == "" {
			continue
		}

		repoAccess, fallbackOrgLevel, err := g.listUserInstallationRepositories(ctx, token.AccessToken, installation.ID, accountLogin)
		if err != nil {
			return UserAccess{}, err
		}

		orgLevel := "read"
		membershipLevel, ok, err := g.userInstallationOrgLevel(ctx, token.AccessToken, accountLogin)
		if err != nil {
			return UserAccess{}, err
		}
		if ok {
			orgLevel = membershipLevel
		} else if fallbackOrgLevel != "" {
			orgLevel = fallbackOrgLevel
		}

		access.Orgs = append(access.Orgs, UserOrgAccess{AccountLogin: accountLogin, Level: orgLevel})
		access.Repos = append(access.Repos, repoAccess...)
	}

	return access, nil
}

func (g *GitHub) primaryEmail(ctx context.Context, accessToken string) (string, error) {
	request, err := g.newRequest(ctx, http.MethodGet, "/user/emails", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", githubBearerPrefix+accessToken)

	var payload []githubEmail
	status, err := g.doWithStatus(request, &payload)
	if err != nil && status == http.StatusForbidden && strings.Contains(err.Error(), "Resource not accessible by integration") {
		return "", errors.New("github login requires OAuth App credentials in HIBOU_FORGE_N_CLIENT_ID and HIBOU_FORGE_N_CLIENT_SECRET; keep GitHub App credentials in HIBOU_FORGE_N_APP_ID and HIBOU_FORGE_N_PRIVATE_KEY only")
	}
	if err != nil {
		return "", err
	}

	for _, email := range payload {
		if email.Primary && email.Verified && strings.TrimSpace(email.Email) != "" {
			return email.Email, nil
		}
	}
	for _, email := range payload {
		if email.Verified && strings.TrimSpace(email.Email) != "" {
			return email.Email, nil
		}
	}

	return "", nil
}

func (g *GitHub) isAppMode() bool {
	return g.appID > 0 && len(g.privateKey) > 0
}

func (g *GitHub) listUserInstallations(ctx context.Context, accessToken string) ([]githubInstallation, error) {
	var all []githubInstallation
	path := "/user/installations?per_page=100"
	for path != "" {
		req, err := g.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", githubBearerPrefix+accessToken)

		var payload struct {
			Installations []githubInstallation `json:"installations"`
		}
		resp, err := g.doWithResponse(req, &payload)
		if err != nil {
			return nil, fmt.Errorf("list user github installations: %w", err)
		}
		all = append(all, payload.Installations...)
		path = nextPagePath(resp)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}

	return all, nil
}

func (g *GitHub) listUserInstallationRepositories(ctx context.Context, accessToken string, installationID int64, accountLogin string) ([]UserRepoAccess, string, error) {
	var all []UserRepoAccess
	hasWrite := false
	hasRead := false
	path := fmt.Sprintf("/user/installations/%d/repositories?per_page=100", installationID)
	for path != "" {
		req, err := g.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Authorization", githubBearerPrefix+accessToken)

		var payload struct {
			Repositories []githubUserAccessRepository `json:"repositories"`
		}
		resp, err := g.doWithResponse(req, &payload)
		if err != nil {
			return nil, "", fmt.Errorf("list user installation repositories: %w", err)
		}
		for _, repo := range payload.Repositories {
			level := repo.highestPermissionLevel()
			if level == "" {
				continue
			}
			all = append(all, repo.toUserRepoAccess(accountLogin, level))
			switch capGitHubRepoLevelForOrg(level) {
			case "push":
				hasWrite = true
			case "pull":
				hasRead = true
			}
		}
		path = nextPagePath(resp)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}

	switch {
	case hasWrite:
		return all, "push", nil
	case hasRead:
		return all, "pull", nil
	default:
		return all, "", nil
	}
}

func (g *GitHub) userInstallationOrgLevel(ctx context.Context, accessToken, accountLogin string) (string, bool, error) {
	path := "/user/memberships/orgs/" + url.PathEscape(accountLogin)
	req, err := g.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", githubBearerPrefix+accessToken)

	var payload struct {
		Role string `json:"role"`
	}
	status, err := g.doWithStatus(req, &payload)
	if err != nil {
		if status > 0 {
			return "", false, nil
		}
		return "", false, nil
	}

	switch strings.ToLower(strings.TrimSpace(payload.Role)) {
	case "admin":
		return "admin", true, nil
	case "member":
		return "read", true, nil
	default:
		return "read", true, nil
	}
}

func capGitHubRepoLevelForOrg(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "admin", "maintain", "push":
		return "push"
	case "triage", "pull":
		return "pull"
	default:
		return ""
	}
}

// generateAppJWT creates a JWT signed with the App's private key.
// GitHub requires: iat (issued at), exp (max 10 min), iss (app ID).
func (g *GitHub) generateAppJWT() (string, error) {
	block, _ := pem.Decode(g.privateKey)
	if block == nil {
		return "", errors.New("failed to decode PEM block from private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, errPKCS8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errPKCS8 != nil {
			return "", fmt.Errorf("parse private key: %w", err)
		}

		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("private key is not RSA")
		}
		key = rsaKey
	}

	now := time.Now().Add(-30 * time.Second)
	expiresAt := now.Add(10 * time.Minute)
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(fmt.Sprintf(
		`{"iat":%d,"exp":%d,"iss":%d}`,
		now.Unix(),
		expiresAt.Unix(),
		g.appID,
	)))

	signingInput := header + "." + payload
	hash := crypto.SHA256.New()
	_, _ = hash.Write([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signingInput + "." + base64URLEncode(signature), nil
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// listInstallations returns all installations of this GitHub App.
// Paginates through all pages to handle Apps installed on many orgs.
func (g *GitHub) listInstallations(ctx context.Context) ([]githubInstallation, error) {
	jwt, err := g.generateAppJWT()
	if err != nil {
		return nil, err
	}

	var all []githubInstallation
	path := "/app/installations?per_page=100"
	for path != "" {
		req, err := g.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", githubBearerPrefix+jwt)

		var page []githubInstallation
		resp, err := g.doWithResponse(req, &page)
		if err != nil {
			return nil, fmt.Errorf("list github app installations: %w", err)
		}
		all = append(all, page...)
		path = nextPagePath(resp)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}

	return all, nil
}

// createInstallationToken creates an access token for an installation.
func (g *GitHub) createInstallationToken(ctx context.Context, installationID int64) (*githubInstallationToken, error) {
	jwt, err := g.generateAppJWT()
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	req, err := g.newRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", githubBearerPrefix+jwt)

	var token githubInstallationToken
	if err := g.do(req, &token); err != nil {
		return nil, fmt.Errorf("create installation token for %d: %w", installationID, err)
	}

	return &token, nil
}

// ListInstallationRepositories lists all repos accessible to an App installation.
// Paginates through all pages.
func (g *GitHub) ListInstallationRepositories(ctx context.Context, installationID int64) ([]Repository, error) {
	token, err := g.createInstallationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}

	var repositories []Repository
	path := "/installation/repositories?per_page=100"
	for path != "" {
		req, err := g.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", githubBearerPrefix+token.Token)

		var payload struct {
			Repositories []githubRepository `json:"repositories"`
		}
		resp, err := g.doWithResponse(req, &payload)
		if err != nil {
			return nil, fmt.Errorf("list installation repositories: %w", err)
		}
		for _, repo := range payload.Repositories {
			repositories = append(repositories, repo.toRepository())
		}
		path = nextPagePath(resp)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}

	return repositories, nil
}

func (g *GitHub) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	endpoint := g.apiURL + path

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal github request body: %w", err)
		}
		reader = bytes.NewReader(payload)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("create github request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	return request, nil
}

func (g *GitHub) doJSON(ctx context.Context, method, path string, body any, out any) error {
	request, err := g.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}

	return g.do(request, out)
}

// doJSONOwner is doJSON with the owner's installation token attached (App
// mode). Repo-level REST calls must use this: anonymous calls are capped at 60
// requests/hour per IP and cannot see private repositories.
func (g *GitHub) doJSONOwner(ctx context.Context, owner, method, path string, body any, out any) error {
	request, err := g.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	g.authorizeForOwner(ctx, request, owner)
	return g.do(request, out)
}

func (g *GitHub) do(request *http.Request, out any) error {
	_, err := g.doWithStatus(request, out)
	return err
}

// doWithResponse performs a request and returns the raw HTTP response (for pagination headers).
func (g *GitHub) doWithResponse(request *http.Request, out any) (*http.Response, error) {
	response, err := g.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("perform github request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return nil, fmt.Errorf("github api %s: %s", request.URL.Path, message)
	}

	if out != nil {
		if err := json.NewDecoder(response.Body).Decode(out); err != nil {
			return nil, fmt.Errorf("decode github response: %w", err)
		}
	} else {
		_, _ = io.Copy(io.Discard, response.Body)
	}

	return response, nil
}

// nextPagePath extracts the "next" page path from the Link header.
// Returns "" if there is no next page.
func nextPagePath(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	link := resp.Header.Get("Link")
	if link == "" {
		return ""
	}
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start < 0 || end < 0 || end <= start {
			continue
		}
		fullURL := part[start+1 : end]
		// Extract path+query from full URL
		parsed, err := url.Parse(fullURL)
		if err != nil {
			continue
		}
		path := parsed.Path
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		return path
	}
	return ""
}

func (g *GitHub) doWithStatus(request *http.Request, out any) (int, error) {
	response, err := g.httpClient.Do(request)
	if err != nil {
		return 0, fmt.Errorf("perform github request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return response.StatusCode, fmt.Errorf("github api %s: %s", request.URL.Path, message)
	}

	if out == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode, nil
	}

	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		return response.StatusCode, fmt.Errorf("decode github response: %w", err)
	}

	return response.StatusCode, nil
}

func (g *GitHub) lookupContentSHA(ctx context.Context, owner, repo, filePath, ref string) (string, error) {
	requestPath := fmt.Sprintf("/repos/%s/%s/contents/%s?ref=%s", url.PathEscape(owner), url.PathEscape(repo), escapeContentPath(filePath), url.QueryEscape(ref))
	request, err := g.newRequest(ctx, http.MethodGet, requestPath, nil)
	if err != nil {
		return "", err
	}
	g.authorizeForOwner(ctx, request, owner)

	var payload githubContentFile
	status, err := g.doWithStatus(request, &payload)
	if status == http.StatusNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return payload.SHA, nil
}

func escapeContentPath(filePath string) string {
	parts := strings.Split(strings.Trim(filePath, "/"), "/")
	for index, part := range parts {
		parts[index] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func decodeBase64Content(content string) ([]byte, error) {
	cleaned := strings.ReplaceAll(content, "\n", "")
	return base64.StdEncoding.DecodeString(cleaned)
}

func paginateRepositories(repositories []Repository, opts ListReposOptions) []Repository {
	if opts.PerPage <= 0 {
		return repositories
	}

	page := opts.Page
	if page <= 0 {
		page = 1
	}

	start := (page - 1) * opts.PerPage
	if start >= len(repositories) {
		return nil
	}

	end := start + opts.PerPage
	if end > len(repositories) {
		end = len(repositories)
	}

	return repositories[start:end]
}

type githubRepository struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Archived      bool   `json:"archived"`
	Private       bool   `json:"private"`
	CloneURL      string `json:"clone_url"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
	Size          int64  `json:"size"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

type githubContentFile struct {
	SHA      string `json:"sha"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type githubInstallation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"account"`
}

func (i githubInstallation) toInstallation() Installation {
	return Installation{
		ID:          i.ID,
		AccountName: i.Account.Login,
		AccountType: i.Account.Type,
	}
}

type githubInstallationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type githubRepositoryPermissions struct {
	Admin    bool `json:"admin"`
	Maintain bool `json:"maintain"`
	Push     bool `json:"push"`
	Triage   bool `json:"triage"`
	Pull     bool `json:"pull"`
}

type githubPullRequestResource struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
}

func (r githubRepository) toRepository() Repository {
	providerRepoID := ""
	if r.ID > 0 {
		providerRepoID = strconv.FormatInt(r.ID, 10)
	}

	return Repository{
		ProviderID:     r.FullName,
		ProviderRepoID: providerRepoID,
		Owner:          r.Owner.Login,
		Name:           r.Name,
		FullName:       r.FullName,
		DefaultBranch:  r.DefaultBranch,
		Archived:       r.Archived,
		Private:        r.Private,
		CloneURL:       r.CloneURL,
		HTMLURL:        r.HTMLURL,
		SizeKB:         r.Size,
	}
}

type githubBranch struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
	Commit    struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

func (b githubBranch) toBranch() Branch {
	return Branch{
		Name:      b.Name,
		SHA:       b.Commit.SHA,
		Protected: b.Protected,
	}
}

type githubUser struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (u githubUser) toUserInfo() UserInfo {
	displayName := u.Name
	if displayName == "" {
		displayName = u.Login
	}
	providerID := u.Login
	if u.ID > 0 {
		providerID = strconv.FormatInt(u.ID, 10)
	}

	return UserInfo{
		ProviderID:  providerID,
		Email:       u.Email,
		DisplayName: displayName,
		AvatarURL:   u.AvatarURL,
	}
}

type githubPushEvent struct {
	Ref        string           `json:"ref"`
	Before     string           `json:"before"`
	After      string           `json:"after"`
	Repository githubRepository `json:"repository"`
	Sender     githubUser       `json:"sender"`
}

type githubReleaseEvent struct {
	Action  string `json:"action"`
	Release struct {
		TagName     string     `json:"tag_name"`
		Name        string     `json:"name"`
		HTMLURL     string     `json:"html_url"`
		Draft       bool       `json:"draft"`
		Prerelease  bool       `json:"prerelease"`
		PublishedAt *time.Time `json:"published_at"`
	} `json:"release"`
	Repository githubRepository `json:"repository"`
	Sender     githubUser       `json:"sender"`
}

type githubPullRequestEvent struct {
	Action      string           `json:"action"`
	Number      int              `json:"number"`
	Repository  githubRepository `json:"repository"`
	PullRequest struct {
		Title  string `json:"title"`
		Merged bool   `json:"merged"`
		Head   struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
}

type githubInstallationRepository struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

type githubUserAccessRepository struct {
	ID          int64                       `json:"id"`
	Name        string                      `json:"name"`
	FullName    string                      `json:"full_name"`
	Permissions githubRepositoryPermissions `json:"permissions"`
	Owner       struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func (r githubUserAccessRepository) highestPermissionLevel() string {
	switch {
	case r.Permissions.Admin:
		return "admin"
	case r.Permissions.Maintain:
		return "maintain"
	case r.Permissions.Push:
		return "push"
	case r.Permissions.Triage:
		return "triage"
	case r.Permissions.Pull:
		return "pull"
	default:
		return ""
	}
}

func (r githubUserAccessRepository) toUserRepoAccess(accountLogin, level string) UserRepoAccess {
	providerRepoID := ""
	if r.ID > 0 {
		providerRepoID = strconv.FormatInt(r.ID, 10)
	}

	return UserRepoAccess{
		AccountLogin:   accountLogin,
		ProviderRepoID: providerRepoID,
		Owner:          strings.TrimSpace(r.Owner.Login),
		Name:           strings.TrimSpace(r.Name),
		FullName:       strings.TrimSpace(r.FullName),
		Level:          level,
	}
}

func (r githubInstallationRepository) toRepository(accountLogin string) Repository {
	owner := strings.TrimSpace(accountLogin)
	fullName := strings.TrimSpace(r.FullName)
	name := strings.TrimSpace(r.Name)
	if fullName == "" && owner != "" && name != "" {
		fullName = owner + "/" + name
	}
	if owner == "" && fullName != "" {
		parts := strings.SplitN(fullName, "/", 2)
		if len(parts) == 2 {
			owner = parts[0]
			if name == "" {
				name = parts[1]
			}
		}
	}
	providerRepoID := ""
	if r.ID > 0 {
		providerRepoID = strconv.FormatInt(r.ID, 10)
	}

	return Repository{
		ProviderID:     fullName,
		ProviderRepoID: providerRepoID,
		Owner:          owner,
		Name:           name,
		FullName:       fullName,
		Private:        r.Private,
	}
}

type githubInstallationEvent struct {
	Action       string                         `json:"action"`
	Installation githubInstallation             `json:"installation"`
	Repositories []githubInstallationRepository `json:"repositories"`
	Sender       githubUser                     `json:"sender"`
}

type githubInstallationRepositoriesEvent struct {
	Action              string                         `json:"action"`
	Installation        githubInstallation             `json:"installation"`
	RepositoriesAdded   []githubInstallationRepository `json:"repositories_added"`
	RepositoriesRemoved []githubInstallationRepository `json:"repositories_removed"`
	Sender              githubUser                     `json:"sender"`
}

type githubRepositoryEvent struct {
	Action     string           `json:"action"`
	Repository githubRepository `json:"repository"`
	Changes    struct {
		Repository struct {
			Name struct {
				From string `json:"from"`
			} `json:"name"`
		} `json:"repository"`
	} `json:"changes"`
	Sender githubUser `json:"sender"`
}

func (e githubRepositoryEvent) oldFullName() string {
	oldName := strings.TrimSpace(e.Changes.Repository.Name.From)
	if oldName == "" {
		return ""
	}
	owner := strings.TrimSpace(e.Repository.Owner.Login)
	if owner == "" {
		parts := strings.SplitN(strings.TrimSpace(e.Repository.FullName), "/", 2)
		if len(parts) == 2 {
			owner = parts[0]
		}
	}
	if owner == "" {
		return oldName
	}
	return owner + "/" + oldName
}

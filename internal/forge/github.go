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
		repositories = append(repositories, repo.toRepository(g.ID()))
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

func (g *GitHub) GetRepository(ctx context.Context, owner, name string) (*Repository, error) {
	var payload githubRepository
	path := fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(name))
	if err := g.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	repo := payload.toRepository(g.ID())
	return &repo, nil
}

func (g *GitHub) ListBranches(ctx context.Context, owner, repo string) ([]Branch, error) {
	var payload []githubBranch
	path := fmt.Sprintf("/repos/%s/%s/branches", url.PathEscape(owner), url.PathEscape(repo))
	if err := g.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
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
	if err := g.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
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
	return g.doJSON(ctx, http.MethodPut, requestPath, payload, nil)
}

func (g *GitHub) CreateBranch(ctx context.Context, owner, repo, branch, fromSHA string) error {
	requestPath := fmt.Sprintf("/repos/%s/%s/git/refs", url.PathEscape(owner), url.PathEscape(repo))
	return g.doJSON(ctx, http.MethodPost, requestPath, map[string]string{
		"ref": "refs/heads/" + branch,
		"sha": fromSHA,
	}, nil)
}

func (g *GitHub) CreatePullRequest(ctx context.Context, owner, repo string, opts CreatePROptions) (*PullRequest, error) {
	requestPath := fmt.Sprintf("/repos/%s/%s/pulls", url.PathEscape(owner), url.PathEscape(repo))
	var payload githubPullRequestResource
	if err := g.doJSON(ctx, http.MethodPost, requestPath, map[string]string{
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

	return g.doJSON(ctx, http.MethodPost, path, payload, nil)
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
			Repo:   event.Repository.toRepository(g.ID()),
			Sender: event.Sender.toUserInfo(g.ID()),
		}
		return parsed, nil
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
			Repo:         event.Repository.toRepository(g.ID()),
		}
		return parsed, nil
	default:
		return nil, fmt.Errorf("github webhook event %q not supported", eventType)
	}
}

func (g *GitHub) OAuth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"read:user", "user:email", "repo"},
		//nolint:gosec // G101: OAuth endpoint URLs are constants, not credentials.
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

	user := payload.toUserInfo(g.ID())
	return &user, nil
}

func (g *GitHub) primaryEmail(ctx context.Context, accessToken string) (string, error) {
	request, err := g.newRequest(ctx, http.MethodGet, "/user/emails", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", githubBearerPrefix+accessToken)

	var payload []githubEmail
	if err := g.do(request, &payload); err != nil {
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
			repositories = append(repositories, repo.toRepository(g.ID()))
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
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	CloneURL      string `json:"clone_url"`
	HTMLURL       string `json:"html_url"`
	DefaultBranch string `json:"default_branch"`
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

type githubInstallationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type githubPullRequestResource struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
}

func (r githubRepository) toRepository(providerID string) Repository {
	return Repository{
		ProviderID:    providerID,
		Owner:         r.Owner.Login,
		Name:          r.Name,
		FullName:      r.FullName,
		DefaultBranch: r.DefaultBranch,
		Private:       r.Private,
		CloneURL:      r.CloneURL,
		HTMLURL:       r.HTMLURL,
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

func (u githubUser) toUserInfo(providerID string) UserInfo {
	displayName := u.Name
	if displayName == "" {
		displayName = u.Login
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

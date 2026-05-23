package forge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

const defaultGitHubAPIURL = "https://api.github.com"

type GitHub struct {
	httpClient    *http.Client
	apiURL        string
	clientID      string
	clientSecret  string
	webhookSecret string
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

func (g *GitHub) ListRepositories(ctx context.Context, opts ListReposOptions) ([]Repository, error) {
	path := "/user/repos"
	values := url.Values{}
	if opts.Page > 0 {
		values.Set("page", fmt.Sprintf("%d", opts.Page))
	}
	if opts.PerPage > 0 {
		values.Set("per_page", fmt.Sprintf("%d", opts.PerPage))
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
		return nil, fmt.Errorf("github webhook signature missing or malformed")
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
		return nil, fmt.Errorf("github webhook signature mismatch")
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
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}
}

func (g *GitHub) UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("github user info requires access token")
	}

	request, err := g.newRequest(ctx, http.MethodGet, "/user", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)

	var payload githubUser
	if err := g.do(request, &payload); err != nil {
		return nil, err
	}

	user := payload.toUserInfo(g.ID())
	return &user, nil
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
	response, err := g.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("perform github request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return fmt.Errorf("github api %s: %s", request.URL.Path, message)
	}

	if out == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}

	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		return fmt.Errorf("decode github response: %w", err)
	}

	return nil
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
		Title string `json:"title"`
		Head  struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
}
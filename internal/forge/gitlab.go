package forge

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

type GitLab struct {
	apiURL        string
	clientID      string
	clientSecret  string
	webhookSecret string
	httpClient    *http.Client
}

func NewGitLab(apiURL, clientID, clientSecret, webhookSecret string) *GitLab {
	if apiURL == "" {
		apiURL = "https://gitlab.com"
	}

	return &GitLab{
		apiURL:        strings.TrimRight(apiURL, "/"),
		clientID:      clientID,
		clientSecret:  clientSecret,
		webhookSecret: webhookSecret,
		httpClient:    http.DefaultClient,
	}
}

func (g *GitLab) ID() string {
	return "gitlab"
}

func (g *GitLab) Installations(context.Context) ([]Installation, error) {
	return nil, nil
}

func (g *GitLab) ListRepositories(ctx context.Context, opts ListReposOptions) ([]Repository, error) {
	path := "/api/v4/projects?membership=true"
	values := url.Values{}
	if opts.Page > 0 {
		values.Set("page", strconv.Itoa(opts.Page))
	}
	if opts.PerPage > 0 {
		values.Set("per_page", strconv.Itoa(opts.PerPage))
	}
	if encoded := values.Encode(); encoded != "" {
		path += "&" + encoded
	}

	var payload []gitlabProject
	if err := g.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	repositories := make([]Repository, 0, len(payload))
	for _, project := range payload {
		repositories = append(repositories, project.toRepository())
	}

	return repositories, nil
}

func (g *GitLab) GetRepository(ctx context.Context, owner, name string) (*Repository, error) {
	var payload gitlabProject
	path := "/api/v4/projects/" + gitlabProjectID(owner, name)
	if err := g.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	repo := payload.toRepository()
	return &repo, nil
}

func (g *GitLab) ListBranches(ctx context.Context, owner, repo string) ([]Branch, error) {
	var payload []gitlabBranch
	path := fmt.Sprintf("/api/v4/projects/%s/repository/branches", gitlabProjectID(owner, repo))
	if err := g.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	branches := make([]Branch, 0, len(payload))
	for _, branch := range payload {
		branches = append(branches, branch.toBranch())
	}

	return branches, nil
}

func (g *GitLab) GetBranch(ctx context.Context, owner, repo, branch string) (*Branch, error) {
	var payload gitlabBranch
	path := fmt.Sprintf(
		"/api/v4/projects/%s/repository/branches/%s",
		gitlabProjectID(owner, repo),
		url.PathEscape(branch),
	)
	if err := g.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	result := payload.toBranch()
	return &result, nil
}

func (g *GitLab) GetFileContent(ctx context.Context, owner, repo, filePath, ref string) ([]byte, error) {
	requestPath := fmt.Sprintf(
		"/api/v4/projects/%s/repository/files/%s/raw?ref=%s",
		gitlabProjectID(owner, repo),
		gitlabFilePath(filePath),
		url.QueryEscape(ref),
	)
	request, err := g.newRequest(ctx, http.MethodGet, requestPath, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "*/*")

	response, err := g.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("perform gitlab request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return nil, ErrFileNotFound
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return nil, fmt.Errorf("gitlab api %s: %s", request.URL.Path, message)
	}

	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read gitlab file content: %w", err)
	}
	return content, nil
}

func (g *GitLab) CreateOrUpdateFile(ctx context.Context, owner, repo, filePath, branch, message string, content []byte) error {
	payload := map[string]string{
		"branch":         branch,
		"content":        base64.StdEncoding.EncodeToString(content),
		"commit_message": message,
		"encoding":       "base64",
	}

	exists, err := g.fileExists(ctx, owner, repo, filePath, branch)
	if err != nil {
		return err
	}

	requestPath := fmt.Sprintf(
		"/api/v4/projects/%s/repository/files/%s",
		gitlabProjectID(owner, repo),
		gitlabFilePath(filePath),
	)
	method := http.MethodPost
	if exists {
		method = http.MethodPut
	}

	return g.doJSON(ctx, method, requestPath, payload, nil)
}

func (g *GitLab) CreateBranch(ctx context.Context, owner, repo, branch, fromSHA string) error {
	values := url.Values{}
	values.Set("branch", branch)
	values.Set("ref", fromSHA)

	requestPath := fmt.Sprintf("/api/v4/projects/%s/repository/branches?%s", gitlabProjectID(owner, repo), values.Encode())
	return g.doJSON(ctx, http.MethodPost, requestPath, nil, nil)
}

func (g *GitLab) CreatePullRequest(ctx context.Context, owner, repo string, opts CreatePROptions) (*PullRequest, error) {
	requestPath := fmt.Sprintf("/api/v4/projects/%s/merge_requests", gitlabProjectID(owner, repo))
	var payload gitlabMergeRequest
	if err := g.doJSON(ctx, http.MethodPost, requestPath, map[string]string{
		"title":         opts.Title,
		"description":   opts.Body,
		"source_branch": opts.Head,
		"target_branch": opts.Base,
	}, &payload); err != nil {
		return nil, err
	}

	return &PullRequest{Number: payload.IID, Title: payload.Title, HTMLURL: payload.WebURL}, nil
}

func (g *GitLab) CreateCommitStatus(ctx context.Context, owner, repo, sha string, status CommitStatus) error {
	payload := map[string]string{
		"state":       gitlabStatusState(status.State),
		"name":        status.Context,
		"target_url":  status.TargetURL,
		"description": status.Description,
	}

	path := fmt.Sprintf(
		"/api/v4/projects/%s/statuses/%s",
		gitlabProjectID(owner, repo),
		url.PathEscape(sha),
	)

	return g.doJSON(ctx, http.MethodPost, path, payload, nil)
}

func (g *GitLab) ValidateWebhookPayload(r *http.Request, secret string) ([]byte, error) {
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read gitlab webhook payload: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(payload))

	activeSecret := secret
	if activeSecret == "" {
		activeSecret = g.webhookSecret
	}
	if activeSecret == "" {
		return payload, nil
	}

	provided := r.Header.Get("X-Gitlab-Token")
	if provided == "" {
		return nil, errors.New("gitlab webhook token missing")
	}
	if subtle.ConstantTimeCompare([]byte(provided), []byte(activeSecret)) != 1 {
		return nil, errors.New("gitlab webhook token mismatch")
	}

	return payload, nil
}

func (g *GitLab) ParseWebhookEvent(eventType string, payload []byte) (WebhookEvent, error) {
	switch strings.TrimSpace(eventType) {
	case "Push Hook":
		var event gitlabPushEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode gitlab push event: %w", err)
		}
		return PushEvent{
			Ref:    event.Ref,
			Before: event.Before,
			After:  event.After,
			Repo:   event.Project.toRepository(),
			Sender: event.toUserInfo(),
		}, nil
	case "Merge Request Hook":
		var event gitlabMergeRequestEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode gitlab merge request event: %w", err)
		}
		return PullRequestEvent{
			Action:       event.ObjectAttributes.Action,
			Merged:       event.ObjectAttributes.State == "merged" || event.ObjectAttributes.Action == "merge",
			Number:       event.ObjectAttributes.IID,
			Title:        event.ObjectAttributes.Title,
			SourceBranch: event.ObjectAttributes.SourceBranch,
			TargetBranch: event.ObjectAttributes.TargetBranch,
			HeadSHA:      event.ObjectAttributes.LastCommit.ID,
			Repo:         event.Project.toRepository(),
		}, nil
	default:
		return nil, fmt.Errorf("gitlab webhook event %q not supported", eventType)
	}
}

func (g *GitLab) OAuth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  g.apiURL + "/oauth/authorize",
			TokenURL: g.apiURL + "/oauth/token",
		},
	}
}

func (g *GitLab) UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	if token == nil || token.AccessToken == "" {
		return nil, errors.New("gitlab user info requires access token")
	}

	request, err := g.newRequest(ctx, http.MethodGet, "/api/v4/user", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)

	var payload gitlabUser
	if err := g.do(request, &payload); err != nil {
		return nil, err
	}

	user := payload.toUserInfo()
	return &user, nil
}

func (g *GitLab) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	endpoint := g.apiURL + path

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal gitlab request body: %w", err)
		}
		reader = bytes.NewReader(payload)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("create gitlab request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	return request, nil
}

func (g *GitLab) doJSON(ctx context.Context, method, path string, body any, out any) error {
	request, err := g.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}

	return g.do(request, out)
}

func (g *GitLab) do(request *http.Request, out any) error {
	_, err := g.doWithStatus(request, out)
	return err
}

func (g *GitLab) fileExists(ctx context.Context, owner, repo, filePath, branch string) (bool, error) {
	requestPath := fmt.Sprintf(
		"/api/v4/projects/%s/repository/files/%s?ref=%s",
		gitlabProjectID(owner, repo),
		gitlabFilePath(filePath),
		url.QueryEscape(branch),
	)
	request, err := g.newRequest(ctx, http.MethodGet, requestPath, nil)
	if err != nil {
		return false, err
	}

	status, err := g.doWithStatus(request, nil)
	if status == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (g *GitLab) doWithStatus(request *http.Request, out any) (int, error) {
	response, err := g.httpClient.Do(request)
	if err != nil {
		return 0, fmt.Errorf("perform gitlab request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return response.StatusCode, fmt.Errorf("gitlab api %s: %s", request.URL.Path, message)
	}

	if out == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode, nil
	}

	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		return response.StatusCode, fmt.Errorf("decode gitlab response: %w", err)
	}

	return response.StatusCode, nil
}

func gitlabProjectID(owner, repo string) string {
	return url.PathEscape(strings.Trim(owner, "/") + "/" + strings.Trim(repo, "/"))
}

func gitlabFilePath(filePath string) string {
	return url.PathEscape(strings.Trim(filePath, "/"))
}

func gitlabStatusState(state string) string {
	switch state {
	case "pending":
		return "pending"
	case "success":
		return "success"
	case "failure", "error":
		return "failed"
	default:
		return state
	}
}

func gitlabRepositoryParts(pathWithNamespace, fallbackOwner, fallbackName, displayName string) (string, string) {
	owner := fallbackOwner
	name := fallbackName

	if index := strings.LastIndex(pathWithNamespace, "/"); index >= 0 {
		owner = pathWithNamespace[:index]
		name = pathWithNamespace[index+1:]
	}
	if name == "" {
		name = displayName
	}

	return owner, name
}

type gitlabProject struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
	Visibility        string `json:"visibility"`
	HTTPURLToRepo     string `json:"http_url_to_repo"`
	WebURL            string `json:"web_url"`
	Namespace         struct {
		Path string `json:"path"`
	} `json:"namespace"`
	Path string `json:"path"`
}

func (p gitlabProject) toRepository() Repository {
	owner, name := gitlabRepositoryParts(p.PathWithNamespace, p.Namespace.Path, p.Path, p.Name)

	return Repository{
		ProviderID:    strconv.FormatInt(p.ID, 10),
		Owner:         owner,
		Name:          name,
		FullName:      p.PathWithNamespace,
		DefaultBranch: p.DefaultBranch,
		Private:       p.Visibility != "public",
		CloneURL:      p.HTTPURLToRepo,
		HTMLURL:       p.WebURL,
	}
}

type gitlabWebhookProject struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
	Visibility        string `json:"visibility"`
	HTTPURLToRepo     string `json:"http_url_to_repo"`
	WebURL            string `json:"web_url"`
	Namespace         string `json:"namespace"`
}

func (p gitlabWebhookProject) toRepository() Repository {
	owner, name := gitlabRepositoryParts(p.PathWithNamespace, p.Namespace, "", p.Name)

	return Repository{
		ProviderID:    strconv.FormatInt(p.ID, 10),
		Owner:         owner,
		Name:          name,
		FullName:      p.PathWithNamespace,
		DefaultBranch: p.DefaultBranch,
		Private:       p.Visibility != "public",
		CloneURL:      p.HTTPURLToRepo,
		HTMLURL:       p.WebURL,
	}
}

type gitlabBranch struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
	Commit    struct {
		ID string `json:"id"`
	} `json:"commit"`
}

func (b gitlabBranch) toBranch() Branch {
	return Branch{
		Name:      b.Name,
		SHA:       b.Commit.ID,
		Protected: b.Protected,
	}
}

type gitlabUser struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

func (u gitlabUser) toUserInfo() UserInfo {
	displayName := u.Name
	if displayName == "" {
		displayName = u.Username
	}

	return UserInfo{
		ProviderID:  strconv.FormatInt(u.ID, 10),
		Email:       u.Email,
		DisplayName: displayName,
		AvatarURL:   u.AvatarURL,
	}
}

type gitlabMergeRequest struct {
	IID    int    `json:"iid"`
	Title  string `json:"title"`
	WebURL string `json:"web_url"`
}

type gitlabPushEvent struct {
	Ref        string               `json:"ref"`
	Before     string               `json:"before"`
	After      string               `json:"after"`
	Project    gitlabWebhookProject `json:"project"`
	UserName   string               `json:"user_name"`
	UserEmail  string               `json:"user_email"`
	UserID     int64                `json:"user_id"`
	UserAvatar string               `json:"user_avatar"`
}

func (e gitlabPushEvent) toUserInfo() UserInfo {
	return UserInfo{
		ProviderID:  strconv.FormatInt(e.UserID, 10),
		Email:       e.UserEmail,
		DisplayName: e.UserName,
		AvatarURL:   e.UserAvatar,
	}
}

type gitlabMergeRequestEvent struct {
	Project          gitlabWebhookProject `json:"project"`
	ObjectAttributes struct {
		IID          int    `json:"iid"`
		Title        string `json:"title"`
		Action       string `json:"action"`
		SourceBranch string `json:"source_branch"`
		TargetBranch string `json:"target_branch"`
		LastCommit   struct {
			ID string `json:"id"`
		} `json:"last_commit"`
		State string `json:"state"`
	} `json:"object_attributes"`
}

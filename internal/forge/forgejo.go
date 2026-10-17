package forge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// Forgejo implements the Provider interface for Forgejo and Gitea instances.
// The API is Gitea-compatible so this works with both.
type Forgejo struct {
	apiURL        string
	clientID      string
	clientSecret  string
	webhookSecret string
	// token authenticates the server's own API calls. The OAuth2 client
	// credentials above only authenticate a user login; Forgejo answers
	// "token is required" to any API call that arrives without this, so
	// without it commit statuses and PR comments are silently dropped.
	token      string
	httpClient *http.Client
}

// CloneURL implements CloneURLProvider: Forgejo's apiURL is the web base
// (request paths append /api/v1), so the clone URL derives directly from it.
func (f *Forgejo) CloneURL(owner, name string) string {
	owner = strings.TrimSpace(owner)
	name = strings.TrimSpace(name)
	if owner == "" || name == "" {
		return ""
	}
	return f.apiURL + "/" + owner + "/" + name + ".git"
}

func NewForgejo(apiURL, clientID, clientSecret, webhookSecret, token string) *Forgejo {
	if apiURL == "" {
		apiURL = "http://localhost:3030"
	}

	return &Forgejo{
		apiURL:        strings.TrimRight(apiURL, "/"),
		clientID:      clientID,
		clientSecret:  clientSecret,
		webhookSecret: webhookSecret,
		token:         strings.TrimSpace(token),
		httpClient:    NewHTTPClient(),
	}
}

func (f *Forgejo) ID() string {
	return "forgejo"
}

func (f *Forgejo) Installations(context.Context) ([]Installation, error) {
	return nil, nil
}

func (f *Forgejo) ListRepositories(ctx context.Context, opts ListReposOptions) ([]Repository, error) {
	path := "/api/v1/user/repos"
	values := url.Values{}
	if opts.Page > 0 {
		values.Set("page", strconv.Itoa(opts.Page))
	}
	if opts.PerPage > 0 {
		values.Set("limit", strconv.Itoa(opts.PerPage))
	}
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}

	var payload []forgejoRepository
	if err := f.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	repositories := make([]Repository, 0, len(payload))
	for _, repo := range payload {
		repositories = append(repositories, repo.toRepository())
	}

	return repositories, nil
}

func (f *Forgejo) GetRepository(ctx context.Context, owner, name string) (*Repository, error) {
	var payload forgejoRepository
	path := fmt.Sprintf("/api/v1/repos/%s/%s", url.PathEscape(owner), url.PathEscape(name))
	if err := f.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	repo := payload.toRepository()
	return &repo, nil
}

func (f *Forgejo) ListBranches(ctx context.Context, owner, repo string) ([]Branch, error) {
	var payload []forgejoBranch
	path := fmt.Sprintf("/api/v1/repos/%s/%s/branches", url.PathEscape(owner), url.PathEscape(repo))
	if err := f.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	branches := make([]Branch, 0, len(payload))
	for _, branch := range payload {
		branches = append(branches, branch.toBranch())
	}

	return branches, nil
}

func (f *Forgejo) GetBranch(ctx context.Context, owner, repo, branch string) (*Branch, error) {
	var payload forgejoBranch
	path := fmt.Sprintf(
		"/api/v1/repos/%s/%s/branches/%s",
		url.PathEscape(owner),
		url.PathEscape(repo),
		url.PathEscape(branch),
	)
	if err := f.doJSON(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, err
	}

	result := payload.toBranch()
	return &result, nil
}

// ListTreePaths returns every blob path at a ref.
func (f *Forgejo) ListTreePaths(ctx context.Context, owner, repo, ref string) ([]string, error) {
	listing, err := f.ListTree(ctx, owner, repo, ref)
	if err != nil {
		return nil, err
	}
	return listing.Paths, nil
}

// forgejoTreePageSize is the page size asked of the git trees API; servers
// cap it at their own maximum, which the loop tolerates.
const forgejoTreePageSize = 1000

// ListTree pages through the recursive git trees API (Forgejo and Gitea),
// blobs only. More than maxTreeListingFiles entries returns truncated.
func (f *Forgejo) ListTree(ctx context.Context, owner, repo, ref string) (*TreeListing, error) {
	listing := &TreeListing{Paths: make([]string, 0)}
	seen := 0
	for page := 1; ; page++ {
		path := fmt.Sprintf(
			"/api/v1/repos/%s/%s/git/trees/%s?recursive=true&per_page=%d&page=%d",
			url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(ref), forgejoTreePageSize, page,
		)
		var payload struct {
			Tree []struct {
				Path string `json:"path"`
				Type string `json:"type"`
			} `json:"tree"`
			Truncated  bool `json:"truncated"`
			TotalCount int  `json:"total_count"`
		}
		request, err := f.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		status, err := f.doWithStatus(request, &payload)
		if status == http.StatusNotFound {
			return nil, ErrFileNotFound
		}
		if err != nil {
			return nil, err
		}
		for _, entry := range payload.Tree {
			if entry.Type == "blob" {
				listing.Paths = append(listing.Paths, entry.Path)
			}
		}
		seen += len(payload.Tree)
		// Gitea's paginated trees set truncated when more pages remain; the
		// listing ends on the first page that is not truncated.
		if !payload.Truncated || len(payload.Tree) == 0 || (payload.TotalCount > 0 && seen >= payload.TotalCount) {
			return listing, nil
		}
		if len(listing.Paths) >= maxTreeListingFiles {
			listing.Truncated = true
			return listing, nil
		}
	}
}

func (f *Forgejo) GetFileContent(ctx context.Context, owner, repo, filePath, ref string) ([]byte, error) {
	contentPath, err := checkedContentPath(filePath)
	if err != nil {
		return nil, err
	}
	requestPath := fmt.Sprintf("/api/v1/repos/%s/%s/contents/%s?ref=%s", url.PathEscape(owner), url.PathEscape(repo), contentPath, url.QueryEscape(ref))
	request, err := f.newRequest(ctx, http.MethodGet, requestPath, nil)
	if err != nil {
		return nil, err
	}

	var payload forgejoContentFile
	status, err := f.doWithStatus(request, &payload)
	if status == http.StatusNotFound {
		return nil, ErrFileNotFound
	}
	if err != nil {
		return nil, err
	}

	decoded, err := decodeBase64Content(payload.Content)
	if err != nil {
		return nil, fmt.Errorf("decode forgejo file content: %w", err)
	}
	return decoded, nil
}

func (f *Forgejo) CreateOrUpdateFile(ctx context.Context, owner, repo, filePath, branch, message string, content []byte) error {
	sha, err := f.lookupContentSHA(ctx, owner, repo, filePath, branch)
	if err != nil {
		return err
	}

	payload := map[string]string{
		"branch":  branch,
		"content": base64.StdEncoding.EncodeToString(content),
		"message": message,
	}
	method := http.MethodPost
	if sha != "" {
		method = http.MethodPut
		payload["sha"] = sha
	}

	contentPath, err := checkedContentPath(filePath)
	if err != nil {
		return err
	}
	requestPath := fmt.Sprintf("/api/v1/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), contentPath)
	return f.doJSON(ctx, method, requestPath, payload, nil)
}

func (f *Forgejo) CreateBranch(ctx context.Context, owner, repo, branch, fromSHA string) error {
	requestPath := fmt.Sprintf("/api/v1/repos/%s/%s/branches", url.PathEscape(owner), url.PathEscape(repo))
	return f.doJSON(ctx, http.MethodPost, requestPath, map[string]string{
		"new_branch_name": branch,
		"old_branch_name": fromSHA,
	}, nil)
}

func (f *Forgejo) CreatePullRequest(ctx context.Context, owner, repo string, opts CreatePROptions) (*PullRequest, error) {
	requestPath := fmt.Sprintf("/api/v1/repos/%s/%s/pulls", url.PathEscape(owner), url.PathEscape(repo))
	var payload forgejoPullRequestResource
	if err := f.doJSON(ctx, http.MethodPost, requestPath, map[string]string{
		"title": opts.Title,
		"body":  opts.Body,
		"head":  opts.Head,
		"base":  opts.Base,
	}, &payload); err != nil {
		return nil, err
	}
	return &PullRequest{Number: payload.Number, Title: payload.Title, HTMLURL: payload.HTMLURL}, nil
}

func (f *Forgejo) CreateCommitStatus(ctx context.Context, owner, repo, sha string, status CommitStatus) error {
	payload := map[string]string{
		"state":       status.State,
		"context":     status.Context,
		"target_url":  status.TargetURL,
		"description": status.Description,
	}

	path := fmt.Sprintf(
		"/api/v1/repos/%s/%s/statuses/%s",
		url.PathEscape(owner),
		url.PathEscape(repo),
		url.PathEscape(sha),
	)

	return f.doJSON(ctx, http.MethodPost, path, payload, nil)
}

// HasWebhookSecret reports whether webhook payloads can be verified.
func (f *Forgejo) HasWebhookSecret() bool { return f.webhookSecret != "" }

func (f *Forgejo) ValidateWebhookPayload(r *http.Request, secret string) ([]byte, error) {
	activeSecret := secret
	if activeSecret == "" {
		activeSecret = f.webhookSecret
	}
	if activeSecret == "" {
		return nil, fmt.Errorf("forgejo: %w", ErrWebhookSecretNotConfigured)
	}

	payload, err := ReadWebhookPayload(r, "forgejo")
	if err != nil {
		return nil, err
	}

	signature := r.Header.Get("X-Gitea-Signature")
	if signature == "" {
		return nil, errors.New("forgejo webhook signature missing")
	}

	expectedMAC := hmac.New(sha256.New, []byte(activeSecret))
	if _, err := expectedMAC.Write(payload); err != nil {
		return nil, fmt.Errorf("hash forgejo webhook payload: %w", err)
	}
	expected := expectedMAC.Sum(nil)

	provided, err := hex.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("decode forgejo webhook signature: %w", err)
	}
	if !hmac.Equal(provided, expected) {
		return nil, errors.New("forgejo webhook signature mismatch")
	}

	return payload, nil
}

func (f *Forgejo) ParseWebhookEvent(eventType string, payload []byte) (WebhookEvent, error) {
	switch eventType {
	case "push":
		var event forgejoPushEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode forgejo push event: %w", err)
		}
		return PushEvent{
			Ref:    event.Ref,
			Before: event.Before,
			After:  event.After,
			Repo:   event.Repository.toRepository(),
			Sender: event.Sender.toUserInfo(),
		}, nil
	case "workflow_run", "action_run":
		var event struct {
			Action      string            `json:"action"`
			Repository  forgejoRepository `json:"repository"`
			WorkflowRun struct {
				ID         int64  `json:"id"`
				HeadSHA    string `json:"head_sha"`
				HeadBranch string `json:"head_branch"`
				RunAttempt int    `json:"run_attempt"`
				Conclusion string `json:"conclusion"`
				Status     string `json:"status"`
			} `json:"workflow_run"`
		}
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode forgejo workflow_run event: %w", err)
		}
		if !strings.EqualFold(event.WorkflowRun.Status, "completed") && !strings.EqualFold(event.Action, "completed") {
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
		var event forgejoPullRequestEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode forgejo pull request event: %w", err)
		}
		return PullRequestEvent{
			Action:       event.Action,
			Merged:       event.PullRequest.Merged,
			Number:       event.Number,
			Title:        event.PullRequest.Title,
			SourceBranch: event.PullRequest.Head.Ref,
			TargetBranch: event.PullRequest.Base.Ref,
			HeadSHA:      event.PullRequest.Head.SHA,
			Repo:         event.Repository.toRepository(),
		}, nil
	case "release":
		var event forgejoReleaseEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, fmt.Errorf("decode forgejo release event: %w", err)
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
	default:
		return nil, fmt.Errorf("%w: forgejo webhook event %q", ErrUnsupportedWebhookEvent, eventType)
	}
}

func (f *Forgejo) OAuth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     f.clientID,
		ClientSecret: f.clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  f.apiURL + "/login/oauth/authorize",
			TokenURL: f.apiURL + "/login/oauth/access_token",
		},
	}
}

func (f *Forgejo) UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	if token == nil || token.AccessToken == "" {
		return nil, errors.New("forgejo user info requires access token")
	}

	request, err := f.newRequest(ctx, http.MethodGet, "/api/v1/user", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "token "+token.AccessToken)

	var payload forgejoUser
	if err := f.do(request, &payload); err != nil {
		return nil, err
	}

	user := payload.toUserInfo()
	return &user, nil
}

// AccountLogin returns the Forgejo login of the token's user, the name a
// sign-in allowlist matches against.
func (f *Forgejo) AccountLogin(ctx context.Context, token *oauth2.Token) (string, error) {
	if token == nil || token.AccessToken == "" {
		return "", errors.New("forgejo account login requires access token")
	}
	request, err := f.newRequest(ctx, http.MethodGet, "/api/v1/user", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "token "+token.AccessToken)
	var payload forgejoUser
	if err := f.do(request, &payload); err != nil {
		return "", err
	}
	return strings.TrimSpace(payload.Login), nil
}

// ComparesPathsOnly: Forgejo's compare API has no hunks.
func (f *Forgejo) ComparesPathsOnly() bool { return true }

// ComparePatch lists the files changed between base and head through the
// compare API (Forgejo and Gitea 1.20+), which reports files per commit and
// no hunks: the result is PathsOnly. A file's last status across the commits
// wins (added then removed = removed). An instance without the endpoint
// answers 404, read as "cannot compare" rather than as a failure.
func (f *Forgejo) ComparePatch(ctx context.Context, owner, repo, base, head string) (*PatchDiff, error) {
	path := fmt.Sprintf("/api/v1/repos/%s/%s/compare/%s...%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(base), url.PathEscape(head))
	request, err := f.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var payload struct {
		TotalCommits int `json:"total_commits"`
		Commits      []struct {
			Files []struct {
				Filename string `json:"filename"`
				Status   string `json:"status"`
			} `json:"files"`
		} `json:"commits"`
	}
	status, err := f.doWithStatus(request, &payload)
	if status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Commits come newest first; replay oldest first so the last status wins.
	order := make([]string, 0)
	statuses := map[string]string{}
	for i := len(payload.Commits) - 1; i >= 0; i-- {
		for _, file := range payload.Commits[i].Files {
			name := strings.TrimSpace(file.Filename)
			if name == "" {
				continue
			}
			if _, seen := statuses[name]; !seen {
				order = append(order, name)
			}
			statuses[name] = file.Status
		}
	}
	diff := &PatchDiff{
		Files:     make([]PatchFile, 0, len(order)),
		PathsOnly: true,
		Truncated: payload.TotalCommits > len(payload.Commits),
	}
	for _, name := range order {
		status := "modified"
		switch statuses[name] {
		case "added":
			status = "added"
		case "removed", "deleted":
			status = "removed"
		}
		diff.Files = append(diff.Files, PatchFile{Path: name, Status: status})
	}
	return diff, nil
}

func (f *Forgejo) ListUserAccess(context.Context, *oauth2.Token) (UserAccess, error) {
	return UserAccess{}, nil
}

func (f *Forgejo) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	endpoint := f.apiURL + path

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal forgejo request body: %w", err)
		}
		reader = bytes.NewReader(payload)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("create forgejo request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if f.token != "" {
		request.Header.Set("Authorization", "token "+f.token)
	}

	return request, nil
}

func (f *Forgejo) doJSON(ctx context.Context, method, path string, body any, out any) error {
	request, err := f.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}

	return f.do(request, out)
}

func (f *Forgejo) do(request *http.Request, out any) error {
	_, err := f.doWithStatus(request, out)
	return err
}

func (f *Forgejo) doWithStatus(request *http.Request, out any) (int, error) {
	response, err := f.httpClient.Do(request)
	if err != nil {
		return 0, fmt.Errorf("perform forgejo request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return response.StatusCode, fmt.Errorf("forgejo api %s: %s", request.URL.Path, message)
	}

	if out == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode, nil
	}

	if err := json.NewDecoder(LimitResponse(response.Body)).Decode(out); err != nil {
		return response.StatusCode, fmt.Errorf("decode forgejo response: %w", err)
	}

	return response.StatusCode, nil
}

func (f *Forgejo) lookupContentSHA(ctx context.Context, owner, repo, filePath, ref string) (string, error) {
	contentPath, err := checkedContentPath(filePath)
	if err != nil {
		return "", err
	}
	requestPath := fmt.Sprintf("/api/v1/repos/%s/%s/contents/%s?ref=%s", url.PathEscape(owner), url.PathEscape(repo), contentPath, url.QueryEscape(ref))
	request, err := f.newRequest(ctx, http.MethodGet, requestPath, nil)
	if err != nil {
		return "", err
	}

	var payload forgejoContentFile
	status, err := f.doWithStatus(request, &payload)
	if status == http.StatusNotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return payload.SHA, nil
}

// Forgejo/Gitea API types

type forgejoRepository struct {
	ID            int64  `json:"id"`
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

type forgejoContentFile struct {
	SHA      string `json:"sha"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type forgejoPullRequestResource struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
}

func (r forgejoRepository) toRepository() Repository {
	return Repository{
		ProviderID:    strconv.FormatInt(r.ID, 10),
		Owner:         r.Owner.Login,
		Name:          r.Name,
		FullName:      r.FullName,
		DefaultBranch: r.DefaultBranch,
		Private:       r.Private,
		CloneURL:      r.CloneURL,
		HTMLURL:       r.HTMLURL,
	}
}

type forgejoBranch struct {
	Name   string `json:"name"`
	Commit struct {
		ID string `json:"id"`
	} `json:"commit"`
	Protected bool `json:"protected"`
}

func (b forgejoBranch) toBranch() Branch {
	return Branch{
		Name:      b.Name,
		SHA:       b.Commit.ID,
		Protected: b.Protected,
	}
}

type forgejoUser struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Login     string `json:"login"`
	FullName  string `json:"full_name"`
	AvatarURL string `json:"avatar_url"`
}

func (u forgejoUser) toUserInfo() UserInfo {
	displayName := u.FullName
	if displayName == "" {
		displayName = u.Login
	}

	return UserInfo{
		ProviderID:  strconv.FormatInt(u.ID, 10),
		Email:       u.Email,
		DisplayName: displayName,
		AvatarURL:   u.AvatarURL,
	}
}

type forgejoPushEvent struct {
	Ref        string            `json:"ref"`
	Before     string            `json:"before"`
	After      string            `json:"after"`
	Repository forgejoRepository `json:"repository"`
	Sender     forgejoUser       `json:"sender"`
}

// Gitea/Forgejo release webhook payload. Gitea's release object exposes the
// release page as html_url; older versions only carry the API url, in which
// case the link is simply absent.
type forgejoReleaseEvent struct {
	Action  string `json:"action"`
	Release struct {
		TagName     string     `json:"tag_name"`
		Name        string     `json:"name"`
		HTMLURL     string     `json:"html_url"`
		Draft       bool       `json:"draft"`
		Prerelease  bool       `json:"prerelease"`
		PublishedAt *time.Time `json:"published_at"`
	} `json:"release"`
	Repository forgejoRepository `json:"repository"`
	Sender     forgejoUser       `json:"sender"`
}

type forgejoPullRequestEvent struct {
	Action      string            `json:"action"`
	Number      int               `json:"number"`
	Repository  forgejoRepository `json:"repository"`
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

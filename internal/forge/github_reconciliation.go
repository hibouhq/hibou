package forge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	reconciliationPageLimit = 100
	// Bump when a reader needs additional projected fields on a cached 304.
	reconciliationCacheVersion  = 1
	reconciliationPageBytes     = 16 << 20
	reconciliationTransferBytes = 64 << 20
	reconciliationRetainedBytes = 16 << 20
)

func (g *GitHub) InvalidateInstallationCredentials() {
	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()
	clear(g.ownerTokens)
	clear(g.ownerInstallations)
}

func (g *GitHub) readObservation(ctx context.Context, owner, path string, out any) (string, error) {
	request, err := g.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	if err := g.authorizeForOwner(ctx, request, owner); err != nil {
		return "", err
	}
	return g.readAuthorizedObservation(ctx, request, path, out)
}

func (g *GitHub) readAuthorizedObservation(ctx context.Context, request *http.Request, cacheKey string, out any) (string, error) {
	var cache ResponseCache
	session, _ := ctx.Value(responseCacheKey{}).(*responseCacheSession)
	if session != nil {
		cache = session.entries
		session.used[cacheKey] = true
	}
	cached, ok := cache[cacheKey]
	ok = ok && cached.Version == reconciliationCacheVersion
	if ok && cached.ETag != "" {
		request.Header.Set("If-None-Match", cached.ETag)
	}
	resp, err := g.sendRequest(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		if !ok {
			return "", errors.New("github returned 304 without a cached observation")
		}
		if session != nil {
			session.retained += len(cached.Body)
			if session.retained > reconciliationRetainedBytes {
				return "", errors.New("GitHub observation exceeds retained metadata budget")
			}
		}
		return cached.Next, json.Unmarshal(cached.Body, out)
	}
	if resp.StatusCode != http.StatusOK {
		return "", g.responseError(request, resp)
	}
	limit := reconciliationPageBytes
	if session != nil {
		limit = min(limit, reconciliationTransferBytes-session.received)
	}
	if limit < 0 {
		return "", errors.New("GitHub observation exceeds transfer budget")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return "", err
	}
	if len(body) > limit {
		return "", errors.New("GitHub observation exceeds page or cumulative transfer budget")
	}
	if session != nil {
		session.received += len(body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return "", fmt.Errorf("decode github observation: %w", err)
	}
	next, err := g.observationNextPage(resp, request)
	if err != nil {
		return "", err
	}
	if cache != nil {
		projected, err := json.Marshal(out)
		if err != nil {
			return "", err
		}
		session.retained += len(projected)
		if session.retained > reconciliationRetainedBytes {
			return "", errors.New("GitHub observation exceeds retained metadata budget")
		}
		cache[cacheKey] = CachedResponse{Version: reconciliationCacheVersion, ETag: resp.Header.Get("ETag"), Body: projected, Next: next}
	}

	return next, nil
}

func (g *GitHub) installationInventoryToken(ctx context.Context, installationID int64) (string, error) {
	key := fmt.Sprintf("inventory:%d", installationID)
	g.tokenMu.Lock()
	cached, ok := g.ownerTokens[key]
	g.tokenMu.Unlock()
	if ok && time.Until(cached.expiresAt) > 2*time.Minute {
		return cached.value, nil
	}
	token, err := g.createInstallationTokenWith(ctx, installationID, &installationTokenRequest{Permissions: map[string]string{"metadata": "read"}})
	if err != nil {
		return "", err
	}
	expires := token.ExpiresAt
	if bound := time.Now().Add(installationCacheTTL); bound.Before(expires) {
		expires = bound
	}
	g.tokenMu.Lock()
	g.ownerTokens[key] = ownerToken{value: token.Token, expiresAt: expires}
	g.tokenMu.Unlock()
	return token.Token, nil
}

func (g *GitHub) observationNextPage(response *http.Response, request *http.Request) (string, error) {
	next := nextPagePath(response)
	if next == "" {
		return "", nil
	}
	parsed, err := url.Parse(next)
	if err != nil {
		return "", err
	}
	if parsed.Path != request.URL.Path {
		return "", errors.New("github pagination changed resource path")
	}
	base, err := url.Parse(g.apiURL)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(next, strings.TrimRight(base.Path, "/")), nil
}

func readGitHubPages[T any](ctx context.Context, g *GitHub, owner, path string) ([]T, error) {
	var all []T
	seen := map[string]bool{}
	for page := 0; path != ""; page++ {
		if page >= reconciliationPageLimit || seen[path] {
			return nil, errors.New("github listing incomplete: pagination limit or cycle")
		}
		seen[path] = true
		var rows []T
		next, err := g.readObservation(ctx, owner, path, &rows)
		if err != nil {
			return nil, err
		}
		all = append(all, rows...)
		path = next
	}
	return all, nil
}

func repoReadPath(owner, repo, resource string) string {
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/" + resource
}

func (g *GitHub) ReadRefs(ctx context.Context, owner, repo string) ([]RefObservation, error) {
	branches, err := readGitHubPages[githubBranch](ctx, g, owner, repoReadPath(owner, repo, "branches?per_page=100"))
	if err != nil {
		return nil, err
	}
	tags, err := readGitHubPages[struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}](ctx, g, owner, repoReadPath(owner, repo, "tags?per_page=100"))
	if err != nil {
		return nil, err
	}
	refs := make([]RefObservation, 0, len(branches)+len(tags))
	for _, branch := range branches {
		refs = append(refs, RefObservation{Name: branch.Name, SHA: branch.Commit.SHA})
	}
	for _, tag := range tags {
		refs = append(refs, RefObservation{Name: tag.Name, SHA: tag.Commit.SHA, Tag: true})
	}
	return refs, nil
}

type githubObservedPR struct {
	Number    int        `json:"number"`
	Title     string     `json:"title"`
	State     string     `json:"state"`
	UpdatedAt time.Time  `json:"updated_at"`
	ClosedAt  *time.Time `json:"closed_at"`
	MergedAt  *time.Time `json:"merged_at"`
	Head      struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"base"`
}

func (p githubObservedPR) observation() PullRequestEvent {
	action := "opened"
	if p.State == "closed" {
		action = "closed"
	}
	return PullRequestEvent{Number: p.Number, Title: p.Title, Action: action,
		Merged: p.MergedAt != nil, SourceBranch: p.Head.Ref, TargetBranch: p.Base.Ref,
		HeadSHA: p.Head.SHA, BaseSHA: p.Base.SHA, UpdatedAt: p.UpdatedAt,
		ClosedAt: p.ClosedAt, MergedAt: p.MergedAt}
}

func (g *GitHub) ReadOpenPullRequests(ctx context.Context, owner, repo string) ([]PullRequestEvent, error) {
	rows, err := readGitHubPages[githubObservedPR](ctx, g, owner, repoReadPath(owner, repo, "pulls?state=open&per_page=100"))
	if err != nil {
		return nil, err
	}
	result := make([]PullRequestEvent, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.observation())
	}
	return result, nil
}

func (g *GitHub) ReadPullRequest(ctx context.Context, owner, repo string, number int) (PullRequestEvent, error) {
	var row githubObservedPR
	_, err := g.readObservation(ctx, owner, repoReadPath(owner, repo, fmt.Sprintf("pulls/%d", number)), &row)
	return row.observation(), err
}

func (g *GitHub) ReadReleases(ctx context.Context, owner, repo string) ([]ReleaseObservation, error) {
	rows, err := readGitHubPages[struct {
		ID          int64      `json:"id"`
		Tag         string     `json:"tag_name"`
		Name        string     `json:"name"`
		URL         string     `json:"html_url"`
		Draft       bool       `json:"draft"`
		Prerelease  bool       `json:"prerelease"`
		PublishedAt *time.Time `json:"published_at"`
		UpdatedAt   time.Time  `json:"updated_at"`
	}](ctx, g, owner, repoReadPath(owner, repo, "releases?per_page=100"))
	if err != nil {
		return nil, err
	}
	result := make([]ReleaseObservation, 0, len(rows))
	for _, row := range rows {
		if row.Draft {
			continue
		}
		if row.ID <= 0 || strings.TrimSpace(row.Tag) == "" {
			return nil, errors.New("GitHub release observation omitted immutable id or tag")
		}
		result = append(result, ReleaseObservation{ID: strconv.FormatInt(row.ID, 10), UpdatedAt: row.UpdatedAt,
			Event: ReleaseEvent{Action: "published", TagName: row.Tag, Name: row.Name, HTMLURL: row.URL,
				Prerelease: row.Prerelease, PublishedAt: row.PublishedAt}})
	}
	return result, nil
}

func (g *GitHub) ReadWorkflowRun(ctx context.Context, owner, repo, id string) (WorkflowRun, error) {
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return WorkflowRun{}, errors.New("invalid GitHub workflow run id")
	}
	var row struct {
		ID         int64  `json:"id"`
		Attempt    int    `json:"run_attempt"`
		SHA        string `json:"head_sha"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
	}
	_, err := g.readObservation(ctx, owner, repoReadPath(owner, repo, "actions/runs/"+id), &row)
	if err == nil && (strconv.FormatInt(row.ID, 10) != id || row.Attempt <= 0 || row.SHA == "" || row.Status == "") {
		return WorkflowRun{}, errors.New("GitHub workflow observation omitted or mismatched run identity")
	}
	return WorkflowRun{ID: strconv.FormatInt(row.ID, 10), Attempt: strconv.Itoa(row.Attempt), SHA: row.SHA, Status: row.Status, Conclusion: row.Conclusion}, err
}

func (g *GitHub) sendRequest(request *http.Request) (*http.Response, error) {
	g.retryMu.Lock()
	until := g.retryAt
	g.retryMu.Unlock()
	if time.Now().Before(until) {
		return nil, &APIError{Status: http.StatusTooManyRequests, Path: request.URL.Path, RetryAt: until}
	}
	response, err := g.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("perform github request: %w", err)
	}
	if response.Header.Get("X-RateLimit-Remaining") == "0" {
		if epoch, err := strconv.ParseInt(response.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			g.retryMu.Lock()
			if until := time.Unix(epoch, 0); until.After(g.retryAt) {
				g.retryAt = until
			}
			g.retryMu.Unlock()
		}
	}
	return response, nil
}

func (g *GitHub) responseError(request *http.Request, response *http.Response) error {
	retry := time.Time{}
	now := time.Now()
	var detail struct {
		Message string `json:"message"`
	}
	// Only classify known reasons; never expose response bodies in settings.
	_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&detail)
	if value := response.Header.Get("Retry-After"); value != "" {
		if seconds, err := strconv.Atoi(value); err == nil {
			retry = now.Add(time.Duration(seconds) * time.Second)
		} else if date, err := http.ParseTime(value); err == nil {
			retry = date
		}
	}
	if response.Header.Get("X-RateLimit-Remaining") == "0" {
		if epoch, err := strconv.ParseInt(response.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && time.Unix(epoch, 0).After(retry) {
			retry = time.Unix(epoch, 0)
		}
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(detail.Message), "rate limit") {
		// A secondary limit may omit reset headers. A conservative cooldown
		// also bounds repeated permission-denied requests.
		if retry.IsZero() {
			retry = now.Add(time.Minute)
		}
	}
	if !retry.IsZero() {
		g.retryMu.Lock()
		if retry.After(g.retryAt) {
			g.retryAt = retry
		}
		g.retryMu.Unlock()
	}
	return &APIError{Status: response.StatusCode, Path: request.URL.Path, RetryAt: retry,
		IntegrationDenied: detail.Message == "Resource not accessible by integration"}
}

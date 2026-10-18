package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// SupportsCheckRuns reports whether this provider can publish a native GitHub
// check run. Check runs require a GitHub App installation token with the
// `checks:write` permission, so they are only available in App mode. In OAuth-only
// mode the gatePublisher falls back to the commit status.
func (g *GitHub) SupportsCheckRuns() bool {
	return g.isAppMode()
}

type githubCheckRunResource struct {
	ID int64 `json:"id"`
}

// CreateOrUpdateCheckRun publishes the gate outcome as a GitHub check run on the
// head SHA, idempotently: if a check run with the same name already exists on the
// commit it is updated in place (PATCH), otherwise a new one is created (POST).
// Returns the check run id as a string so callers can persist it.
func (g *GitHub) CreateOrUpdateCheckRun(ctx context.Context, owner, repo string, run CheckRun) (string, error) {
	if !g.isAppMode() {
		return "", errors.New("check runs require GitHub App credentials (HIBOU_FORGE_N_APP_ID / HIBOU_FORGE_N_PRIVATE_KEY)")
	}
	token, err := g.scopedInstallationToken(ctx, owner, TokenScope{Repo: repo, Permissions: map[string]string{"checks": "write"}})
	if err != nil {
		return "", err
	}

	output := map[string]any{
		"title":   run.Title,
		"summary": run.Summary,
	}
	if annotations := githubAnnotations(run.Annotations); len(annotations) > 0 {
		output["annotations"] = annotations
	}
	payload := map[string]any{
		"name":     run.Name,
		"head_sha": run.HeadSHA,
		"output":   output,
	}
	// An empty conclusion means "still working": GitHub renders it as a yellow
	// in-progress check, which later transitions to success/failure/neutral on
	// the next update. Sending conclusion:"" with status:completed is rejected.
	if strings.TrimSpace(run.Conclusion) == "" {
		payload["status"] = "in_progress"
	} else {
		payload["status"] = "completed"
		payload["conclusion"] = run.Conclusion
	}
	if strings.TrimSpace(run.DetailsURL) != "" {
		payload["details_url"] = run.DetailsURL
	}

	existingID, err := g.findCheckRunID(ctx, token, owner, repo, run.HeadSHA, run.Name)
	if err != nil {
		return "", err
	}

	var (
		method string
		path   string
	)
	if existingID != 0 {
		method = http.MethodPatch
		path = fmt.Sprintf("/repos/%s/%s/check-runs/%d", url.PathEscape(owner), url.PathEscape(repo), existingID)
	} else {
		method = http.MethodPost
		path = fmt.Sprintf("/repos/%s/%s/check-runs", url.PathEscape(owner), url.PathEscape(repo))
	}

	req, err := g.newRequest(ctx, method, path, payload)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", githubBearerPrefix+token)

	var result githubCheckRunResource
	if _, err := g.doWithStatus(req, &result); err != nil {
		return "", fmt.Errorf("create/update check run: %w", err)
	}
	return strconv.FormatInt(result.ID, 10), nil
}

// githubAnnotations maps hibou's inline annotations to GitHub's Checks API shape.
// annotation_level must be one of notice|warning|failure.
func githubAnnotations(annotations []CheckRunAnnotation) []map[string]any {
	if len(annotations) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(annotations))
	for _, a := range annotations {
		if strings.TrimSpace(a.Path) == "" || a.StartLine <= 0 {
			continue
		}
		level := a.Level
		switch level {
		case "notice", "warning", "failure":
		default:
			level = "notice"
		}
		end := a.EndLine
		if end < a.StartLine {
			end = a.StartLine
		}
		annotation := map[string]any{
			"path":             a.Path,
			"start_line":       a.StartLine,
			"end_line":         end,
			"annotation_level": level,
			"message":          a.Message,
		}
		if strings.TrimSpace(a.Title) != "" {
			annotation["title"] = a.Title
		}
		out = append(out, annotation)
	}
	return out
}

// findCheckRunID returns the id of an existing check run with the given name on
// the commit, or 0 when none exists.
func (g *GitHub) findCheckRunID(ctx context.Context, token, owner, repo, sha, name string) (int64, error) {
	path := fmt.Sprintf(
		"/repos/%s/%s/commits/%s/check-runs?check_name=%s&per_page=100",
		url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(sha), url.QueryEscape(name),
	)
	req, err := g.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", githubBearerPrefix+token)

	var payload struct {
		CheckRuns []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"check_runs"`
	}
	if _, err := g.doWithStatus(req, &payload); err != nil {
		return 0, fmt.Errorf("list check runs: %w", err)
	}
	for _, cr := range payload.CheckRuns {
		if cr.Name == name {
			return cr.ID, nil
		}
	}
	return 0, nil
}

// CloneToken implements CloneAuthProvider: a short-lived installation token
// usable as the password in an HTTPS clone URL, for that one repository and
// read-only. Empty outside App mode, so public repositories still clone
// unauthenticated.
func (g *GitHub) CloneToken(ctx context.Context, owner, repo string) (string, error) {
	if !g.isAppMode() {
		return "", nil
	}
	return g.scopedInstallationToken(ctx, owner, TokenScope{Repo: repo, Permissions: map[string]string{"contents": "read"}})
}

// authorizeForOwner attaches the owner's installation token when running in
// App mode. A token that cannot be minted is an error, not an anonymous
// request: an unauthenticated call sees only public data, and a caller that
// reads its answer ("file not found", "not a member") would act on what it
// was never allowed to see. Outside App mode the request stays as it is.
func (g *GitHub) authorizeForOwner(ctx context.Context, request *http.Request, owner string) error {
	if !g.isAppMode() || request == nil {
		return nil
	}
	token, err := g.scopedInstallationToken(ctx, owner, scopeForRequest(request))
	if err != nil {
		return fmt.Errorf("installation token for %q: %w", owner, err)
	}
	if token == "" {
		return fmt.Errorf("installation token for %q: empty token", owner)
	}
	request.Header.Set("Authorization", githubBearerPrefix+token)
	return nil
}

// ErrInstallationOwnerMismatch is returned when a caller bound its context to
// one forge account and then asked for another account's installation token.
var ErrInstallationOwnerMismatch = errors.New("installation token requested for an account other than the bound one")

type installationOwnerKey struct{}

// WithInstallationOwner binds ctx to one forge account: installation tokens
// minted under it are refused for any other owner. Installation tokens are
// looked up by owner string and cover the whole installation, so a caller
// acting for one tenant sets this to that tenant's account as defense in
// depth against an owner taken from tenant-controlled data (security audit
// §3.1). An empty account leaves ctx unbound.
func WithInstallationOwner(ctx context.Context, account string) context.Context {
	account = strings.ToLower(strings.TrimSpace(account))
	if account == "" {
		return ctx
	}
	return context.WithValue(ctx, installationOwnerKey{}, account)
}

func checkInstallationOwner(ctx context.Context, owner string) error {
	bound, ok := ctx.Value(installationOwnerKey{}).(string)
	if !ok || bound == "" {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(owner), bound) {
		return nil
	}
	return fmt.Errorf("%w: %q is not %q", ErrInstallationOwnerMismatch, owner, bound)
}

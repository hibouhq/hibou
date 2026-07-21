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
// mode the annotator falls back to the commit status.
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
	token, err := g.installationTokenForOwner(ctx, owner)
	if err != nil {
		return "", err
	}

	payload := map[string]any{
		"name":       run.Name,
		"head_sha":   run.HeadSHA,
		"status":     "completed",
		"conclusion": run.Conclusion,
		"output": map[string]string{
			"title":   run.Title,
			"summary": run.Summary,
		},
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

// installationTokenForOwner mints an installation access token for the App
// installation on the given account (owner).
func (g *GitHub) installationTokenForOwner(ctx context.Context, owner string) (string, error) {
	installations, err := g.listInstallations(ctx)
	if err != nil {
		return "", err
	}
	for _, installation := range installations {
		if strings.EqualFold(strings.TrimSpace(installation.Account.Login), strings.TrimSpace(owner)) {
			token, err := g.createInstallationToken(ctx, installation.ID)
			if err != nil {
				return "", err
			}
			return token.Token, nil
		}
	}
	return "", fmt.Errorf("no GitHub App installation found for owner %q", owner)
}

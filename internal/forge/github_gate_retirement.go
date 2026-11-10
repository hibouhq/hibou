package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

const retiredGateSummary = "PR reporting is not configured for this repository. Dependency monitoring does not require CI uploads. No quality-gate verdict was computed. Configure repository quality gates or a CI upload integration to enable PR reporting."

// RetirePendingGate completes only existing pending checks from this App.
// Completed verdicts and checks belonging to other Apps are left untouched.
func (g *GitHub) RetirePendingGate(ctx context.Context, owner, repo, headSHA, name string) error {
	if !g.isAppMode() {
		return g.retirePendingCommitStatus(ctx, owner, repo, headSHA, name)
	}
	token, err := g.scopedInstallationToken(ctx, owner, TokenScope{Repo: repo, Permissions: map[string]string{"checks": "write"}})
	if err != nil {
		return err
	}
	for page := 1; page <= reconciliationPageLimit; page++ {
		path := fmt.Sprintf("/repos/%s/%s/commits/%s/check-runs?check_name=%s&filter=latest&per_page=100&page=%d",
			url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(headSHA), url.QueryEscape(name), page)
		request, err := g.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", githubBearerPrefix+token)
		var payload struct {
			TotalCount int `json:"total_count"`
			CheckRuns  []struct {
				ID     int64  `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
				App    struct {
					ID int64 `json:"id"`
				} `json:"app"`
			} `json:"check_runs"`
		}
		if _, err := g.doWithStatus(request, &payload); err != nil {
			return fmt.Errorf("list pending gate checks: %w", err)
		}
		for _, run := range payload.CheckRuns {
			if run.Name != name || run.App.ID != g.appID || run.Status == "" || run.Status == "completed" {
				continue
			}
			path := fmt.Sprintf("/repos/%s/%s/check-runs/%d", url.PathEscape(owner), url.PathEscape(repo), run.ID)
			request, err := g.newRequest(ctx, http.MethodPatch, path, map[string]any{
				"status": "completed", "conclusion": "neutral",
				"output": map[string]string{"title": "Quality gate - not configured", "summary": retiredGateSummary},
			})
			if err != nil {
				return err
			}
			request.Header.Set("Authorization", githubBearerPrefix+token)
			if _, err := g.doWithStatus(request, nil); err != nil {
				return fmt.Errorf("retire pending gate check: %w", err)
			}
		}
		if page*100 >= payload.TotalCount {
			return nil
		}
	}
	return errors.New("pending gate check listing exceeds pagination limit")
}

func (g *GitHub) retirePendingCommitStatus(ctx context.Context, owner, repo, headSHA, name string) error {
	for page := 1; page <= reconciliationPageLimit; page++ {
		path := fmt.Sprintf("/repos/%s/%s/commits/%s/status?per_page=100&page=%d",
			url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(headSHA), page)
		var payload struct {
			TotalCount int `json:"total_count"`
			Statuses   []struct {
				Context string `json:"context"`
				State   string `json:"state"`
			} `json:"statuses"`
		}
		if err := g.doJSONOwner(ctx, owner, http.MethodGet, path, nil, &payload); err != nil {
			return fmt.Errorf("list pending gate statuses: %w", err)
		}
		for _, status := range payload.Statuses {
			if status.Context == name {
				if status.State != "pending" {
					return nil
				}
				// Commit statuses have no neutral state. Make the skip
				// explicit rather than claiming that an analysis passed.
				return g.CreateCommitStatus(ctx, owner, repo, headSHA, CommitStatus{
					Context: name, State: "success", Description: "Not evaluated: PR reporting is not configured",
				})
			}
		}
		if page*100 >= payload.TotalCount {
			return nil
		}
	}
	return errors.New("pending gate status listing exceeds pagination limit")
}

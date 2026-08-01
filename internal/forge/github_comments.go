package forge

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// SupportsPRComments reports whether this provider can maintain a sticky PR
// comment. Requires an App installation token, same as check runs.
func (g *GitHub) SupportsPRComments() bool {
	return g.isAppMode()
}

// UpsertPRComment creates or edits Hibou's sticky comment on the PR. GitHub's
// comment listing is paginated and needs an installation token, so it drives
// the shared helpers directly rather than upsertViaJSON.
func (g *GitHub) UpsertPRComment(ctx context.Context, owner, repo string, prNumber int, marker, body string) error {
	fullBody, err := stickyCommentBody(marker, body)
	if err != nil {
		return err
	}

	existingID, err := g.findMarkedComment(ctx, owner, repo, prNumber, marker)
	if err != nil {
		return err
	}
	if existingID != 0 {
		path := fmt.Sprintf("/repos/%s/%s/issues/comments/%d", url.PathEscape(owner), url.PathEscape(repo), existingID)
		return g.doJSONOwner(ctx, owner, http.MethodPatch, path, map[string]string{"body": fullBody}, nil)
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", url.PathEscape(owner), url.PathEscape(repo), prNumber)
	return g.doJSONOwner(ctx, owner, http.MethodPost, path, map[string]string{"body": fullBody}, nil)
}

func (g *GitHub) findMarkedComment(ctx context.Context, owner, repo string, prNumber int, marker string) (int64, error) {
	token, err := g.cachedInstallationToken(ctx, owner)
	if err != nil {
		return 0, err
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100", url.PathEscape(owner), url.PathEscape(repo), prNumber)
	for path != "" {
		req, err := g.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", githubBearerPrefix+token)
		var comments []markedComment
		resp, err := g.doWithResponse(req, &comments)
		if err != nil {
			return 0, err
		}
		if id := commentIDWithMarker(comments, marker); id != 0 {
			return id, nil
		}
		path = nextPagePath(resp)
	}
	return 0, nil
}

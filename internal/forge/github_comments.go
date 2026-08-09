package forge

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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

	existing, err := g.findMarkedComment(ctx, owner, repo, prNumber, marker)
	if err != nil {
		return err
	}
	if existing != nil {
		// Deterministic body: identical content means nothing new — skip the
		// edit so the PR timeline stops accumulating no-op "edited" entries.
		if strings.TrimSpace(existing.Body) == strings.TrimSpace(fullBody) {
			return nil
		}
		path := fmt.Sprintf("/repos/%s/%s/issues/comments/%d", url.PathEscape(owner), url.PathEscape(repo), existing.ID)
		return g.doJSONOwner(ctx, owner, http.MethodPatch, path, map[string]string{"body": fullBody}, nil)
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", url.PathEscape(owner), url.PathEscape(repo), prNumber)
	return g.doJSONOwner(ctx, owner, http.MethodPost, path, map[string]string{"body": fullBody}, nil)
}

func (g *GitHub) findMarkedComment(ctx context.Context, owner, repo string, prNumber int, marker string) (*markedComment, error) {
	token, err := g.cachedInstallationToken(ctx, owner)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100", url.PathEscape(owner), url.PathEscape(repo), prNumber)
	for path != "" {
		req, err := g.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", githubBearerPrefix+token)
		var comments []markedComment
		resp, err := g.doWithResponse(req, &comments)
		if err != nil {
			return nil, err
		}
		found := commentWithMarker(comments, marker)
		path = nextPagePath(resp)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if found != nil {
			return found, nil
		}
	}
	return nil, nil
}

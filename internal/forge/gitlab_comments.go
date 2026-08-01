package forge

import (
	"context"
	"fmt"
	"net/http"
)

// SupportsPRComments reports whether this provider can maintain a sticky MR
// comment. GitLab exposes merge-request notes on the same API as commit status.
func (g *GitLab) SupportsPRComments() bool {
	return true
}

// UpsertPRComment creates or edits Hibou's sticky note on the merge request.
func (g *GitLab) UpsertPRComment(ctx context.Context, owner, repo string, prNumber int, marker, body string) error {
	base := fmt.Sprintf("/api/v4/projects/%s/merge_requests/%d/notes", gitlabProjectID(owner, repo), prNumber)
	return upsertViaJSON(ctx, g.doJSON, commentAPI{
		list:         base + "?per_page=100",
		create:       base,
		update:       func(id int64) string { return fmt.Sprintf("%s/%d", base, id) },
		updateMethod: http.MethodPut,
	}, marker, body)
}

package forge

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// SupportsPRComments reports whether this provider can maintain a sticky PR
// comment. Forgejo/Gitea expose issue comments on the same API as commit status.
func (f *Forgejo) SupportsPRComments() bool {
	return true
}

// UpsertPRComment creates or edits Hibou's sticky comment on the PR.
func (f *Forgejo) UpsertPRComment(ctx context.Context, owner, repo string, prNumber int, marker, body string) error {
	base := fmt.Sprintf("/api/v1/repos/%s/%s/issues", url.PathEscape(owner), url.PathEscape(repo))
	return upsertViaJSON(ctx, f.doJSON, commentAPI{
		list:         fmt.Sprintf("%s/%d/comments?limit=50", base, prNumber),
		create:       fmt.Sprintf("%s/%d/comments", base, prNumber),
		update:       func(id int64) string { return fmt.Sprintf("%s/comments/%d", base, id) },
		updateMethod: http.MethodPatch,
	}, marker, body)
}

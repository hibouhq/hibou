package forge

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// markedComment is the minimal shape Hibou reads from any forge's comment
// listing to locate its own sticky comment by marker.
type markedComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

func commentWithMarker(comments []markedComment, marker string) *markedComment {
	for i := range comments {
		if strings.Contains(comments[i].Body, marker) {
			return &comments[i]
		}
	}
	return nil
}

// stickyCommentBody prepends the hidden marker so a later run can find and edit
// the same comment instead of posting a new one.
func stickyCommentBody(marker, body string) (string, error) {
	if strings.TrimSpace(marker) == "" {
		return "", errors.New("pr comment marker is required")
	}
	return marker + "\n" + body, nil
}

// commentAPI describes a forge's REST shape for its single sticky comment.
type commentAPI struct {
	list         string
	create       string
	update       func(id int64) string
	updateMethod string
}

// upsertViaJSON runs the shared find-then-create-or-update flow for forges whose
// comment API is a plain JSON list + write (Forgejo, GitLab). GitHub's listing
// needs pagination and an installation token, so it drives the shared helpers
// (markedComment, commentIDWithMarker, stickyCommentBody) directly instead.
func upsertViaJSON(
	ctx context.Context,
	doJSON func(ctx context.Context, method, path string, body, out any) error,
	api commentAPI,
	marker, body string,
) error {
	fullBody, err := stickyCommentBody(marker, body)
	if err != nil {
		return err
	}
	var comments []markedComment
	if err := doJSON(ctx, http.MethodGet, api.list, nil, &comments); err != nil {
		return err
	}
	if existing := commentWithMarker(comments, marker); existing != nil {
		// The body is deterministic now (no timestamp): identical content
		// means Hibou has nothing new to say — skip the edit so PR timelines
		// stop filling with no-op "edited" entries every reconcile pass.
		if strings.TrimSpace(existing.Body) == strings.TrimSpace(fullBody) {
			return nil
		}
		return doJSON(ctx, api.updateMethod, api.update(existing.ID), map[string]string{"body": fullBody}, nil)
	}
	return doJSON(ctx, http.MethodPost, api.create, map[string]string{"body": fullBody}, nil)
}

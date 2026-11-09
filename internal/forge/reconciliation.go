package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type RefObservation struct {
	Name string
	SHA  string
	Tag  bool
}

type ReleaseObservation struct {
	ID        string
	UpdatedAt time.Time
	Event     ReleaseEvent
}

type WorkflowRun struct {
	ID         string
	Attempt    string
	SHA        string
	Status     string
	Conclusion string
}

// Resource reads are optional capabilities, not successful no-ops on forges
// whose API cannot provide authoritative state.
type RefReader interface {
	ReadRefs(context.Context, string, string) ([]RefObservation, error)
}
type PullRequestReader interface {
	ReadOpenPullRequests(context.Context, string, string) ([]PullRequestEvent, error)
	ReadPullRequest(context.Context, string, string, int) (PullRequestEvent, error)
}
type ReleaseReader interface {
	ReadReleases(context.Context, string, string) ([]ReleaseObservation, error)
}
type WorkflowReader interface {
	ReadWorkflowRun(context.Context, string, string, string) (WorkflowRun, error)
}
type InstallationRepositoryReader interface {
	ListInstallationRepositories(context.Context, int64) ([]Repository, error)
}
type CredentialInvalidator interface {
	InvalidateInstallationCredentials()
}

type repositoryIdentityKey struct{}
type repositoryIdentity struct{ account, repository string }

func WithRepositoryIdentity(ctx context.Context, account, repository string) context.Context {
	return context.WithValue(ctx, repositoryIdentityKey{}, repositoryIdentity{account: account, repository: repository})
}

type CachedResponse struct {
	Version int             `json:"version,omitempty"`
	ETag    string          `json:"etag"`
	Body    json.RawMessage `json:"body"`
	Next    string          `json:"next,omitempty"`
}
type ResponseCache map[string]CachedResponse
type responseCacheKey struct{}
type responseCacheSession struct {
	entries  ResponseCache
	used     map[string]bool
	received int
	retained int
}

// The cache belongs to one durable reconciliation scope. Each page has its
// own validator; a first-page 304 never stands for a complete list.
func WithResponseCache(ctx context.Context, cache ResponseCache) context.Context {
	return context.WithValue(ctx, responseCacheKey{}, &responseCacheSession{entries: cache, used: map[string]bool{}})
}

// Cached bodies are only for the current full observation, not an unbounded
// history of every workflow run and closed PR the scope has ever visited.
func PruneResponseCache(ctx context.Context) {
	session, _ := ctx.Value(responseCacheKey{}).(*responseCacheSession)
	if session == nil {
		return
	}
	for path := range session.entries {
		if !session.used[path] {
			delete(session.entries, path)
		}
	}
}

type APIError struct {
	Status            int
	Path              string
	RetryAt           time.Time
	IntegrationDenied bool
}

func (e *APIError) Error() string {
	if !e.RetryAt.IsZero() {
		return fmt.Sprintf("github %s: HTTP %d; retry after %s", e.Path, e.Status, e.RetryAt.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("github %s: HTTP %d (check App permissions and repository access)", e.Path, e.Status)
}

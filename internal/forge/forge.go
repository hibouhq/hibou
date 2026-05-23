package forge

import (
	"context"
	"errors"
	"net/http"

	"golang.org/x/oauth2"
)

// Provider abstracts operations on a git forge (GitHub, Gitea/Forgejo, GitLab).
type Provider interface {
	// ID returns the provider identifier ("github", "gitea", "gitlab").
	ID() string

	// ListRepositories lists repositories accessible via the given installation/token.
	ListRepositories(ctx context.Context, opts ListReposOptions) ([]Repository, error)

	// GetRepository fetches a single repository by owner/name.
	GetRepository(ctx context.Context, owner, name string) (*Repository, error)

	// ListBranches lists branches for a repository.
	ListBranches(ctx context.Context, owner, repo string) ([]Branch, error)

	// GetBranch fetches a single branch by name.
	GetBranch(ctx context.Context, owner, repo, branch string) (*Branch, error)

	// GetFileContent fetches a file's raw content from a ref.
	GetFileContent(ctx context.Context, owner, repo, path, ref string) ([]byte, error)

	// CreateOrUpdateFile writes a file on a branch.
	CreateOrUpdateFile(ctx context.Context, owner, repo, path, branch, message string, content []byte) error

	// CreateBranch creates a branch from a base ref or SHA.
	CreateBranch(ctx context.Context, owner, repo, branch, fromSHA string) error

	// CreatePullRequest opens a pull request.
	CreatePullRequest(ctx context.Context, owner, repo string, opts CreatePROptions) (*PullRequest, error)

	// CreateCommitStatus sets a commit status (for PR feedback).
	CreateCommitStatus(ctx context.Context, owner, repo, sha string, status CommitStatus) error

	// ValidateWebhookPayload validates and returns the raw webhook payload.
	ValidateWebhookPayload(r *http.Request, secret string) ([]byte, error)

	// ParseWebhookEvent parses a webhook event from its type and payload.
	ParseWebhookEvent(eventType string, payload []byte) (WebhookEvent, error)

	// OAuth2Config returns the OAuth2 configuration for this provider.
	OAuth2Config(redirectURL string) *oauth2.Config

	// UserInfo fetches the authenticated user's info using an OAuth2 token.
	UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error)
}

type Repository struct {
	ProviderID    string
	Owner         string
	Name          string
	FullName      string
	DefaultBranch string
	Private       bool
	CloneURL      string
	HTMLURL       string
}

type Branch struct {
	Name      string
	SHA       string
	Protected bool
}

type CommitStatus struct {
	State       string
	Context     string
	TargetURL   string
	Description string
}

type CreatePROptions struct {
	Title string
	Body  string
	Head  string
	Base  string
}

type PullRequest struct {
	Number  int
	Title   string
	HTMLURL string
}

type ListReposOptions struct {
	Page    int
	PerPage int
}

type UserInfo struct {
	ProviderID  string
	Email       string
	DisplayName string
	AvatarURL   string
}

type WebhookEvent interface {
	EventType() string
}

type PushEvent struct {
	Ref    string
	Before string
	After  string
	Repo   Repository
	Sender UserInfo
}

func (PushEvent) EventType() string {
	return "push"
}

type PullRequestEvent struct {
	Action       string
	Number       int
	Title        string
	SourceBranch string
	TargetBranch string
	HeadSHA      string
	Repo         Repository
}

func (PullRequestEvent) EventType() string {
	return "pull_request"
}

var ErrNotImplemented = errors.New("forge: provider not implemented")
var ErrFileNotFound = errors.New("forge: file not found")

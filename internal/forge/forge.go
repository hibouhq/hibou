package forge

import (
	"context"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// Provider abstracts operations on a git forge (GitHub, Gitea/Forgejo, GitLab).
type Provider interface {
	// ID returns the provider identifier ("github", "gitea", "gitlab").
	ID() string

	// Installations returns App installations when supported by the provider.
	Installations(ctx context.Context) ([]Installation, error)

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

	// ListTreePaths returns every blob path in the repository tree at a ref.
	// Providers without support return nil, nil; callers must then require
	// exact paths instead of suffix-resolving tool-emitted ones.
	ListTreePaths(ctx context.Context, owner, repo, ref string) ([]string, error)

	// CreateOrUpdateFile writes a file on a branch.
	CreateOrUpdateFile(ctx context.Context, owner, repo, path, branch, message string, content []byte) error

	// CreateBranch creates a branch from a base ref or SHA.
	CreateBranch(ctx context.Context, owner, repo, branch, fromSHA string) error

	// CreatePullRequest opens a pull request.
	CreatePullRequest(ctx context.Context, owner, repo string, opts CreatePROptions) (*PullRequest, error)

	// CreateCommitStatus sets a commit status (for PR feedback).
	CreateCommitStatus(ctx context.Context, owner, repo, sha string, status CommitStatus) error

	// ComparePatch returns the changed-file line map between base and head refs
	// (a PR's target and source), used for line-level patch coverage. Providers
	// without support return nil, nil so callers degrade to file-level diffs.
	ComparePatch(ctx context.Context, owner, repo, base, head string) (*PatchDiff, error)

	// ValidateWebhookPayload validates and returns the raw webhook payload.
	ValidateWebhookPayload(r *http.Request, secret string) ([]byte, error)

	// ParseWebhookEvent parses a webhook event from its type and payload.
	ParseWebhookEvent(eventType string, payload []byte) (WebhookEvent, error)

	// OAuth2Config returns the OAuth2 configuration for this provider.
	OAuth2Config(redirectURL string) *oauth2.Config

	// UserInfo fetches the authenticated user's info using an OAuth2 token.
	UserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error)

	// ListUserAccess enumerates the authenticated user's accessible orgs/repos with forge-native
	// permission levels, using their OAuth token transiently (for login-time permission mirroring).
	// Providers without support return an empty UserAccess and nil error.
	ListUserAccess(ctx context.Context, token *oauth2.Token) (UserAccess, error)
}

type Repository struct {
	ProviderID     string
	ProviderRepoID string
	Owner          string
	Name           string
	FullName       string
	DefaultBranch  string
	Archived       bool
	Private        bool
	CloneURL       string
	HTMLURL        string
	// SizeKB is the forge-reported repository size. Zero means the provider does
	// not report it; callers must treat zero as unknown, not empty.
	SizeKB int64
}

// CloneAuthProvider is implemented by providers that can mint short-lived
// credentials for git-over-HTTPS clones. An empty token with a nil error means
// no credential is available (e.g. not running in App mode) — public
// repositories still clone without one.
type CloneAuthProvider interface {
	CloneToken(ctx context.Context, owner string) (string, error)
}

type Installation struct {
	ID          int64
	AccountName string
	AccountType string
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
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
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

type UserAccess struct {
	Orgs  []UserOrgAccess
	Repos []UserRepoAccess
}

type UserOrgAccess struct {
	AccountLogin string
	Level        string
}

type UserRepoAccess struct {
	AccountLogin   string
	ProviderRepoID string
	Owner          string
	Name           string
	FullName       string
	Level          string
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
	Merged       bool
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

// ReleaseEvent is a forge release lifecycle event (GitHub/Gitea/Forgejo
// "release", GitLab "Release Hook"), normalized across providers (ADR-024 §5).
type ReleaseEvent struct {
	Action      string
	TagName     string
	Name        string
	HTMLURL     string
	Draft       bool
	Prerelease  bool
	PublishedAt *time.Time
	Repo        Repository
	Sender      UserInfo
}

func (ReleaseEvent) EventType() string {
	return "release"
}

type InstallationEvent struct {
	Action       string
	Installation Installation
	Repositories []Repository
	Sender       UserInfo
}

func (InstallationEvent) EventType() string {
	return "installation"
}

type InstallationRepositoriesEvent struct {
	Action              string
	Installation        Installation
	RepositoriesAdded   []Repository
	RepositoriesRemoved []Repository
	Sender              UserInfo
}

func (InstallationRepositoriesEvent) EventType() string {
	return "installation_repositories"
}

type RepositoryEvent struct {
	Action      string
	Repo        Repository
	OldFullName string
	Sender      UserInfo
}

func (RepositoryEvent) EventType() string {
	return "repository"
}

var ErrNotImplemented = errors.New("forge: provider not implemented")
var ErrFileNotFound = errors.New("forge: file not found")
var ErrUnsupportedWebhookEvent = errors.New("forge: unsupported webhook event")

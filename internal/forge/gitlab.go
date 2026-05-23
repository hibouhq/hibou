package forge

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type GitLab struct {
	apiURL        string
	clientID      string
	clientSecret  string
	webhookSecret string
	httpClient    *http.Client
}

func NewGitLab(apiURL, clientID, clientSecret, webhookSecret string) *GitLab {
	if apiURL == "" {
		apiURL = "https://gitlab.com"
	}

	return &GitLab{
		apiURL:        strings.TrimRight(apiURL, "/"),
		clientID:      clientID,
		clientSecret:  clientSecret,
		webhookSecret: webhookSecret,
		httpClient:    http.DefaultClient,
	}
}

func (g *GitLab) ID() string {
	return "gitlab"
}

func (g *GitLab) ListRepositories(context.Context, ListReposOptions) ([]Repository, error) {
	return nil, ErrNotImplemented
}

func (g *GitLab) GetRepository(context.Context, string, string) (*Repository, error) {
	return nil, ErrNotImplemented
}

func (g *GitLab) ListBranches(context.Context, string, string) ([]Branch, error) {
	return nil, ErrNotImplemented
}

func (g *GitLab) GetBranch(context.Context, string, string, string) (*Branch, error) {
	return nil, ErrNotImplemented
}

func (g *GitLab) GetFileContent(context.Context, string, string, string, string) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (g *GitLab) CreateOrUpdateFile(context.Context, string, string, string, string, string, []byte) error {
	return ErrNotImplemented
}

func (g *GitLab) CreateBranch(context.Context, string, string, string, string) error {
	return ErrNotImplemented
}

func (g *GitLab) CreatePullRequest(context.Context, string, string, CreatePROptions) (*PullRequest, error) {
	return nil, ErrNotImplemented
}

func (g *GitLab) CreateCommitStatus(context.Context, string, string, string, CommitStatus) error {
	return ErrNotImplemented
}

func (g *GitLab) ValidateWebhookPayload(*http.Request, string) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (g *GitLab) ParseWebhookEvent(string, []byte) (WebhookEvent, error) {
	return nil, ErrNotImplemented
}

func (g *GitLab) OAuth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  g.apiURL + "/oauth/authorize",
			TokenURL: g.apiURL + "/oauth/token",
		},
	}
}

func (g *GitLab) UserInfo(context.Context, *oauth2.Token) (*UserInfo, error) {
	return nil, ErrNotImplemented
}

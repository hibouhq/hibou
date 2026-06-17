package repoconfig

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/forge"
)

type testForgeProvider struct {
	fileContent      []byte
	fileErr          error
	branch           *forge.Branch
	branchErr        error
	createBranchErr  error
	createFileErr    error
	createPullReqErr error
	pullRequest      *forge.PullRequest
	operations       []string
	lastCreateBranch string
	lastCreateRef    string
	lastFilePath     string
	lastFileBranch   string
	lastFileMessage  string
	lastFileContent  []byte
	lastPullRequest  forge.CreatePROptions
	providerType     string
}

func (p *testForgeProvider) ID() string {
	if p.providerType != "" {
		return p.providerType
	}
	return "github"
}
func (p *testForgeProvider) Installations(context.Context) ([]forge.Installation, error) {
	return nil, nil
}
func (p *testForgeProvider) ListRepositories(context.Context, forge.ListReposOptions) ([]forge.Repository, error) {
	return nil, forge.ErrNotImplemented
}
func (p *testForgeProvider) GetRepository(context.Context, string, string) (*forge.Repository, error) {
	return nil, forge.ErrNotImplemented
}
func (p *testForgeProvider) ListBranches(context.Context, string, string) ([]forge.Branch, error) {
	return nil, forge.ErrNotImplemented
}
func (p *testForgeProvider) GetBranch(_ context.Context, _, _, _ string) (*forge.Branch, error) {
	p.operations = append(p.operations, "GetBranch")
	if p.branchErr != nil {
		return nil, p.branchErr
	}
	if p.branch != nil {
		return p.branch, nil
	}
	return &forge.Branch{Name: "main", SHA: "abc123"}, nil
}
func (p *testForgeProvider) CreateCommitStatus(context.Context, string, string, string, forge.CommitStatus) error {
	return forge.ErrNotImplemented
}
func (p *testForgeProvider) ValidateWebhookPayload(*http.Request, string) ([]byte, error) {
	return nil, forge.ErrNotImplemented
}
func (p *testForgeProvider) ParseWebhookEvent(string, []byte) (forge.WebhookEvent, error) {
	return nil, forge.ErrNotImplemented
}
func (p *testForgeProvider) OAuth2Config(string) *oauth2.Config { return nil }
func (p *testForgeProvider) UserInfo(context.Context, *oauth2.Token) (*forge.UserInfo, error) {
	return nil, forge.ErrNotImplemented
}
func (p *testForgeProvider) ListUserAccess(context.Context, *oauth2.Token) (forge.UserAccess, error) {
	return forge.UserAccess{}, nil
}
func (p *testForgeProvider) GetFileContent(_ context.Context, _, _, _, _ string) ([]byte, error) {
	if p.fileErr != nil {
		return nil, p.fileErr
	}
	return append([]byte(nil), p.fileContent...), nil
}
func (p *testForgeProvider) CreateOrUpdateFile(_ context.Context, _, _, path, branch, message string, content []byte) error {
	p.operations = append(p.operations, "CreateOrUpdateFile")
	p.lastFilePath = path
	p.lastFileBranch = branch
	p.lastFileMessage = message
	p.lastFileContent = append([]byte(nil), content...)
	return p.createFileErr
}
func (p *testForgeProvider) CreateBranch(_ context.Context, _, _, branch, fromSHA string) error {
	p.operations = append(p.operations, "CreateBranch")
	p.lastCreateBranch = branch
	p.lastCreateRef = fromSHA
	return p.createBranchErr
}
func (p *testForgeProvider) CreatePullRequest(_ context.Context, _, _ string, opts forge.CreatePROptions) (*forge.PullRequest, error) {
	p.operations = append(p.operations, "CreatePullRequest")
	p.lastPullRequest = opts
	if p.createPullReqErr != nil {
		return nil, p.createPullReqErr
	}
	if p.pullRequest != nil {
		return p.pullRequest, nil
	}
	return &forge.PullRequest{Number: 1, Title: opts.Title, HTMLURL: "https://example.test/pr/1"}, nil
}

func TestLoadReturnsConfigWhenFileExists(t *testing.T) {
	provider := &testForgeProvider{fileContent: []byte("version: 1\n")}
	loader := NewLoader(map[string]forge.Provider{"github-main": provider}, zerolog.Nop())

	cfg, err := loader.Load(context.Background(), "github-main", "octo", "repo", "main")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Version != 1 {
		t.Fatalf("expected parsed config, got %#v", cfg)
	}
}

func TestLoadReturnsNilWhenFileNotFound(t *testing.T) {
	provider := &testForgeProvider{fileErr: forge.ErrFileNotFound}
	loader := NewLoader(map[string]forge.Provider{"github-main": provider}, zerolog.Nop())

	cfg, err := loader.Load(context.Background(), "github-main", "octo", "repo", "main")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config when file is missing, got %#v", cfg)
	}
}

func TestLoadReturnsNilOnParseErrorAndLogsWarning(t *testing.T) {
	provider := &testForgeProvider{fileContent: []byte("version: 2\n")}
	var buffer bytes.Buffer
	logger := zerolog.New(&buffer)
	loader := NewLoader(map[string]forge.Provider{"github-main": provider}, logger)

	cfg, err := loader.Load(context.Background(), "github-main", "octo", "repo", "main")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config on parse error, got %#v", cfg)
	}
	if !bytes.Contains(buffer.Bytes(), []byte("invalid repo config")) {
		t.Fatalf("expected warning log, got %q", buffer.String())
	}
	if errors.Is(provider.fileErr, forge.ErrFileNotFound) {
		t.Fatal("unexpected not found error")
	}
}

func TestLoadReturnsNilWhenFileExceedsSizeLimit(t *testing.T) {
	provider := &testForgeProvider{fileContent: bytes.Repeat([]byte("a"), maxRepoConfigBytes+1)}
	var buffer bytes.Buffer
	logger := zerolog.New(&buffer)
	loader := NewLoader(map[string]forge.Provider{"github-main": provider}, logger)

	cfg, err := loader.Load(context.Background(), "github-main", "octo", "repo", "main")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config for oversized file, got %#v", cfg)
	}
	if !bytes.Contains(buffer.Bytes(), []byte("repo config exceeds size limit")) {
		t.Fatalf("expected size limit warning, got %q", buffer.String())
	}
}

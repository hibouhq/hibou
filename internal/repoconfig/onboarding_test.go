package repoconfig

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/forge"
)

func TestCreateOnboardingPRCallsForgeMethodsInCorrectOrder(t *testing.T) {
	provider := &testForgeProvider{branch: &forge.Branch{Name: "main", SHA: "abc123"}, pullRequest: &forge.PullRequest{Number: 42, HTMLURL: "https://example.test/pr/42"}}
	service := NewOnboardingService(map[string]forge.Provider{"github-main": provider}, zerolog.Nop())

	pr, err := service.CreateOnboardingPR(context.Background(), "github-main", "octo", "repo", "main")
	if err != nil {
		t.Fatalf("CreateOnboardingPR returned error: %v", err)
	}
	if pr == nil || pr.Number != 42 {
		t.Fatalf("unexpected pull request: %#v", pr)
	}
	if want := []string{"GetBranch", "CreateBranch", "CreateOrUpdateFile", "CreatePullRequest"}; !reflect.DeepEqual(provider.operations, want) {
		t.Fatalf("unexpected operation order: got %v want %v", provider.operations, want)
	}
	if provider.lastCreateBranch != onboardingBranchName || provider.lastCreateRef != "abc123" {
		t.Fatalf("unexpected branch creation args: branch=%q ref=%q", provider.lastCreateBranch, provider.lastCreateRef)
	}
	if provider.lastFilePath != RepoConfigPath || provider.lastFileBranch != onboardingBranchName {
		t.Fatalf("unexpected file write args: path=%q branch=%q", provider.lastFilePath, provider.lastFileBranch)
	}
	if string(provider.lastFileContent) != string(DefaultYAML()) {
		t.Fatalf("unexpected file content: %q", string(provider.lastFileContent))
	}
}

func TestCreateOnboardingPRReturnsErrorIfBranchCreationFails(t *testing.T) {
	provider := &testForgeProvider{branch: &forge.Branch{Name: "main", SHA: "abc123"}, createBranchErr: errors.New("boom")}
	service := NewOnboardingService(map[string]forge.Provider{"github-main": provider}, zerolog.Nop())

	_, err := service.CreateOnboardingPR(context.Background(), "github-main", "octo", "repo", "main")
	if err == nil {
		t.Fatal("expected CreateOnboardingPR to fail")
	}
	if want := []string{"GetBranch", "CreateBranch"}; !reflect.DeepEqual(provider.operations, want) {
		t.Fatalf("unexpected operation order after failure: got %v want %v", provider.operations, want)
	}
}

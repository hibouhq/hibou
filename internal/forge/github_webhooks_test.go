package forge

import "testing"

func TestParseGitHubInstallationWebhookEvent(t *testing.T) {
	t.Parallel()

	provider := NewGitHub("", "", "")
	payload := []byte(`{"action":"created","installation":{"id":12,"account":{"login":"acme","type":"Organization"}},"repositories":[{"id":101,"name":"api","full_name":"acme/api","private":true}],"sender":{"id":7,"login":"octocat","name":"Octo Cat"}}`)

	event, err := provider.ParseWebhookEvent("installation", payload)
	if err != nil {
		t.Fatalf("ParseWebhookEvent() error = %v", err)
	}
	typed, ok := event.(InstallationEvent)
	if !ok {
		t.Fatalf("expected InstallationEvent, got %T", event)
	}
	if typed.Installation.AccountName != "acme" || len(typed.Repositories) != 1 {
		t.Fatalf("unexpected installation event payload: %#v", typed)
	}
	if typed.Repositories[0].ProviderRepoID != "101" || typed.Repositories[0].DefaultBranch != "" || typed.Repositories[0].HTMLURL != "" {
		t.Fatalf("unexpected slim repository mapping: %#v", typed.Repositories[0])
	}
}

func TestParseGitHubInstallationRepositoriesWebhookEvent(t *testing.T) {
	t.Parallel()

	provider := NewGitHub("", "", "")
	payload := []byte(`{"action":"added","installation":{"id":12,"account":{"login":"acme","type":"Organization"}},"repositories_added":[{"id":101,"name":"api","full_name":"acme/api","private":true}],"repositories_removed":[{"id":102,"name":"old","full_name":"acme/old","private":false}],"sender":{"id":7,"login":"octocat"}}`)

	event, err := provider.ParseWebhookEvent("installation_repositories", payload)
	if err != nil {
		t.Fatalf("ParseWebhookEvent() error = %v", err)
	}
	typed, ok := event.(InstallationRepositoriesEvent)
	if !ok {
		t.Fatalf("expected InstallationRepositoriesEvent, got %T", event)
	}
	if len(typed.RepositoriesAdded) != 1 || len(typed.RepositoriesRemoved) != 1 {
		t.Fatalf("unexpected installation_repositories payload: %#v", typed)
	}
	if typed.RepositoriesRemoved[0].FullName != "acme/old" {
		t.Fatalf("unexpected removed repo mapping: %#v", typed.RepositoriesRemoved[0])
	}
}

func TestParseGitHubRepositoryRenamedWebhookEvent(t *testing.T) {
	t.Parallel()

	provider := NewGitHub("", "", "")
	payload := []byte(`{"action":"renamed","repository":{"id":101,"name":"api-renamed","full_name":"acme/api-renamed","private":true,"default_branch":"main","html_url":"https://github.com/acme/api-renamed","clone_url":"https://github.com/acme/api-renamed.git","owner":{"login":"acme"}},"changes":{"repository":{"name":{"from":"api"}}},"sender":{"id":7,"login":"octocat"}}`)

	event, err := provider.ParseWebhookEvent("repository", payload)
	if err != nil {
		t.Fatalf("ParseWebhookEvent() error = %v", err)
	}
	typed, ok := event.(RepositoryEvent)
	if !ok {
		t.Fatalf("expected RepositoryEvent, got %T", event)
	}
	if typed.OldFullName != "acme/api" {
		t.Fatalf("expected old full name acme/api, got %q", typed.OldFullName)
	}
	if typed.Repo.ProviderRepoID != "101" || typed.Repo.FullName != "acme/api-renamed" {
		t.Fatalf("unexpected repository mapping: %#v", typed.Repo)
	}
}

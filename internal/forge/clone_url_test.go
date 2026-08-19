package forge

import "testing"

// The secret scanner leans on CloneURL when a repo has no mirrored URL — an
// API call there runs anonymous when token minting fails (60 req/h on GitHub),
// so the derivation must hold for both github.com and GHES shapes.
func TestGitHubCloneURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		opts        []GitHubOption
		owner, repo string
		want        string
	}{
		{"github.com default", nil, "hibouhq", "hibou-sample-project", "https://github.com/hibouhq/hibou-sample-project.git"},
		{"explicit github.com api", []GitHubOption{WithAPIURL("https://api.github.com")}, "acme", "app", "https://github.com/acme/app.git"},
		{"GHES strips /api/v3", []GitHubOption{WithAPIURL("https://ghe.corp.example/api/v3")}, "acme", "app", "https://ghe.corp.example/acme/app.git"},
		{"missing owner", nil, "", "app", ""},
		{"missing name", nil, "acme", "", ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			provider := NewGitHub("client-id", "client-secret", "webhook-secret", testCase.opts...)
			if got := provider.CloneURL(testCase.owner, testCase.repo); got != testCase.want {
				t.Fatalf("CloneURL(%q, %q) = %q, want %q", testCase.owner, testCase.repo, got, testCase.want)
			}
		})
	}
}

func TestForgejoCloneURL(t *testing.T) {
	t.Parallel()

	provider := NewForgejo("https://git.example.com/", "id", "secret", "hook")
	if got, want := provider.CloneURL("acme", "app"), "https://git.example.com/acme/app.git"; got != want {
		t.Fatalf("CloneURL = %q, want %q", got, want)
	}
	if got := provider.CloneURL("", "app"); got != "" {
		t.Fatalf("CloneURL with empty owner = %q, want empty", got)
	}
}

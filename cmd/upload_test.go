package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveUploadContextGitHubPRUsesGithubRef(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")
	t.Setenv("GITHUB_HEAD_REF", "feature/branch")
	t.Setenv("GITHUB_BASE_REF", "main")
	t.Setenv("GITHUB_RUN_ID", "99")
	t.Setenv("GITHUB_RUN_ATTEMPT", "3")
	t.Setenv("GITHUB_RUN_NUMBER", "7")
	t.Setenv("GITHUB_SERVER_URL", "https://github.example")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()

	if ctx.ref != "refs/pull/42/merge" {
		t.Fatalf("ref = %q, want refs/pull/42/merge", ctx.ref)
	}
	if ctx.prSourceBranch != "feature/branch" {
		t.Fatalf("prSourceBranch = %q, want feature/branch", ctx.prSourceBranch)
	}
	if ctx.prTargetBranch != "main" {
		t.Fatalf("prTargetBranch = %q, want main", ctx.prTargetBranch)
	}
	if ctx.prNumber != "42" {
		t.Fatalf("prNumber = %q, want 42", ctx.prNumber)
	}
	if ctx.runAttempt != "3" {
		t.Fatalf("runAttempt = %q, want 3", ctx.runAttempt)
	}
	if ctx.buildURL != "https://github.example/owner/repo/actions/runs/99" {
		t.Fatalf("buildURL = %q", ctx.buildURL)
	}
}

func TestResolveUploadContextHIBOURunAttemptOverride(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	t.Setenv("HIBOU_RUN_ATTEMPT", "5")
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()

	if ctx.runAttempt != "5" {
		t.Fatalf("runAttempt = %q, want 5", ctx.runAttempt)
	}
}

func TestResolveUploadContextFlagOverridesHIBOUAndCI(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "ci-sha")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("HIBOU_REF", "refs/heads/override")
	t.Setenv("HIBOU_SHA", "hibou-sha")
	t.Setenv("HIBOU_PR_SOURCE_BRANCH", "hibou-source")
	t.Cleanup(resetUploadFlags)

	uploadRef = "refs/tags/v2.0.0"
	uploadCommitSHA = "flag-sha"

	ctx := resolveUploadContext()

	if ctx.ref != "refs/tags/v2.0.0" {
		t.Fatalf("ref = %q, want refs/tags/v2.0.0", ctx.ref)
	}
	if ctx.commitSHA != "flag-sha" {
		t.Fatalf("commitSHA = %q, want flag-sha", ctx.commitSHA)
	}
	if ctx.prSourceBranch != "hibou-source" {
		t.Fatalf("prSourceBranch = %q, want hibou-source", ctx.prSourceBranch)
	}
}

func TestResolveUploadContextGitLabRequiresGitlabCITrue(t *testing.T) {
	t.Setenv("CI_COMMIT_SHA", "abc123")
	t.Setenv("CI_COMMIT_REF_NAME", "main")
	t.Setenv("CI_PIPELINE_ID", "123")
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()
	if ctx != (uploadCIContext{}) {
		t.Fatalf("ctx = %+v, want empty", ctx)
	}

	t.Setenv("GITLAB_CI", "true")
	ctx = resolveUploadContext()
	if ctx.commitSHA != "abc123" || ctx.ref != "main" || ctx.runID != "123" {
		t.Fatalf("ctx = %+v, want gitlab values", ctx)
	}
}

func TestResolveUploadContextGitLabTagUsesTagRef(t *testing.T) {
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_COMMIT_SHA", "abc123")
	t.Setenv("CI_COMMIT_REF_NAME", "release")
	t.Setenv("CI_COMMIT_TAG", "v1.2.3")
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()

	if ctx.ref != "refs/tags/v1.2.3" {
		t.Fatalf("ref = %q, want refs/tags/v1.2.3", ctx.ref)
	}
	if ctx.tag != "v1.2.3" {
		t.Fatalf("tag = %q, want v1.2.3", ctx.tag)
	}
}

func TestDetectGitHubFamilyTagUsesRefNameTag(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REF", "refs/tags/v3.1.4")
	t.Setenv("GITHUB_REF_NAME", "v3.1.4")
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()
	if ctx.tag != "v3.1.4" {
		t.Fatalf("tag = %q, want v3.1.4", ctx.tag)
	}
}

func TestSetOptionalUploadContextFieldsIncludesRunAttempt(t *testing.T) {
	payload := map[string]any{}
	setOptionalUploadContextFields(payload, uploadCIContext{runAttempt: "4"})

	raw, ok := payload["run_attempt"]
	if !ok {
		t.Fatal("run_attempt missing from payload")
	}
	value, ok := raw.(string)
	if !ok || value != "4" {
		t.Fatalf("run_attempt = %#v, want \"4\"", raw)
	}
}

func resetUploadFlags() {
	uploadRef = ""
	uploadCommitSHA = ""
	uploadOrg = ""
	uploadRepo = ""
	_ = os.Unsetenv("HIBOU_REF")
	_ = os.Unsetenv("HIBOU_SHA")
	_ = os.Unsetenv("HIBOU_PR_SOURCE_BRANCH")
	_ = os.Unsetenv("HIBOU_RUN_ATTEMPT")
}

func TestResolveUploadContextDetectsGitHubOrgRepo(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_REPOSITORY", "acme/api-gateway")
	t.Setenv("GITHUB_REPOSITORY_OWNER", "acme")
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()
	if ctx.org != "github/acme" {
		t.Fatalf("org = %q, want github/acme", ctx.org)
	}
	if ctx.repo != "api-gateway" {
		t.Fatalf("repo = %q, want api-gateway", ctx.repo)
	}
}

func TestResolveUploadContextForgejoTakesPrecedenceOverGitHub(t *testing.T) {
	// Forgejo/Gitea act_runner sets GITEA_* alongside GITHUB_*; provider must be forgejo.
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_REPOSITORY", "acme/api-gateway")
	t.Setenv("GITHUB_REPOSITORY_OWNER", "acme")
	t.Setenv("GITEA_REPOSITORY", "devtools/api-gateway")
	t.Setenv("GITEA_REPOSITORY_OWNER", "devtools")
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()
	if ctx.org != "forgejo/devtools" {
		t.Fatalf("org = %q, want forgejo/devtools", ctx.org)
	}
	if ctx.repo != "api-gateway" {
		t.Fatalf("repo = %q, want api-gateway", ctx.repo)
	}
}

func TestResolveUploadBaseUsesDetectedOrgRepoWhenFlagsAbsent(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_REPOSITORY", "acme/api-gateway")
	t.Setenv("GITHUB_REPOSITORY_OWNER", "acme")
	t.Cleanup(resetUploadFlags)
	uploadOrg = ""
	uploadRepo = ""

	base, err := resolveUploadBase()
	if err != nil {
		t.Fatalf("resolveUploadBase() error = %v", err)
	}
	if base.provider != "github" || base.org != "acme" || base.repo != "api-gateway" {
		t.Fatalf("base = %+v, want {github acme api-gateway}", base)
	}
}

// On pull_request events GITHUB_SHA is the ephemeral merge commit; the true
// PR head comes from the event payload and is what checks must attach to.
func TestResolveUploadContextGitHubPRUsesEventHeadSHA(t *testing.T) {
	eventFile := t.TempDir() + "/event.json"
	if err := os.WriteFile(eventFile, []byte(`{"pull_request":{"head":{"sha":"headsha7777"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "mergesha0000")
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")
	t.Setenv("GITHUB_EVENT_PATH", eventFile)
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()

	if ctx.commitSHA != "headsha7777" {
		t.Fatalf("commitSHA = %q, want the PR head from the event payload", ctx.commitSHA)
	}
}

// Outside a PR (branch push), GITHUB_SHA is already the right commit — the
// event payload must not override it even if it carries a pull_request block.
func TestResolveUploadContextGitHubBranchKeepsGithubSHA(t *testing.T) {
	eventFile := t.TempDir() + "/event.json"
	if err := os.WriteFile(eventFile, []byte(`{"pull_request":{"head":{"sha":"headsha7777"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "branchsha111")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_EVENT_PATH", eventFile)
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()

	if ctx.commitSHA != "branchsha111" {
		t.Fatalf("commitSHA = %q, want GITHUB_SHA on a branch ref", ctx.commitSHA)
	}
}

// A missing or malformed event file must fall back to GITHUB_SHA, never fail.
func TestResolveUploadContextGitHubPRBrokenEventFileFallsBack(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "mergesha0000")
	t.Setenv("GITHUB_REF", "refs/pull/42/merge")
	t.Setenv("GITHUB_EVENT_PATH", t.TempDir()+"/missing.json")
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()

	if ctx.commitSHA != "mergesha0000" {
		t.Fatalf("commitSHA = %q, want the GITHUB_SHA fallback", ctx.commitSHA)
	}
}

// GitLab merged-results pipelines run on an internal merge commit; the MR head
// (CI_MERGE_REQUEST_SOURCE_BRANCH_SHA) is what the forge shows.
func TestResolveUploadContextGitLabMergedResultsUsesSourceBranchSHA(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_RUN_ID", "")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_PATH", "group/project")
	t.Setenv("CI_PROJECT_NAME", "project")
	t.Setenv("CI_COMMIT_SHA", "internalmerge99")
	t.Setenv("CI_COMMIT_REF_NAME", "feature")
	t.Setenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", "realhead4242")
	t.Cleanup(resetUploadFlags)

	ctx := resolveUploadContext()

	if ctx.commitSHA != "realhead4242" {
		t.Fatalf("commitSHA = %q, want the MR source branch head", ctx.commitSHA)
	}
}

func TestWithContextFingerprintsReadsCheckout(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkg", "io.go"), []byte("package pkg\n\nfunc f() {\n\tos.ReadFile(p)\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := []byte(`{"runs":[{"tool":{"driver":{"name":"gosec"}},"results":[{"ruleId":"G304","locations":[{"physicalLocation":{"artifactLocation":{"uri":"pkg/io.go"},"region":{"startLine":4}}}]}]}]}`)
	if out := withContextFingerprints(doc, root); !strings.Contains(string(out), "hibou/contextHash/v1") {
		t.Fatalf("expected a content fingerprint, got %s", out)
	}
	if out := withContextFingerprints(doc, t.TempDir()); string(out) != string(doc) {
		t.Fatal("missing source must upload the file unchanged")
	}
	sbom := []byte(`{"bomFormat":"CycloneDX"}`)
	if out := withContextFingerprints(sbom, root); string(out) != string(sbom) {
		t.Fatal("non-SARIF must pass through")
	}
}

func TestResolveSourcePath(t *testing.T) {
	cases := []struct{ uri, base, want string }{
		{"pkg/a.go", "", filepath.Join("/root", "pkg", "a.go")},
		{"a%20b.go", "", filepath.Join("/root", "a b.go")},
		{"file:///abs/a.go", "", "/abs/a.go"},
		{"a.go", "file:///src/", filepath.Join("/src", "a.go")},
	}
	for _, tc := range cases {
		got, err := resolveSourcePath("/root", tc.uri, tc.base)
		if err != nil || got != tc.want {
			t.Errorf("resolveSourcePath(%q, %q) = %q, %v; want %q", tc.uri, tc.base, got, err, tc.want)
		}
	}
	if _, err := resolveSourcePath("/root", "https://x/a.go", ""); err == nil {
		t.Error("remote uri must be rejected")
	}
}

// SpotBugs writes paths relative to the Java source root; the upload makes
// them repo-relative so change checks and links match the forge.
func TestWithRepoRelativePaths(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"java/src/main/java/com/acme/App.java", "a/Dup.java", "b/Dup.java", "java/target/classes/com/acme/App.java"} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("class X {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	doc := []byte(`{"runs":[{"tool":{"driver":{"name":"SpotBugs"}},"results":[
	  {"ruleId":"A","locations":[{"physicalLocation":{"artifactLocation":{"uri":"com/acme/App.java"},"region":{"startLine":1}}}]},
	  {"ruleId":"B","locations":[{"physicalLocation":{"artifactLocation":{"uri":"Dup.java"},"region":{"startLine":1}}}]}]}]}`)
	out := string(withRepoRelativePaths(doc, root))
	if !strings.Contains(out, `"java/src/main/java/com/acme/App.java"`) {
		t.Fatalf("source-root path not rewritten: %s", out)
	}
	if !strings.Contains(out, `"Dup.java"`) {
		t.Fatalf("ambiguous path must stay as written: %s", out)
	}
}

package cmd

import (
	"os"
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
	_ = os.Unsetenv("HIBOU_REF")
	_ = os.Unsetenv("HIBOU_SHA")
	_ = os.Unsetenv("HIBOU_PR_SOURCE_BRANCH")
	_ = os.Unsetenv("HIBOU_RUN_ATTEMPT")
}

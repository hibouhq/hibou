package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/cliconfig"
)

var (
	uploadProvider   string
	uploadOrg        string
	uploadRepo       string
	uploadRef        string
	uploadCommitSHA  string
	uploadComplete   bool = true
	uploadNoComplete bool
	uploadExpect     int
	uploadServer     string
	uploadToken      string
)

type uploadBase struct {
	provider string
	org      string
	repo     string
}

type uploadCIContext struct {
	// org is the auto-detected "provider/slug" (e.g. "github/acme"); repo is the
	// repository slug. Both are filled from the CI environment so callers (and
	// the GitHub Action wrapper) need not pass --org/--repo.
	org            string
	repo           string
	ref            string
	commitSHA      string
	runID          string
	runAttempt     string
	runNumber      string
	buildURL       string
	prNumber       string
	prTargetBranch string
	prSourceBranch string
	prTitle        string
	tag            string
}

var uploadCmd = &cobra.Command{
	Use:   "upload <file> [file...]",
	Short: "Upload security artifacts to Hibou",
	Long: `Upload SBOM, SARIF, coverage, or JUnit test-result artifacts to Hibou. The artifact type is auto-detected from file content.
Accepts multiple files — each is uploaded separately.

Supported CI auto-detection:
	- GitHub Actions, Forgejo Actions, and Gitea Actions via GITHUB_* environment variables
	- GitLab CI via GITLAB_CI=true plus CI_* merge/pipeline variables

Retry handling (distinct snapshot per attempt):
	- The server synthesizes a new attempt for every forge: an upload arriving after the
	  build's latest snapshot is no longer pending starts a new attempt automatically.
	- When the forge exposes a real attempt (GitHub/Forgejo/Gitea GITHUB_RUN_ATTEMPT), it is
	  sent as the authoritative attempt, which keeps overlapping re-runs (same run_id) distinct.
	- GitLab has no native pipeline-attempt variable; it relies on the server synthesis above.
	  Set HIBOU_RUN_ATTEMPT to override the attempt explicitly on any forge.

Generic CI overrides:
	HIBOU_REF, HIBOU_SHA, HIBOU_RUN_ID, HIBOU_RUN_ATTEMPT, HIBOU_RUN_NUMBER, HIBOU_BUILD_URL,
	HIBOU_PR_NUMBER, HIBOU_PR_TARGET_BRANCH, HIBOU_PR_SOURCE_BRANCH, HIBOU_PR_TITLE, HIBOU_TAG

Precedence for upload context: explicit flag > HIBOU_* override > detected CI provider.

With no files and --complete, closes the current snapshot for the given ref/sha and triggers gate evaluation.

Examples:
  hibou upload sbom.cdx.json
  hibou upload coverage.xml
  hibou upload results.sarif sbom.cdx.json
  hibou upload *.sarif --org forgejo/devtools --repo myapp --ref refs/heads/main --sha abc123
  hibou upload --no-complete coverage-unit.xml   # parallel job, don't close yet
  hibou upload --complete --org ... --ref ... --sha ...  # close snapshot, no files
  hibou upload --expect 3 --no-complete cov.xml  # expect 3 distinct upload API calls`,
	Args: cobra.MinimumNArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		if uploadNoComplete {
			uploadComplete = false
		}

		// Zero files + --complete = close snapshot without uploading
		if len(args) == 0 {
			if !uploadComplete {
				return errors.New("no files provided and --complete is not set; nothing to do")
			}
			return runUploadComplete()
		}

		failed := 0
		for i, file := range args {
			fmt.Printf("--- Uploading: %s\n", file)
			isLast := i == len(args)-1
			complete := uploadComplete && isLast
			expect := 0
			if i == 0 {
				expect = uploadExpect
			}
			if err := runUploadAuto(file, complete, expect); err != nil {
				fmt.Fprintf(os.Stderr, "error: %s: %v\n", file, err)
				failed++
			}
		}
		if failed > 0 {
			return fmt.Errorf("%d upload(s) failed", failed)
		}
		return nil
	},
}

func resolveUploadClient() (*cliclient.Client, error) {
	server := strings.TrimSpace(uploadServer)
	if server == "" {
		server = strings.TrimSpace(os.Getenv("HIBOU_SERVER"))
	}
	token := strings.TrimSpace(uploadToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("HIBOU_TOKEN"))
	}

	return cliclient.NewWithOverrides(server, token)
}

func resolveUploadBase() (uploadBase, error) {
	ci := resolveUploadContext()

	org := strings.TrimSpace(uploadOrg)
	if org == "" {
		cfg, _ := cliconfig.Load()
		org = strings.TrimSpace(cfg.Org)
	}
	if org == "" {
		org = ci.org // auto-detected "provider/slug" from the CI environment
	}
	if uploadProvider != "" && org == "" {
		return uploadBase{}, errors.New("--provider is deprecated, use --org provider/slug")
	}
	if org == "" {
		return uploadBase{}, errors.New("--org is required (or set default with 'hibou config set-org')")
	}

	repo := strings.TrimSpace(uploadRepo)
	if repo == "" {
		repo = ci.repo // auto-detected repository slug from the CI environment
	}
	if repo == "" {
		return uploadBase{}, errors.New("--repo is required")
	}

	if ci.ref == "" {
		return uploadBase{}, errors.New("--ref is required")
	}
	if ci.commitSHA == "" {
		return uploadBase{}, errors.New("--sha is required")
	}

	parts := strings.SplitN(org, "/", 2)
	if len(parts) != 2 {
		return uploadBase{}, errors.New("org must be in 'provider/slug' format (e.g., 'forgejo/devtools')")
	}

	return uploadBase{provider: parts[0], org: parts[1], repo: repo}, nil
}

// repoOwner returns the owner segment of a "owner/name" repository, preferring
// the explicit owner env value when set.
func repoOwner(fullName, explicitOwner string) string {
	if owner := strings.TrimSpace(explicitOwner); owner != "" {
		return owner
	}
	if idx := strings.Index(fullName, "/"); idx >= 0 {
		return fullName[:idx]
	}
	return fullName
}

// repoSlug returns the repository name (last path segment) of a repository path.
func repoSlug(fullName string) string {
	if idx := strings.LastIndex(fullName, "/"); idx >= 0 {
		return fullName[idx+1:]
	}
	return fullName
}

func detectCIContext() uploadCIContext {
	for _, detector := range []func() (uploadCIContext, bool){detectGitHubFamilyCIContext, detectGitLabCIContext} {
		if ctx, matched := detector(); matched {
			return ctx
		}
	}
	return uploadCIContext{}
}

func resolveUploadContext() uploadCIContext {
	ctx := applyHIBOUOverrides(detectCIContext())
	if value := strings.TrimSpace(uploadRef); value != "" {
		ctx.ref = value
	}
	if value := strings.TrimSpace(uploadCommitSHA); value != "" {
		ctx.commitSHA = value
	}
	return ctx
}

func detectGitHubFamilyCIContext() (uploadCIContext, bool) {
	if strings.TrimSpace(os.Getenv("GITHUB_ACTIONS")) != "true" && strings.TrimSpace(os.Getenv("GITHUB_SHA")) == "" && strings.TrimSpace(os.Getenv("GITHUB_RUN_ID")) == "" {
		return uploadCIContext{}, false
	}
	ctx := uploadCIContext{
		commitSHA:      strings.TrimSpace(os.Getenv("GITHUB_SHA")),
		ref:            strings.TrimSpace(os.Getenv("GITHUB_REF")),
		prTargetBranch: strings.TrimSpace(os.Getenv("GITHUB_BASE_REF")),
		prSourceBranch: strings.TrimSpace(os.Getenv("GITHUB_HEAD_REF")),
		runID:          strings.TrimSpace(os.Getenv("GITHUB_RUN_ID")),
		runAttempt:     strings.TrimSpace(os.Getenv("GITHUB_RUN_ATTEMPT")),
		runNumber:      strings.TrimSpace(os.Getenv("GITHUB_RUN_NUMBER")),
	}
	// Forgejo/Gitea act_runner sets GITEA_* alongside GITHUB_*; prefer it so the
	// provider is "forgejo" rather than "github" on those runners.
	if repository := strings.TrimSpace(os.Getenv("GITEA_REPOSITORY")); repository != "" {
		ctx.org = "forgejo/" + repoOwner(repository, os.Getenv("GITEA_REPOSITORY_OWNER"))
		ctx.repo = repoSlug(repository)
	} else if repository := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY")); repository != "" {
		ctx.org = "github/" + repoOwner(repository, os.Getenv("GITHUB_REPOSITORY_OWNER"))
		ctx.repo = repoSlug(repository)
	}
	serverURL := strings.TrimSpace(os.Getenv("GITHUB_SERVER_URL"))
	repository := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	if ctx.runID != "" && serverURL != "" && repository != "" {
		ctx.buildURL = strings.TrimRight(serverURL, "/") + "/" + repository + "/actions/runs/" + ctx.runID
	}
	ctx.prNumber = parseGitHubPRNumber(ctx.ref)
	if strings.HasPrefix(ctx.ref, "refs/tags/") {
		ctx.tag = strings.TrimSpace(os.Getenv("GITHUB_REF_NAME"))
	}
	return ctx, true
}

func detectGitLabCIContext() (uploadCIContext, bool) {
	if strings.TrimSpace(os.Getenv("GITLAB_CI")) != "true" {
		return uploadCIContext{}, false
	}
	tag := strings.TrimSpace(os.Getenv("CI_COMMIT_TAG"))
	ref := strings.TrimSpace(os.Getenv("CI_COMMIT_REF_NAME"))
	if tag != "" {
		ref = "refs/tags/" + tag
	}
	buildURL := strings.TrimSpace(os.Getenv("CI_PIPELINE_URL"))
	if buildURL == "" {
		buildURL = strings.TrimSpace(os.Getenv("CI_JOB_URL"))
	}
	return uploadCIContext{
		org:            "gitlab/" + repoOwner(strings.TrimSpace(os.Getenv("CI_PROJECT_PATH")), os.Getenv("CI_PROJECT_ROOT_NAMESPACE")),
		repo:           strings.TrimSpace(os.Getenv("CI_PROJECT_NAME")),
		commitSHA:      strings.TrimSpace(os.Getenv("CI_COMMIT_SHA")),
		ref:            ref,
		prTargetBranch: strings.TrimSpace(os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")),
		prSourceBranch: strings.TrimSpace(os.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")),
		prNumber:       strings.TrimSpace(os.Getenv("CI_MERGE_REQUEST_IID")),
		runID:          strings.TrimSpace(os.Getenv("CI_PIPELINE_ID")),
		runNumber:      strings.TrimSpace(os.Getenv("CI_PIPELINE_IID")),
		buildURL:       buildURL,
		prTitle:        strings.TrimSpace(os.Getenv("CI_MERGE_REQUEST_TITLE")),
		tag:            tag,
	}, true
}

func applyHIBOUOverrides(ctx uploadCIContext) uploadCIContext {
	if value := strings.TrimSpace(os.Getenv("HIBOU_REF")); value != "" {
		ctx.ref = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_SHA")); value != "" {
		ctx.commitSHA = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_RUN_ID")); value != "" {
		ctx.runID = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_RUN_ATTEMPT")); value != "" {
		ctx.runAttempt = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_RUN_NUMBER")); value != "" {
		ctx.runNumber = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_BUILD_URL")); value != "" {
		ctx.buildURL = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_PR_NUMBER")); value != "" {
		ctx.prNumber = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_PR_TARGET_BRANCH")); value != "" {
		ctx.prTargetBranch = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_PR_SOURCE_BRANCH")); value != "" {
		ctx.prSourceBranch = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_PR_TITLE")); value != "" {
		ctx.prTitle = value
	}
	if value := strings.TrimSpace(os.Getenv("HIBOU_TAG")); value != "" {
		ctx.tag = value
	}
	return ctx
}

func parseGitHubPRNumber(ref string) string {
	match := regexp.MustCompile(`^refs/pull/(\d+)/merge$`).FindStringSubmatch(strings.TrimSpace(ref))
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func submitUpload(client *cliclient.Client, endpoint string, payload any) error {
	var result struct {
		UploadID string `json:"upload_id"`
		Status   string `json:"status"`
	}
	if err := client.Post(endpoint, payload, &result); err != nil {
		return err
	}

	fmt.Printf("Upload successful: %s (status: %s)\n", result.UploadID, result.Status)
	return nil
}

func runUploadAuto(file string, complete bool, expect int) error {
	client, err := resolveUploadClient()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	base, err := resolveUploadBase()
	if err != nil {
		return err
	}
	ci := resolveUploadContext()

	payload := map[string]any{
		"provider":   base.provider,
		"org":        base.org,
		"repo":       base.repo,
		"ref":        ci.ref,
		"commit_sha": ci.commitSHA,
		"complete":   complete,
		"artifact": map[string]string{
			"filename":       filepath.Base(file),
			"content_base64": base64.StdEncoding.EncodeToString(data),
		},
	}
	setOptionalUploadContextFields(payload, ci)
	if expect > 0 {
		payload["expect"] = expect
	}

	return submitUpload(client, "/upload", payload)
}

func runUploadComplete() error {
	client, err := resolveUploadClient()
	if err != nil {
		return err
	}

	base, err := resolveUploadBase()
	if err != nil {
		return err
	}
	ci := resolveUploadContext()

	payload := map[string]any{
		"provider":   base.provider,
		"org":        base.org,
		"repo":       base.repo,
		"ref":        ci.ref,
		"commit_sha": ci.commitSHA,
		"complete":   true,
	}
	setOptionalUploadContextFields(payload, ci)

	fmt.Println("--- Completing snapshot")
	return submitUpload(client, "/upload", payload)
}

func setOptionalUploadContextFields(payload map[string]any, ctx uploadCIContext) {
	if ctx.runID != "" {
		payload["run_id"] = ctx.runID
	}
	if ctx.runAttempt != "" {
		payload["run_attempt"] = ctx.runAttempt
	}
	if ctx.runNumber != "" {
		payload["run_number"] = ctx.runNumber
	}
	if ctx.buildURL != "" {
		payload["build_url"] = ctx.buildURL
	}
	if ctx.prNumber != "" {
		payload["pr_number"] = ctx.prNumber
	}
	if ctx.prTargetBranch != "" {
		payload["pr_target_branch"] = ctx.prTargetBranch
	}
	if ctx.prSourceBranch != "" {
		payload["pr_source_branch"] = ctx.prSourceBranch
	}
	if ctx.prTitle != "" {
		payload["pr_title"] = ctx.prTitle
	}
	if ctx.tag != "" {
		payload["tag"] = ctx.tag
	}
}

func init() {
	for _, command := range []*cobra.Command{uploadCmd} {
		command.Flags().StringVar(&uploadOrg, "org", "", "Organization (provider/slug, e.g., 'forgejo/devtools')")
		command.Flags().StringVar(&uploadRepo, "repo", "", "Repository slug")
		command.Flags().StringVar(&uploadRef, "ref", "", "Git ref (e.g., refs/heads/main)")
		command.Flags().StringVar(&uploadCommitSHA, "sha", "", "Commit SHA")
		command.Flags().StringVar(&uploadProvider, "provider", "", "Forge provider (deprecated, use --org)")
		command.Flags().StringVar(&uploadServer, "server", "", "Hibou server URL (overrides config and HIBOU_SERVER)")
		command.Flags().StringVar(&uploadToken, "token", "", "API token (overrides config and HIBOU_TOKEN)")
		command.Flags().BoolVar(&uploadComplete, "complete", true, "Complete the snapshot after uploading (set --complete=false for multi-job pipelines)")
		command.Flags().BoolVar(&uploadNoComplete, "no-complete", false, "Do not complete the snapshot after uploading")
		command.Flags().IntVar(&uploadExpect, "expect", 0, "Expected number of upload calls for auto-completion (0 = disabled)")
	}
}

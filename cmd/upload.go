package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/cliconfig"
	"github.com/hibouhq/hibou/internal/sarif"
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
	uploadSourceRoot string
	// Run declaration (ADR-034): overrides .hibou.yaml's scanners section.
	uploadScope string
	uploadPaths []string
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
	// Provenance (PLAN §2): what CI really built on a PR event.
	mergeCommitSHA string
	baseCommitSHA  string
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
		// Past this point every failure is a server or network error, not a
		// usage mistake, so stop cobra from appending the flag reference and
		// burying the actual response in the CI log.
		cmd.SilenceUsage = true

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
	// On pull_request events GITHUB_SHA is the EPHEMERAL MERGE COMMIT
	// (refs/pull/N/merge), not the PR head. Checks and comments posted against
	// it never show on the PR, and the server sees a head it can't match. The
	// event payload carries the real head.
	if ctx.prNumber != "" {
		// GITHUB_SHA on pull_request events IS the ephemeral merge commit —
		// keep it as provenance before swapping commitSHA to the real head.
		ctx.mergeCommitSHA = ctx.commitSHA
		head, base := gitHubEventPRSHAs(os.Getenv("GITHUB_EVENT_PATH"))
		if head != "" {
			ctx.commitSHA = head
		}
		ctx.baseCommitSHA = base
	}
	return ctx, true
}

// gitHubEventPRSHAs reads .pull_request.head.sha and .pull_request.base.sha
// from the Actions event payload file. Empty on any error — the caller keeps
// GITHUB_SHA then.
func gitHubEventPRSHAs(eventPath string) (head, base string) {
	eventPath = strings.TrimSpace(eventPath)
	if eventPath == "" {
		return "", ""
	}
	payload, err := os.ReadFile(eventPath) // #nosec G304 G703 -- the CLI reads GITHUB_EVENT_PATH, the Actions-runner-provided payload file, with the invoking user's own privileges — no trust boundary to traverse.
	if err != nil {
		return "", ""
	}
	var event struct {
		PullRequest struct {
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
			Base struct {
				SHA string `json:"sha"`
			} `json:"base"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return "", ""
	}
	return strings.TrimSpace(event.PullRequest.Head.SHA), strings.TrimSpace(event.PullRequest.Base.SHA)
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
	commitSHA := strings.TrimSpace(os.Getenv("CI_COMMIT_SHA"))
	// Merged-results pipelines run on an internal merge commit; the MR head is
	// what the forge shows and what checks must attach to. The merge commit and
	// the base it merged onto are kept as provenance (PLAN §2).
	mergeCommitSHA := ""
	baseCommitSHA := strings.TrimSpace(os.Getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA"))
	if headSHA := strings.TrimSpace(os.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA")); headSHA != "" {
		mergeCommitSHA = commitSHA
		commitSHA = headSHA
	}
	return uploadCIContext{
		org:            "gitlab/" + repoOwner(strings.TrimSpace(os.Getenv("CI_PROJECT_PATH")), os.Getenv("CI_PROJECT_ROOT_NAMESPACE")),
		repo:           strings.TrimSpace(os.Getenv("CI_PROJECT_NAME")),
		commitSHA:      commitSHA,
		ref:            ref,
		prTargetBranch: strings.TrimSpace(os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")),
		prSourceBranch: strings.TrimSpace(os.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")),
		prNumber:       strings.TrimSpace(os.Getenv("CI_MERGE_REQUEST_IID")),
		mergeCommitSHA: mergeCommitSHA,
		baseCommitSHA:  baseCommitSHA,
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
	data = withContextFingerprints(data, uploadSourceRoot)

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
	setRunDeclarationFields(payload)
	if expect > 0 {
		payload["expect"] = expect
	}

	return submitUpload(client, "/upload", payload)
}

// setRunDeclarationFields sends what the scan covered. Without it the server
// records the run as an assumed full scan: a diff-aware or path-filtered job
// must say --scope=partial (and --path for what it analysed), or findings
// outside its paths would read as fixed.
func setRunDeclarationFields(payload map[string]any) {
	if uploadScope != "" {
		payload["scope"] = uploadScope
	}
	if len(uploadPaths) > 0 {
		payload["paths"] = uploadPaths
	}
}

// withContextFingerprints gives SARIF results without a scanner fingerprint a
// line-independent one computed from the checked-out source (ADR-034, D15),
// so a finding keeps its identity and triage when code above it moves. Any
// failure uploads the file unchanged: the server then falls back to its
// line-based identity, as before.
func withContextFingerprints(data []byte, sourceRoot string) []byte {
	if !bytes.Contains(data, []byte(`"runs"`)) {
		return data
	}
	data = withRepoRelativePaths(data, sourceRoot)
	out, added, err := sarif.AddContextFingerprints(data, sourceFileReader(sourceRoot))
	if err != nil {
		return data
	}
	if added > 0 {
		fmt.Printf("Added content fingerprints to %d result(s)\n", added)
	}
	return out
}

// withRepoRelativePaths rewrites SARIF paths that are relative to a module's
// source root (SpotBugs writes com/acme/App.java for java/src/main/java/com/
// acme/App.java) to repo-relative ones, when exactly one file of the checkout
// ends with that path. Hibou compares paths with the forge's (change checks,
// file links): a path the forge never lists would read as "unchanged".
func withRepoRelativePaths(data []byte, sourceRoot string) []byte {
	index := &checkoutIndex{root: sourceRoot}
	out, rewritten, err := sarif.RewriteArtifactURIs(data, index.resolve)
	if err != nil {
		return data
	}
	if rewritten > 0 {
		fmt.Printf("Rewrote %d SARIF path(s) to repo-relative\n", rewritten)
	}
	return out
}

// checkoutIndex maps file names to repo-relative paths, built on the first
// path that does not resolve as written.
type checkoutIndex struct {
	root   string
	built  bool
	byName map[string][]string
}

// checkoutIndexSkipDirs are build outputs and dependency trees: a source file
// is not looked up there.
var checkoutIndexSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "target": true, "build": true, "dist": true,
	"vendor": true, ".venv": true, "venv": true, "__pycache__": true, ".gradle": true, ".idea": true,
}

// maxCheckoutIndexFiles bounds the walk on very large monorepos; beyond it,
// paths stay as the scanner wrote them.
const maxCheckoutIndexFiles = 500000

func (c *checkoutIndex) resolve(uri, baseURI string) (string, bool) {
	if strings.Contains(uri, "://") || baseURI != "" || filepath.IsAbs(uri) {
		return "", false
	}
	relative := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(uri, "./")))
	if strings.HasPrefix(relative, "../") {
		return "", false
	}
	if _, err := os.Stat(filepath.Join(c.root, filepath.FromSlash(relative))); err == nil {
		return "", false
	}
	c.build()
	var match string
	for _, candidate := range c.byName[filepath.Base(relative)] {
		if strings.HasSuffix(candidate, "/"+relative) {
			if match != "" {
				return "", false // ambiguous: two modules hold the same path
			}
			match = candidate
		}
	}
	return match, match != ""
}

func (c *checkoutIndex) build() {
	if c.built {
		return
	}
	c.built = true
	c.byName = map[string][]string{}
	count := 0
	_ = filepath.WalkDir(c.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if path != c.root && checkoutIndexSkipDirs[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= maxCheckoutIndexFiles {
			return filepath.SkipAll
		}
		relative, relErr := filepath.Rel(c.root, path)
		if relErr != nil {
			return nil
		}
		count++
		c.byName[entry.Name()] = append(c.byName[entry.Name()], filepath.ToSlash(relative))
		return nil
	})
}

// maxFingerprintSourceBytes skips generated or minified files too large to be
// worth reading for a five-line context window.
const maxFingerprintSourceBytes = 8 << 20

// sourceFileReader resolves a SARIF artifact location the way scanners write
// them: an absolute file:// URI, a path under a file:// originalUriBaseIds
// entry, or a path relative to the source root (the CI checkout).
func sourceFileReader(sourceRoot string) sarif.SourceReader {
	return func(uri, baseURI string) ([]byte, error) {
		path, err := resolveSourcePath(sourceRoot, uri, baseURI)
		if err != nil {
			return nil, err
		}
		// #nosec G304 -- the CLI reads the CI checkout files that the user's own SARIF names, with the user's privileges
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > maxFingerprintSourceBytes {
			return nil, errors.New("not a readable source file")
		}
		return io.ReadAll(file)
	}
}

func resolveSourcePath(sourceRoot, uri, baseURI string) (string, error) {
	if path, ok := fileURIPath(uri); ok {
		return path, nil
	}
	relative, err := url.PathUnescape(uri)
	if err != nil {
		relative = uri
	}
	if strings.Contains(relative, "://") {
		return "", errors.New("unsupported uri scheme")
	}
	if base, ok := fileURIPath(baseURI); ok {
		return filepath.Join(base, filepath.FromSlash(relative)), nil
	}
	if filepath.IsAbs(relative) {
		return relative, nil
	}
	return filepath.Join(sourceRoot, filepath.FromSlash(relative)), nil
}

func fileURIPath(uri string) (string, bool) {
	if !strings.HasPrefix(uri, "file://") {
		return "", false
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Path == "" {
		return "", false
	}
	return filepath.FromSlash(parsed.Path), true
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
	if ctx.mergeCommitSHA != "" {
		payload["merge_commit_sha"] = ctx.mergeCommitSHA
	}
	if ctx.baseCommitSHA != "" {
		payload["base_commit_sha"] = ctx.baseCommitSHA
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
		command.Flags().StringVar(&uploadScope, "scope", "", "Override the scope .hibou.yaml's scanners section gives this upload: 'full' or 'partial'")
		command.Flags().StringArrayVar(&uploadPaths, "path", nil, "File or directory a partial scan analysed (repeatable; implies --scope=partial)")
		command.Flags().StringVar(&uploadSourceRoot, "source-root", ".", "Checkout root that relative SARIF paths resolve against (used to fingerprint findings by content)")
	}
}

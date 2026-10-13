package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scanplan"
	"github.com/hibouhq/hibou/internal/scanrun"
)

var (
	scanMode          string
	scanScanners      []string
	scanJobs          int
	scanCacheDir      string
	scanOutDir        string
	scanDryRun        bool
	scanFailOnBlocked bool
	scanOpenGrepRules string
	scanMavenRepo     string
	scanBundleDir     string

	// scanLocalCatalog is the catalog compiled into this CLI; tests replace it.
	scanLocalCatalog = scancatalog.Load

	// scanCommandOverride replaces process execution in tests.
	scanCommandOverride func(ctx context.Context, dir, name string, args ...string) ([]byte, int, error)
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run the bundled scanners hibou plans for this commit and upload their reports",
	Long: `Asks Hibou for a scan plan for this commit (ADR-035/036), then runs each ready job:
the scanner artifact is fetched from the location the plan resolved (upstream, an
operator mirror, or an offline bundle), its sha256 is verified before use, and the
report is uploaded bound to its plan job. Nothing goes through a shell.

What runs is decided by the scanner catalog compiled into this CLI: engine, command
arguments, sha256 pins and Maven coordinates. The server only chooses which scanners
run on which targets and where artifacts are downloaded from. A job for a scanner or
version this CLI does not know fails: upgrade the CLI to match the server.

Offline bundles: pass --bundle-dir (or HIBOU_SCANNER_BUNDLE_DIR) with the directory the
bundle was imported into on this runner.

Jobs the plan marks blocked are listed with the exact blocker and skipped. Bytecode
scanners need the build's classes: compile first, then run hibou scan.

Examples:
  hibou scan                                   # plan + run + upload, CI context auto-detected
  hibou scan --dry-run                         # show the plan only
  hibou scan --scanner opengrep-interfile --opengrep-rules rules.yaml
  hibou scan --mode sweep                      # scheduled full sweep`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cmd.SilenceUsage = true
		return runScan(cmd.Context())
	},
}

type scanPlanEnvelope struct {
	ID   *string       `json:"id"`
	Plan scanplan.Plan `json:"plan"`
}

type scannerCatalogEnvelope struct {
	Scanners []scanrun.CatalogEntry `json:"scanners"`
}

func runScan(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	client, err := resolveUploadClient()
	if err != nil {
		return err
	}
	base, err := resolveUploadBase()
	if err != nil {
		return err
	}
	ci := resolveUploadContext()
	if uploadNoComplete {
		uploadComplete = false
	}

	local, err := scanLocalCatalog()
	if err != nil {
		return fmt.Errorf("load embedded scanner catalog: %w", err)
	}
	bundleDir := strings.TrimSpace(scanBundleDir)
	if bundleDir == "" {
		bundleDir = strings.TrimSpace(os.Getenv("HIBOU_SCANNER_BUNDLE_DIR"))
	}
	if bundleDir != "" {
		if bundleDir, err = filepath.Abs(bundleDir); err != nil {
			return fmt.Errorf("--bundle-dir: %w", err)
		}
	}
	resolver := scanrun.Resolver{Catalog: local, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, BundleDir: bundleDir}

	var catalog scannerCatalogEnvelope
	if err := client.Get("/scanner-catalog", &catalog); err != nil {
		return fmt.Errorf("load scanner catalog: %w", err)
	}
	entries := make(map[string]scanrun.CatalogEntry, len(catalog.Scanners))
	for _, entry := range catalog.Scanners {
		entries[entry.ID] = entry
	}

	request := map[string]any{
		"ref":        strings.TrimPrefix(ci.ref, "refs/heads/"),
		"commit_sha": ci.commitSHA,
		"mode":       scanMode,
		"runner":     map[string]string{"os": runtime.GOOS, "arch": runtime.GOARCH},
		"scanners":   scanScanners,
		"dry_run":    scanDryRun,
	}
	if ci.baseCommitSHA != "" {
		request["base_commit_sha"] = ci.baseCommitSHA
	}
	var planned scanPlanEnvelope
	endpoint := fmt.Sprintf("/orgs/%s/%s/repos/%s/scan-plans", base.provider, base.org, base.repo)
	if err := client.Post(endpoint, request, &planned); err != nil {
		return fmt.Errorf("create scan plan: %w", err)
	}
	printPlan(planned.Plan)
	if planned.Plan.CatalogRevision != "" && planned.Plan.CatalogRevision != local.Revision {
		fmt.Fprintf(os.Stderr, "note: server scanner catalog %s, this CLI embeds %s; jobs this CLI does not pin will fail\n", planned.Plan.CatalogRevision, local.Revision)
	}
	if scanDryRun {
		return nil
	}

	outDir := scanOutDir
	if outDir == "" {
		outDir, err = os.MkdirTemp("", "hibou-scan-")
		if err != nil {
			return err
		}
	}
	cacheDir := scanCacheDir
	if cacheDir == "" {
		userCache, err := os.UserCacheDir()
		if err != nil {
			userCache = os.TempDir()
		}
		cacheDir = filepath.Join(userCache, "hibou", "scanners")
	}
	mavenRepo := scanMavenRepo
	if mavenRepo == "" {
		if home, err := os.UserHomeDir(); err == nil {
			mavenRepo = filepath.Join(home, ".m2", "repository")
		}
	}
	env := scanrun.Environment{
		SourceRoot:      uploadSourceRoot,
		OutDir:          outDir,
		Fetcher:         &scanrun.Fetcher{CacheDir: cacheDir, BundleDir: bundleDir},
		OpenGrepRules:   scanOpenGrepRules,
		MavenRepository: mavenRepo,
		Command:         scanCommandOverride,
	}

	type outcome struct {
		job    scanplan.Job
		result scanrun.Result
		err    error
	}
	runnable := make([]scanplan.Job, 0, len(planned.Plan.Jobs))
	blocked := 0
	for _, job := range planned.Plan.Jobs {
		switch {
		case job.Status == scanplan.JobReady:
			runnable = append(runnable, job)
		case scanOpenGrepRules != "" && strings.HasPrefix(job.BlockedReason, "no approved ruleset") && job.Artifact != nil:
			// Local rules stand in for the unapproved ruleset; the report
			// is uploaded unbound.
			runnable = append(runnable, job)
		default:
			blocked++
		}
	}
	if scanJobs < 1 {
		scanJobs = 1
	}
	outcomes := make([]outcome, len(runnable))
	semaphore := make(chan struct{}, scanJobs)
	var wg sync.WaitGroup
	for i, job := range runnable {
		wg.Add(1)
		go func(i int, job scanplan.Job) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			// The server's entry only contributes download locations; the
			// embedded catalog decides what is executed (P1).
			var served *scanrun.CatalogEntry
			if entry, ok := entries[job.ScannerID]; ok {
				served = &entry
			}
			trusted, entry, err := resolver.Resolve(job, served)
			if err != nil {
				outcomes[i] = outcome{job: job, err: err}
				return
			}
			result, err := scanrun.Run(ctx, trusted, entry, env)
			outcomes[i] = outcome{job: trusted, result: result, err: err}
		}(i, job)
	}
	wg.Wait()

	failed := 0
	for _, o := range outcomes {
		if o.err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "FAILED %s: %v\n", o.job.ScannerID, o.err)
			continue
		}
		for _, note := range o.result.Notes {
			fmt.Printf("note (%s): %s\n", o.job.ScannerID, note)
		}
		for _, sarifPath := range o.result.SARIFPaths {
			if err := uploadScanReport(client, base, ci, planned.ID, o.job, o.result, sarifPath); err != nil {
				failed++
				fmt.Fprintf(os.Stderr, "FAILED upload %s: %v\n", sarifPath, err)
			}
		}
	}
	if uploadComplete {
		if err := runUploadComplete(); err != nil {
			return err
		}
	}
	switch {
	case failed > 0:
		return fmt.Errorf("%d scan job(s) or upload(s) failed", failed)
	case blocked > 0 && scanFailOnBlocked:
		return fmt.Errorf("%d scan job(s) blocked", blocked)
	}
	return nil
}

// uploadScanReport uploads one report. A plan-bound job declares its scope
// through the binding; an unbound run (local rules) declares it explicitly
// and names the rules it ran with.
func uploadScanReport(client *cliclient.Client, base uploadBase, ci uploadCIContext, planID *string, job scanplan.Job, result scanrun.Result, sarifPath string) error {
	data, err := os.ReadFile(sarifPath) // #nosec G304 -- the scanner's report in the scan output directory
	if err != nil {
		return err
	}
	data = withContextFingerprints(data, uploadSourceRoot)
	payload := map[string]any{
		"provider":   base.provider,
		"org":        base.org,
		"repo":       base.repo,
		"ref":        ci.ref,
		"commit_sha": ci.commitSHA,
		"complete":   false,
		"artifact": map[string]string{
			"filename":       filepath.Base(sarifPath),
			"content_base64": base64.StdEncoding.EncodeToString(data),
		},
	}
	setOptionalUploadContextFields(payload, ci)
	switch {
	case planID != nil && !result.Unbound:
		payload["plan_id"] = *planID
		payload["plan_job_id"] = job.ID
	default:
		payload["scope"] = job.Scope
		if job.Scope == "partial" {
			payload["paths"] = job.Targets
		}
		if result.ConfigDigest != "" {
			payload["config_digest"] = result.ConfigDigest
		}
	}
	return submitUpload(client, "/upload", payload)
}

func printPlan(plan scanplan.Plan) {
	fmt.Printf("Scan plan %s — mode %s (%s)\n", shortDigest(plan.Digest), plan.Mode, plan.ModeReason)
	if plan.ApplicabilityStatus != "" && plan.ApplicabilityStatus != "complete" {
		fmt.Printf("  warning: repository listing is %s; the plan may miss scopes\n", plan.ApplicabilityStatus)
	}
	if len(plan.Jobs) == 0 {
		fmt.Println("  no applicable scanner")
	}
	for _, job := range plan.Jobs {
		line := fmt.Sprintf("  %-7s %-22s %s %s", job.Status, job.ScannerID, job.Scope, strings.Join(job.Targets, ","))
		if job.BlockedReason != "" {
			line += " — " + job.BlockedReason
		}
		if len(job.Prerequisites) > 0 {
			line += " [needs " + strings.Join(job.Prerequisites, ", ") + "]"
		}
		fmt.Println(line)
	}
}

func shortDigest(digest string) string {
	digest = strings.TrimPrefix(digest, "sha256:")
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func init() {
	scanCmd.Flags().StringVar(&uploadOrg, "org", "", "Organization (provider/slug)")
	scanCmd.Flags().StringVar(&uploadRepo, "repo", "", "Repository slug")
	scanCmd.Flags().StringVar(&uploadRef, "ref", "", "Git ref")
	scanCmd.Flags().StringVar(&uploadCommitSHA, "sha", "", "Commit SHA")
	scanCmd.Flags().StringVar(&uploadServer, "server", "", "Hibou server URL")
	scanCmd.Flags().StringVar(&uploadToken, "token", "", "API token")
	scanCmd.Flags().StringVar(&uploadSourceRoot, "source-root", ".", "Checkout root the scanners analyse")
	scanCmd.Flags().BoolVar(&uploadNoComplete, "no-complete", false, "Do not complete the snapshot after uploading (other jobs still upload)")
	scanCmd.Flags().StringVar(&scanMode, "mode", "", `Plan mode: empty lets hibou choose; "sweep" asks for a full sweep`)
	scanCmd.Flags().StringArrayVar(&scanScanners, "scanner", nil, "Run these catalog scanners only (repeatable; pre-releases need this)")
	scanCmd.Flags().IntVar(&scanJobs, "jobs", 2, "Scanner jobs run at once")
	scanCmd.Flags().StringVar(&scanCacheDir, "cache-dir", "", "Verified artifact cache (default: user cache dir)/hibou/scanners")
	scanCmd.Flags().StringVar(&scanOutDir, "out-dir", "", "Where reports are written (default: a temporary directory)")
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "Show the plan without storing or running it")
	scanCmd.Flags().BoolVar(&scanFailOnBlocked, "fail-on-blocked", false, "Exit non-zero when a planned job is blocked")
	scanCmd.Flags().StringVar(&scanOpenGrepRules, "opengrep-rules", "", "Local OpenGrep rules while no catalog ruleset is approved; such reports are uploaded unbound")
	scanCmd.Flags().StringVar(&scanBundleDir, "bundle-dir", "", "Imported offline scanner bundle on this runner (default $HIBOU_SCANNER_BUNDLE_DIR); required when the server distributes offline")
	scanCmd.Flags().StringVar(&scanMavenRepo, "maven-repo", "", "Local Maven repository to verify resolved plugin jars in (default ~/.m2/repository)")
}

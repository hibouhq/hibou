package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
)

var (
	gatePR         string
	gateFailOnGate bool
	gateFailOnSev  string
	gateTimeout    time.Duration
)

const (
	// gatePollInterval is how often the gate endpoint is polled while pending.
	gatePollInterval = 5 * time.Second
	// gateStatePending marks a gate that has not been evaluated yet.
	gateStatePending = "pending"
)

// gateResponse mirrors the JSON returned by
// GET /api/v1/{provider}/{slug}/repos/{repoSlug}/pulls/{pr}/gate.
type gateResponse struct {
	PRNumber    int      `json:"pr_number"`
	HeadSHA     string   `json:"head_sha"`
	Context     string   `json:"context"`
	State       string   `json:"state"`
	Conclusion  string   `json:"conclusion"`
	Enforcement string   `json:"enforcement"`
	Passed      bool     `json:"passed"`
	Reasons     []string `json:"reasons"`
	TargetURL   string   `json:"target_url"`
	Source      string   `json:"source"`
}

var gateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Check the Hibou security gate for the current pull request",
	Long: `Poll the Hibou security gate for the pull request detected from the CI
environment and print the verdict.

This command is the opt-in "break the build" escape hatch for CI. By default it
NEVER breaks the build: it reports the gate result and exits 0 regardless of the
outcome, a missing pull request, or a timeout. Pass --fail-on-gate (or
--fail-on-severity) to make a failing gate exit non-zero.

Org, repo, and PR number are resolved from the same CI detection used by
'hibou upload' (GitHub/Forgejo/Gitea Actions and GitLab CI) and can be
overridden with --org, --repo, and --pr.

Examples:
  hibou gate
  hibou gate --fail-on-gate
  hibou gate --org github/acme --repo api --pr 7 --gate-timeout 10m`,
	// Keep CI output clean: on a returned error, print only the message (once,
	// from Execute) and skip cobra's usage dump.
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGate()
	},
}

func runGate() error {
	base, err := resolveUploadBase()
	if err != nil {
		// Without org/repo/ref/sha there is nothing to gate. Never break the build.
		fmt.Printf("Skipping gate: %v\n", err)
		return nil
	}

	pr := strings.TrimSpace(gatePR)
	if pr == "" {
		pr = resolveUploadContext().prNumber
	}
	if pr == "" {
		fmt.Println("No pull request detected — nothing to gate.")
		return nil
	}

	client, err := resolveUploadClient()
	if err != nil {
		fmt.Printf("Skipping gate: %v\n", err)
		return nil
	}

	path := fmt.Sprintf("/orgs/%s/%s/repos/%s/pulls/%s/gate", base.provider, base.org, base.repo, pr)

	verdict, ok := pollGate(client, path)
	if !ok {
		fmt.Printf("Gate did not finish evaluating within %s — not breaking the build.\n", gateTimeout)
		return nil
	}

	printGateVerdict(verdict)

	if verdict.Passed {
		fmt.Println("\nGate passed.")
		return nil
	}

	sev := strings.TrimSpace(gateFailOnSev)
	if gateFailOnGate || sev != "" {
		reason := "--fail-on-gate"
		if sev != "" {
			reason = "--fail-on-severity=" + sev
		}
		fmt.Printf("\nGate did not pass and %s is set — failing the build.\n", reason)
		return fmt.Errorf("hibou gate failed for PR %s", pr)
	}

	fmt.Println("\nGate did not pass, but Hibou is in advisory mode — not breaking the build.")
	fmt.Println("Pass --fail-on-gate to fail the build on gate failures.")
	return nil
}

// pollGate polls path until the gate is no longer pending or the timeout
// elapses. The bool is false only when the timeout was reached.
func pollGate(client *cliclient.Client, path string) (gateResponse, bool) {
	fmt.Printf("Waiting for Hibou gate to evaluate (timeout %s)...\n", gateTimeout)

	deadline := time.After(gateTimeout)
	ticker := time.NewTicker(gatePollInterval)
	defer ticker.Stop()

	var lastErr string
	for {
		verdict, err := fetchGate(client, path)
		switch {
		case err != nil:
			// Transient (or not-yet-created gate): warn once per distinct error
			// and keep polling until the deadline.
			if msg := err.Error(); msg != lastErr {
				fmt.Fprintf(os.Stderr, "gate not ready yet: %v\n", err)
				lastErr = msg
			}
		case verdict.State == gateStatePending:
			// Still evaluating; keep polling.
		default:
			return verdict, true
		}

		select {
		case <-deadline:
			return gateResponse{}, false
		case <-ticker.C:
		}
	}
}

func fetchGate(client *cliclient.Client, path string) (gateResponse, error) {
	var verdict gateResponse
	if err := client.Get(path, &verdict); err != nil {
		return gateResponse{}, err
	}
	return verdict, nil
}

func printGateVerdict(v gateResponse) {
	status := "PASSED"
	if !v.Passed {
		status = "FAILED"
	}
	fmt.Printf("\nHibou gate: %s\n", status)
	if v.Context != "" {
		fmt.Printf("  Context:     %s\n", v.Context)
	}
	fmt.Printf("  State:       %s\n", v.State)
	if v.Conclusion != "" {
		fmt.Printf("  Conclusion:  %s\n", v.Conclusion)
	}
	if v.Enforcement != "" {
		fmt.Printf("  Enforcement: %s\n", v.Enforcement)
	}
	if len(v.Reasons) > 0 {
		fmt.Println("  Reasons:")
		for _, reason := range v.Reasons {
			fmt.Printf("    - %s\n", reason)
		}
	}
	if v.TargetURL != "" {
		fmt.Printf("  Details:     %s\n", v.TargetURL)
	}
}

func init() {
	gateCmd.Flags().StringVar(&uploadOrg, "org", "", "Organization (provider/slug, e.g., 'forgejo/devtools')")
	gateCmd.Flags().StringVar(&uploadRepo, "repo", "", "Repository slug")
	gateCmd.Flags().StringVar(&gatePR, "pr", "", "Pull request number (overrides CI detection)")
	gateCmd.Flags().StringVar(&uploadServer, "server", "", "Hibou server URL (overrides config and HIBOU_SERVER)")
	gateCmd.Flags().StringVar(&uploadToken, "token", "", "API token (overrides config and HIBOU_TOKEN)")
	gateCmd.Flags().BoolVar(&gateFailOnGate, "fail-on-gate", false, "Exit non-zero when the gate does not pass (default: never break the build)")
	gateCmd.Flags().StringVar(&gateFailOnSev, "fail-on-severity", "", "Reserved: fail when findings at or above this severity exist (critical|high|medium|low)")
	gateCmd.Flags().DurationVar(&gateTimeout, "gate-timeout", 5*time.Minute, "Maximum time to wait for the gate to be evaluated")
}

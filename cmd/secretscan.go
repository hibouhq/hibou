package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
)

var (
	secretScanStaged   bool
	secretScanRange    string
	secretScanServer   string
	secretScanToken    string
	secretScanFailOpen bool
)

var secretScanCmd = &cobra.Command{
	Use:   "secret-scan",
	Short: "Check local changes for secrets before they reach the forge",
	Long: `Check local changes for secrets before they are committed or pushed.

The diff is submitted to the Hibou server, which scans it with the configured
detection engines and returns a verdict. Nothing is persisted server-side and
raw secret values never appear in the output — only hashes and locations.

Intended for git hooks:

  pre-commit:  hibou secret-scan --staged
  pre-push:    hibou secret-scan --range <remote-sha>..<local-sha>

Exit codes: 0 clean, 1 secrets found, 2 check unavailable (use --fail-open to
turn an unavailable check into exit 0 so an outage cannot block every push).`,
	RunE: runSecretScan,
}

func init() {
	secretScanCmd.Flags().BoolVar(&secretScanStaged, "staged", false, "Scan the staged diff (git diff --cached)")
	secretScanCmd.Flags().StringVar(&secretScanRange, "range", "", "Scan a commit range, e.g. origin/main..HEAD")
	secretScanCmd.Flags().StringVar(&secretScanServer, "server", "", "Hibou server URL (overrides config and HIBOU_SERVER)")
	secretScanCmd.Flags().StringVar(&secretScanToken, "token", "", "API token (overrides config and HIBOU_TOKEN)")
	secretScanCmd.Flags().BoolVar(&secretScanFailOpen, "fail-open", false, "Exit 0 when the check itself is unavailable")
}

func runSecretScan(cmd *cobra.Command, _ []string) error {
	cmd.SilenceUsage = true

	patch, err := collectSecretScanDiff()
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(patch)) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "Nothing to scan.")
		return nil
	}

	client, err := newSecretScanClient()
	if err != nil {
		return secretScanUnavailable(cmd, err)
	}

	var result struct {
		Block    bool `json:"block"`
		Findings []struct {
			Tool       string `json:"tool"`
			RuleID     string `json:"rule_id"`
			Severity   string `json:"severity"`
			FilePath   string `json:"file_path"`
			Line       int32  `json:"line"`
			SecretType string `json:"secret_type"`
			Verified   bool   `json:"verified"`
		} `json:"findings"`
	}
	if err := client.PostRaw("/secret-scan/check", "text/x-diff", bytes.NewReader(patch), &result); err != nil {
		return secretScanUnavailable(cmd, err)
	}

	if !result.Block {
		fmt.Fprintln(cmd.OutOrStdout(), "No secrets detected.")
		return nil
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "Blocked: %d secret finding(s) detected.\n", len(result.Findings))
	for _, finding := range result.Findings {
		verified := ""
		if finding.Verified {
			verified = " [VERIFIED LIVE]"
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "  %s:%d  %s (%s, %s)%s\n", finding.FilePath, finding.Line, finding.SecretType, finding.Tool, finding.Severity, verified)
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "Rotate anything already committed — history is not rewritten by removing the line.")
	return errSecretsDetected
}

var errSecretsDetected = errors.New("secrets detected")

func collectSecretScanDiff() ([]byte, error) {
	args := []string{"diff", "--no-color", "--cached"}
	if strings.TrimSpace(secretScanRange) != "" {
		if secretScanStaged {
			return nil, errors.New("--staged and --range are mutually exclusive")
		}
		args = []string{"diff", "--no-color", strings.TrimSpace(secretScanRange)}
	}
	output, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("collect diff (git %s): %w", strings.Join(args, " "), err)
	}
	return output, nil
}

func newSecretScanClient() (*cliclient.Client, error) {
	server := strings.TrimSpace(secretScanServer)
	if server == "" {
		server = strings.TrimSpace(os.Getenv("HIBOU_SERVER"))
	}
	token := strings.TrimSpace(secretScanToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("HIBOU_TOKEN"))
	}
	return cliclient.NewWithOverrides(server, token)
}

// secretScanUnavailable distinguishes "the check could not run" from "secrets
// found": a hook should be able to fail open on the former without ever
// failing open on the latter.
func secretScanUnavailable(cmd *cobra.Command, err error) error {
	if secretScanFailOpen {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: secret check unavailable, continuing (--fail-open): %v\n", err)
		return nil
	}
	return fmt.Errorf("secret check unavailable (re-run with --fail-open to continue anyway): %w", err)
}

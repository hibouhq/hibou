package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hibouhq/lehibou/internal/cliclient"
	"github.com/hibouhq/lehibou/internal/cliconfig"
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
}

var uploadCmd = &cobra.Command{
	Use:   "upload <file> [file...]",
	Short: "Upload security artifacts to Hibou",
	Long: `Upload SBOM, SARIF, or coverage artifacts to Hibou. The artifact type is auto-detected from file content.
Accepts multiple files — each is uploaded separately.

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
	org := strings.TrimSpace(uploadOrg)
	if org == "" {
		cfg, _ := cliconfig.Load()
		org = strings.TrimSpace(cfg.Org)
	}
	if uploadProvider != "" && org == "" {
		return uploadBase{}, errors.New("--provider is deprecated, use --org provider/slug")
	}
	if org == "" {
		return uploadBase{}, errors.New("--org is required (or set default with 'hibou config set-org')")
	}
	if uploadRepo == "" {
		return uploadBase{}, errors.New("--repo is required")
	}
	if uploadRef == "" {
		return uploadBase{}, errors.New("--ref is required")
	}
	if uploadCommitSHA == "" {
		return uploadBase{}, errors.New("--sha is required")
	}

	parts := strings.SplitN(org, "/", 2)
	if len(parts) != 2 {
		return uploadBase{}, errors.New("org must be in 'provider/slug' format (e.g., 'forgejo/devtools')")
	}

	return uploadBase{provider: parts[0], org: parts[1]}, nil
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

	payload := map[string]any{
		"provider":   base.provider,
		"org":        base.org,
		"repo":       uploadRepo,
		"ref":        uploadRef,
		"commit_sha": uploadCommitSHA,
		"complete":   complete,
		"artifact": map[string]string{
			"filename":       filepath.Base(file),
			"content_base64": base64.StdEncoding.EncodeToString(data),
		},
	}
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

	payload := map[string]any{
		"provider":   base.provider,
		"org":        base.org,
		"repo":       uploadRepo,
		"ref":        uploadRef,
		"commit_sha": uploadCommitSHA,
		"complete":   true,
	}

	fmt.Println("--- Completing snapshot")
	return submitUpload(client, "/upload", payload)
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

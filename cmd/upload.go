package cmd

import (
	"encoding/base64"
	"encoding/json"
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
	uploadProvider  string
	uploadOrg       string
	uploadRepo      string
	uploadRef       string
	uploadCommitSHA string
	uploadTool      string
	uploadServer    string
	uploadToken     string
)

type uploadBase struct {
	provider string
	org      string
}

var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload security artifacts to Hibou",
}

var uploadSBOMCmd = &cobra.Command{
	Use:   "sbom <file>",
	Short: "Upload an SBOM file (CycloneDX or SPDX)",
	Long: `Upload a Software Bill of Materials to Hibou for analysis.

Examples:
  hibou upload sbom sbom.json --org forgejo/devtools --repo myapp --ref refs/heads/main --sha abc123

  # With format auto-detection from file content
  hibou upload sbom sbom.cdx.json --org forgejo/devtools --repo myapp --ref refs/heads/main --sha abc123

Environment variables (for CI):
  HIBOU_SERVER     Server URL
  HIBOU_TOKEN      API token`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUploadSBOM(args[0])
	},
}

var uploadSARIFCmd = &cobra.Command{
	Use:   "sarif <file>",
	Short: "Upload a SARIF file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUploadSARIF(args[0])
	},
}

var uploadFindingsCmd = &cobra.Command{
	Use:   "findings <file>",
	Short: "Upload generic findings",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUploadFindings(args[0])
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

func runUploadSBOM(file string) error {
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
		"format":     detectSBOMFormat(file),
		"artifact": map[string]string{
			"filename":       filepath.Base(file),
			"content_base64": base64.StdEncoding.EncodeToString(data),
		},
	}

	return submitUpload(client, "/upload/sbom", payload)
}

func runUploadSARIF(file string) error {
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

	toolName := strings.TrimSpace(uploadTool)
	if toolName == "" {
		toolName = strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	}

	payload := map[string]any{
		"provider":   base.provider,
		"org":        base.org,
		"repo":       uploadRepo,
		"ref":        uploadRef,
		"commit_sha": uploadCommitSHA,
		"tool":       toolName,
		"artifact": map[string]string{
			"filename":       filepath.Base(file),
			"content_base64": base64.StdEncoding.EncodeToString(data),
		},
	}

	return submitUpload(client, "/upload/sarif", payload)
}

func runUploadFindings(file string) error {
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

	toolName := strings.TrimSpace(uploadTool)
	if toolName == "" {
		return errors.New("--tool is required for findings upload")
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(data, &findings); err != nil {
		return fmt.Errorf("findings file must be a valid JSON array: %w", err)
	}

	payload := map[string]any{
		"provider":   base.provider,
		"org":        base.org,
		"repo":       uploadRepo,
		"ref":        uploadRef,
		"commit_sha": uploadCommitSHA,
		"tool":       toolName,
		"findings":   findings,
	}

	return submitUpload(client, "/upload/findings", payload)
}

func detectSBOMFormat(file string) string {
	lower := strings.ToLower(filepath.Base(file))
	switch {
	case strings.Contains(lower, "cdx") || strings.Contains(lower, "cyclonedx"):
		if strings.HasSuffix(lower, ".xml") {
			return "cyclonedx-xml"
		}
		return "cyclonedx-json"
	case strings.HasSuffix(lower, ".xml"):
		return "cyclonedx-xml"
	default:
		return "spdx-json"
	}
}

func init() {
	for _, command := range []*cobra.Command{uploadSBOMCmd, uploadSARIFCmd, uploadFindingsCmd} {
		command.Flags().StringVar(&uploadOrg, "org", "", "Organization (provider/slug, e.g., 'forgejo/devtools')")
		command.Flags().StringVar(&uploadRepo, "repo", "", "Repository slug")
		command.Flags().StringVar(&uploadRef, "ref", "", "Git ref (e.g., refs/heads/main)")
		command.Flags().StringVar(&uploadCommitSHA, "sha", "", "Commit SHA")
		command.Flags().StringVar(&uploadProvider, "provider", "", "Forge provider (deprecated, use --org)")
		command.Flags().StringVar(&uploadServer, "server", "", "Hibou server URL (overrides config and HIBOU_SERVER)")
		command.Flags().StringVar(&uploadToken, "token", "", "API token (overrides config and HIBOU_TOKEN)")
	}
	uploadSARIFCmd.Flags().StringVar(&uploadTool, "tool", "", "Tool name (e.g., semgrep, codeql)")
	uploadFindingsCmd.Flags().StringVar(&uploadTool, "tool", "", "Tool name (required)")

	uploadCmd.AddCommand(uploadSBOMCmd, uploadSARIFCmd, uploadFindingsCmd)
}

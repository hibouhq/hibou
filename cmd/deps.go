package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/cliconfig"
)

// `hibou deps ...` works on whatever it is pointed at and never writes to
// Hibou (ADR-046 §1). Recording happens under `hibou release ...`.

var depsCmd = &cobra.Command{
	Use:   "deps",
	Short: "Dependency inventories: local scans, stored data, SBOM verification (never writes to Hibou)",
	Long: `Local analysis and read-only views of dependency inventories (ADR-046).

  hibou deps scan                     analyse a directory, a lockfile, an archive, a binary, an image
  hibou deps list --repo api          what Hibou knows about a ref, tag, release or PR
  hibou deps diff --repo api v1 v2    what changed between two refs
  hibou deps verify app.war --sbom x  does an SBOM describe this deliverable? (offline)
  hibou deps check                    would the package policy hold anything in this tree? (CI pre-install step)
  hibou deps cooldown init            write the install-time cooldown settings (npm, pnpm, Yarn, Bun, uv, pip)
  hibou deps not-shipped ...          the repository's not-shipped list

Nothing here stores anything on the server; "hibou release scan" records.`,
}

// Common flags of the deps commands.
var (
	depsOrg    string
	depsRepo   string
	depsServer string
	depsToken  string
)

func init() {
	for _, c := range []*cobra.Command{depsScanCmd, depsListCmd, depsDiffCmd, depsCheckCmd, depsNotShippedCmd, vulnsListCmd} {
		c.PersistentFlags().StringVar(&depsOrg, "org", "", "Organization (provider/slug); default from 'hibou config set-org' or HIBOU_ORG")
		c.PersistentFlags().StringVar(&depsRepo, "repo", "", "Repository slug; default from the git remote of the current directory")
		c.PersistentFlags().StringVar(&depsServer, "server", "", "Hibou server URL (default HIBOU_SERVER or the stored login)")
		c.PersistentFlags().StringVar(&depsToken, "token", "", "API token (default HIBOU_TOKEN or the stored login)")
	}
	depsCmd.AddCommand(depsScanCmd, depsListCmd, depsDiffCmd, depsVerifyCmd, depsCheckCmd, depsCooldownCmd, depsNotShippedCmd)
	vulnsCmd.AddCommand(vulnsListCmd)
}

var vulnsCmd = &cobra.Command{
	Use:   "vulns",
	Short: "Findings of a ref, tag, release or pull request (read-only)",
}

// depsClient resolves the client with the deps flags.
func depsClient() (*cliclient.Client, error) {
	server := strings.TrimSpace(depsServer)
	if server == "" {
		server = strings.TrimSpace(os.Getenv("HIBOU_SERVER"))
	}
	token := strings.TrimSpace(depsToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("HIBOU_TOKEN"))
	}
	return cliclient.NewWithOverrides(server, token)
}

// depsOrgSlug resolves provider/slug.
func depsOrgSlug() (string, error) {
	if org := strings.TrimSpace(depsOrg); org != "" {
		if !strings.Contains(org, "/") {
			return "", errors.New("--org must be provider/slug")
		}
		return org, nil
	}
	if org := strings.TrimSpace(os.Getenv("HIBOU_ORG")); org != "" {
		return org, nil
	}
	cfg, _ := cliconfig.Load()
	if cfg.Org != "" {
		return cfg.Org, nil
	}
	if ci := resolveUploadContext(); ci.org != "" {
		return ci.org, nil
	}
	return "", errors.New("--org is required (or 'hibou config set-org provider/slug', or HIBOU_ORG)")
}

// depsRepoSlug resolves the repository: the flag, the CI context, then
// the git remote of the current directory.
func depsRepoSlug() (string, error) {
	if repo := strings.TrimSpace(depsRepo); repo != "" {
		return repo, nil
	}
	if ci := resolveUploadContext(); ci.repo != "" {
		return ci.repo, nil
	}
	if remote := gitRemoteRepoSlug("."); remote != "" {
		return remote, nil
	}
	return "", errors.New("--repo is required (not inferable from CI or the git remote)")
}

// depsRepoPath is /orgs/{provider}/{slug}/repos/{repo}.
func depsRepoPath() (string, error) {
	org, err := depsOrgSlug()
	if err != nil {
		return "", err
	}
	repo, err := depsRepoSlug()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/orgs/%s/repos/%s", org, repo), nil
}

// gitRemoteRepoSlug reads the origin remote's repository name.
func gitRemoteRepoSlug(dir string) string {
	output, _, err := execCommandOutput(dir, "git", "config", "--get", "remote.origin.url")
	if err != nil {
		return ""
	}
	url := strings.TrimSpace(string(output))
	url = strings.TrimSuffix(url, ".git")
	if idx := strings.LastIndexAny(url, "/:"); idx >= 0 {
		return url[idx+1:]
	}
	return ""
}

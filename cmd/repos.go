package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/cliconfig"
)

var reposCmd = &cobra.Command{
	Use:   "repos",
	Short: "Manage repositories",
}

var reposListCmd = &cobra.Command{
	Use:   "list",
	Short: "List repositories in the current organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := cliclient.New()
		if err != nil {
			return err
		}

		org, err := resolveOrg()
		if err != nil {
			return err
		}

		var repos []struct {
			Slug          string `json:"slug"`
			Name          string `json:"name"`
			DefaultBranch string `json:"default_branch"`
			SyncState     string `json:"sync_state"`
		}
		if err := client.Get(fmt.Sprintf("/orgs/%s/repos", org), &repos); err != nil {
			return err
		}

		if len(repos) == 0 {
			fmt.Println("No repositories found.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SLUG\tNAME\tBRANCH\tSTATUS")
		for _, repo := range repos {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", repo.Slug, repo.Name, repo.DefaultBranch, repo.SyncState)
		}
		return w.Flush()
	},
}

var reposShowCmd = &cobra.Command{
	Use:   "show <slug>",
	Short: "Show repository details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := cliclient.New()
		if err != nil {
			return err
		}

		org, err := resolveOrg()
		if err != nil {
			return err
		}

		var repo json.RawMessage
		if err := client.Get(fmt.Sprintf("/orgs/%s/repos/%s", org, args[0]), &repo); err != nil {
			return err
		}

		var formatted bytes.Buffer
		if err := json.Indent(&formatted, repo, "", "  "); err != nil {
			fmt.Println(string(repo))
			return nil
		}

		fmt.Println(formatted.String())
		return nil
	},
}

func resolveOrg() (string, error) {
	cfg, _ := cliconfig.Load()
	org := cfg.Org
	if org == "" {
		return "", errors.New("no default org set — use 'hibou config set-org <provider/slug>'")
	}
	return org, nil
}

func init() {
	reposCmd.AddCommand(reposListCmd, reposShowCmd)
}

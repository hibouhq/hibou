package cmd

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
)

var releaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Follow and roll out releases",
	Long: `Releases are derived, never hand-created (ADR-024): a version tag
(v1.2.3) whose analysis is uploaded, or a forge release event, materializes
the release automatically. These commands follow them and record rollouts.`,
}

var releaseListRepo string

var releaseListCmd = &cobra.Command{
	Use:   "list",
	Short: "List releases of a repository with their open-risk posture",
	RunE: func(cmd *cobra.Command, args []string) error {
		if releaseListRepo == "" {
			return errors.New("--repo is required")
		}

		client, err := cliclient.New()
		if err != nil {
			return err
		}
		org, err := resolveOrg()
		if err != nil {
			return err
		}

		var releases []struct {
			Version          string     `json:"version"`
			SnapshotID       *string    `json:"snapshot_id"`
			CriticalCount    int64      `json:"critical_count"`
			HighCount        int64      `json:"high_count"`
			MediumCount      int64      `json:"medium_count"`
			LowCount         int64      `json:"low_count"`
			OpenFindingCount int64      `json:"open_finding_count"`
			PublishedAt      *time.Time `json:"published_at"`
			Clients          []struct {
				Slug string `json:"slug"`
			} `json:"clients"`
		}
		if err := client.Get(fmt.Sprintf("/orgs/%s/repos/%s/releases", org, releaseListRepo), &releases); err != nil {
			return err
		}

		if len(releases) == 0 {
			fmt.Println("No releases found.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "VERSION\tPUBLISHED\tRISK (C/H/M/L)\tOPEN\tCLIENTS")
		for _, release := range releases {
			published := "-"
			if release.PublishedAt != nil {
				published = release.PublishedAt.Format("2006-01-02")
			}
			risk := fmt.Sprintf("%d/%d/%d/%d", release.CriticalCount, release.HighCount, release.MediumCount, release.LowCount)
			if release.SnapshotID == nil {
				risk = "not analyzed"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\n", release.Version, published, risk, release.OpenFindingCount, len(release.Clients))
		}
		return w.Flush()
	},
}

var (
	releaseDeployRepo    string
	releaseDeployVersion string
	releaseDeployClient  string
	releaseDeployEnv     string
	releaseDeployNotes   string
)

var releaseDeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Record that a client runs a release",
	Long: `Record an active deployment of a release for an org client. The client's
active deployment of any other release of the same repository in the same
environment is marked superseded. Meant for deploy pipelines:

  hibou release deploy --repo payments-api --version v7.5.2 --client acme --env production`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if releaseDeployRepo == "" || releaseDeployVersion == "" || releaseDeployClient == "" {
			return errors.New("--repo, --version and --client are required")
		}

		client, err := cliclient.New()
		if err != nil {
			return err
		}
		org, err := resolveOrg()
		if err != nil {
			return err
		}

		// Resolve the version to its release ID via the listing filter.
		var releases []struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		}
		if err := client.Get(fmt.Sprintf("/orgs/%s/repos/%s/releases?q=%s", org, releaseDeployRepo, releaseDeployVersion), &releases); err != nil {
			return err
		}
		releaseID := ""
		for _, release := range releases {
			if release.Version == releaseDeployVersion {
				releaseID = release.ID
				break
			}
		}
		if releaseID == "" {
			return fmt.Errorf("release %q not found in %s", releaseDeployVersion, releaseDeployRepo)
		}

		payload := map[string]any{"client_slug": releaseDeployClient}
		if releaseDeployEnv != "" {
			payload["environment"] = releaseDeployEnv
		}
		if releaseDeployNotes != "" {
			payload["notes"] = releaseDeployNotes
		}

		var deployment struct {
			ID          string `json:"id"`
			Environment string `json:"environment"`
		}
		if err := client.Post(fmt.Sprintf("/orgs/%s/repos/%s/releases/%s/clients", org, releaseDeployRepo, releaseID), payload, &deployment); err != nil {
			return err
		}

		fmt.Printf("deployment recorded: %s runs %s in %s\n", releaseDeployClient, releaseDeployVersion, deployment.Environment)
		return nil
	},
}

func init() {
	releaseListCmd.Flags().StringVar(&releaseListRepo, "repo", "", "repository slug (required)")

	releaseDeployCmd.Flags().StringVar(&releaseDeployRepo, "repo", "", "repository slug (required)")
	releaseDeployCmd.Flags().StringVar(&releaseDeployVersion, "version", "", "release version (required)")
	releaseDeployCmd.Flags().StringVar(&releaseDeployClient, "client", "", "org client slug (required)")
	releaseDeployCmd.Flags().StringVar(&releaseDeployEnv, "env", "", "environment (default: production)")
	releaseDeployCmd.Flags().StringVar(&releaseDeployNotes, "notes", "", "rollout notes")

	releaseCmd.AddCommand(releaseListCmd, releaseDeployCmd)
}

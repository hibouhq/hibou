package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/advisorydb"
)

// hibou vulns db export (ADR-046 step 6): the organisation's advisory
// view as one file, for `hibou deps scan --advisory-db` on a runner that
// cannot reach the server. Only advisories leave: no repository data.

var (
	vulnsExportOut        string
	vulnsExportEcosystems []string
)

var vulnsDBCmd = &cobra.Command{
	Use:   "db",
	Short: "The offline advisory database",
}

var vulnsDBExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the organization's advisories for offline scans (hibou deps scan --advisory-db)",
	Long: `Writes the organization's advisory database as newline-delimited JSON:
advisories with their affected ranges, ratings, aliases, exploited-catalog
flag and EPSS score. Copy the file to the air-gapped runner and pass it
to 'hibou deps scan --advisory-db'. The file carries no repository data:
VEX statements, not-shipped lists and package signals stay on the server.
The export is audit-logged.

  hibou vulns db export --out advisories.ndjson
  hibou vulns db export --ecosystem npm --ecosystem maven --out advisories.ndjson`,
	RunE: func(_ *cobra.Command, _ []string) error {
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		org, err := depsOrgSlug()
		if err != nil {
			return exitError{2, err}
		}
		out := strings.TrimSpace(vulnsExportOut)
		if out == "" {
			return exitError{2, errors.New("--out is required")}
		}
		query := ""
		if len(vulnsExportEcosystems) > 0 {
			query = "?ecosystem=" + strings.Join(vulnsExportEcosystems, ",")
		}
		body, err := client.GetStream(fmt.Sprintf("/orgs/%s/advisories/export%s", org, query), "application/x-ndjson")
		if err != nil {
			return exitError{2, err}
		}
		defer body.Close()
		if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
			return exitError{2, err}
		}
		tmp := out + ".part"
		f, err := os.Create(tmp) // #nosec G304 -- a file the user named
		if err != nil {
			return exitError{2, err}
		}
		written, copyErr := io.Copy(f, body)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil {
			_ = os.Remove(tmp)
			return exitError{2, errors.Join(copyErr, closeErr)}
		}
		// Reading the file back checks the stream was complete and the
		// format is one this CLI understands before it replaces anything.
		db, err := advisorydb.Load(tmp)
		if err != nil {
			_ = os.Remove(tmp)
			return exitError{2, fmt.Errorf("the export is not readable: %w", err)}
		}
		if err := os.Rename(tmp, out); err != nil {
			_ = os.Remove(tmp)
			return exitError{2, err}
		}
		fmt.Printf("Wrote %s: %d advisories, %d bytes, exported %s", out, db.Advisories(), written, db.Header.ExportedAt.Format("2 Jan 2006 15:04 MST"))
		if len(db.Header.Ecosystems) > 0 {
			fmt.Printf(" (%s)", strings.Join(db.Header.Ecosystems, ", "))
		}
		fmt.Println()
		fmt.Println("Use it with: hibou deps scan --advisory-db " + out)
		return nil
	},
}

func init() {
	vulnsDBExportCmd.Flags().StringVar(&vulnsExportOut, "out", "", "File to write")
	vulnsDBExportCmd.Flags().StringArrayVar(&vulnsExportEcosystems, "ecosystem", nil, "Limit to these ecosystems (repeatable); default: every one")
}

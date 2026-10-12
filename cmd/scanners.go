package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/scanbundle"
	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scanrun"
)

var (
	bundleOut       string
	bundlePlatforms []string
	bundleScanners  []string
	bundleInto      string
)

var scannersCmd = &cobra.Command{
	Use:   "scanners",
	Short: "Bundled scanner catalog and offline bundles",
}

var scannersBundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Prepare and import offline scanner bundles (ADR-035)",
}

var scannersBundleExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Download, verify and lay out this version's catalog artifacts for an air-gapped installation",
	Long: `Run on a connected machine with the same hibou version as the air-gapped server.
Every artifact is checked against the catalog's sha256 before it enters the bundle.
Transfer the output directory, then run 'hibou scanners bundle import' there and point
scanner_distribution.bundle_dir at the import target.

Example:
  hibou scanners bundle export --out ./bundle --platform linux/amd64 --platform linux/arm64`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cmd.SilenceUsage = true
		catalog, err := scancatalog.Load()
		if err != nil {
			return err
		}
		if bundleOut == "" {
			return errors.New("--out is required")
		}
		cache, err := os.MkdirTemp("", "hibou-bundle-cache-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(cache)
		manifest, err := scanbundle.Export(cmd.Context(), catalog, scanbundle.ExportOptions{
			OutDir: bundleOut, Scanners: bundleScanners, Platforms: bundlePlatforms,
			Fetcher: &scanrun.Fetcher{CacheDir: cache},
		})
		if err != nil {
			return err
		}
		fmt.Printf("Exported %d artifact(s) for catalog %s to %s\n", len(manifest.Artifacts), manifest.CatalogRevision, bundleOut)
		for _, missing := range manifest.Missing {
			fmt.Printf("  not available: %s (no verified build for that platform)\n", missing)
		}
		return nil
	},
}

var scannersBundleImportCmd = &cobra.Command{
	Use:   "import <bundle-dir>",
	Short: "Verify a bundle against this version's catalog and copy it into the read-only store",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		catalog, err := scancatalog.Load()
		if err != nil {
			return err
		}
		if bundleInto == "" || !filepath.IsAbs(bundleInto) {
			return errors.New("--into must be an absolute path (the server's scanner_distribution.bundle_dir)")
		}
		manifest, err := scanbundle.Import(catalog, args[0], bundleInto)
		if err != nil {
			return err
		}
		fmt.Printf("Imported %d verified artifact(s) into %s\n", len(manifest.Artifacts), bundleInto)
		for _, missing := range manifest.Missing {
			fmt.Printf("  not in this bundle: %s\n", missing)
		}
		return nil
	},
}

func init() {
	scannersBundleExportCmd.Flags().StringVar(&bundleOut, "out", "", "Output directory")
	scannersBundleExportCmd.Flags().StringArrayVar(&bundlePlatforms, "platform", nil, "Runner platform os/arch (repeatable, at least one)")
	scannersBundleExportCmd.Flags().StringArrayVar(&bundleScanners, "scanner", nil, "Export these scanners only (repeatable)")
	scannersBundleImportCmd.Flags().StringVar(&bundleInto, "into", "", "Absolute store directory (scanner_distribution.bundle_dir)")
	scannersBundleCmd.AddCommand(scannersBundleExportCmd, scannersBundleImportCmd)
	scannersCmd.AddCommand(scannersBundleCmd)
}

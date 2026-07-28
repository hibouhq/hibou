package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hibou",
	Short: "Unified DevSecOps security platform",
	Long:  `Hibou is a unified DevSecOps security platform that ingests SBOMs, SARIF, and generic findings to provide comprehensive security intelligence across your organization.`,
	// Execute below already reports the error, so cobra must not print it a
	// second time. Usage stays enabled here so genuine argument errors still
	// show the flag reference; commands silence it once their args validate.
	SilenceErrors: true,
}

func personality() string {
	base := filepath.Base(os.Args[0])
	base = strings.TrimSuffix(base, ".exe")
	if base == "" || base == "." {
		return "hibou"
	}

	return base
}

func init() {
	rootCmd.AddCommand(completionCmd, versionCmd)

	p := personality()
	switch p {
	case "hibou":
		rootCmd.Use = "hibou"
		rootCmd.Short = "Unified DevSecOps security platform"
		rootCmd.AddCommand(loginCmd, logoutCmd, statusCmd, uploadCmd, gateCmd, reposCmd, configCmd, secretScanCmd)
	case "hibou-server":
		rootCmd.Use = "hibou-server"
		rootCmd.Short = "Hibou server - API, workers, and MCP endpoint"
		rootCmd.AddCommand(serveCmd, seedCmd)
	default:
		rootCmd.Use = "hibou"
		rootCmd.Short = "Unified DevSecOps security platform"
		rootCmd.AddCommand(serveCmd, seedCmd, loginCmd, logoutCmd, statusCmd, uploadCmd, gateCmd, reposCmd, configCmd, secretScanCmd)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

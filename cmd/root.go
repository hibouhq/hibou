package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hibou",
	Short: "Unified DevSecOps security platform",
	Long:  `Hibou is a unified DevSecOps security platform that ingests SBOMs, SARIF, and generic findings to provide comprehensive security intelligence across your organization.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

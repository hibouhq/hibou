package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server, SPA, workers, and MCP endpoint",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Starting hibou server...")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
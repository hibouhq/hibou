package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"

	buildversion "github.com/hibouhq/lehibou/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("hibou %s (commit: %s, built: %s)\n", buildversion.Version, buildversion.Commit, buildversion.Date)
		if info, ok := debug.ReadBuildInfo(); ok {
			fmt.Printf("go: %s\n", info.GoVersion)
		}
	},
}

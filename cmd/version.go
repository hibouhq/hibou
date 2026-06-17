package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"

	buildversion "github.com/hibouhq/hibou/internal/version"
)

var versionShort bool

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		// --short prints only the bare version string so tooling (e.g. the
		// hibou-upload CI action) can compare it against /api/v1/bin/version.
		if versionShort {
			fmt.Println(buildversion.Version)
			return
		}
		fmt.Printf("hibou %s (commit: %s, built: %s)\n", buildversion.Version, buildversion.Commit, buildversion.Date)
		if info, ok := debug.ReadBuildInfo(); ok {
			fmt.Printf("go: %s\n", info.GoVersion)
		}
	},
}

func init() {
	versionCmd.Flags().BoolVar(&versionShort, "short", false, "Print only the version string")
}

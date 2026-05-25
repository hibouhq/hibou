package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hibouhq/lehibou/internal/cliconfig"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := cliconfig.Load()
		if err != nil {
			return err
		}

		cfg.Token = ""
		if err := cliconfig.Save(cfg); err != nil {
			return err
		}

		fmt.Println("Logged out. Token cleared.")
		return nil
	},
}

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hibouhq/lehibou/internal/cliclient"
	"github.com/hibouhq/lehibou/internal/cliconfig"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current authentication status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := cliconfig.Load()
		if err != nil {
			return err
		}

		if cfg.Server == "" {
			fmt.Println("Not logged in. Run 'hibou login' to get started.")
			return nil
		}

		fmt.Printf("Server:  %s\n", cfg.Server)
		if cfg.Org != "" {
			fmt.Printf("Org:     %s\n", cfg.Org)
		}
		fmt.Printf("Config:  %s\n", cliconfig.DefaultPath())

		if cfg.Token == "" {
			fmt.Println("Status:  not authenticated (no token)")
			return nil
		}

		client, err := cliclient.New()
		if err != nil {
			fmt.Printf("Status:  %s\n", err)
			return nil
		}

		var user struct {
			DisplayName string `json:"display_name"`
			Email       string `json:"email"`
		}
		if err := client.Get("/users/me", &user); err != nil {
			fmt.Printf("Status:  error — %s\n", err)
			return nil
		}

		fmt.Printf("User:    %s (%s)\n", user.DisplayName, user.Email)
		fmt.Println("Status:  authenticated")
		return nil
	},
}

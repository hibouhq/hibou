package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliconfig"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage CLI configuration",
}

var configSetOrgCmd = &cobra.Command{
	Use:   "set-org <provider/slug>",
	Short: "Set the default organization context",
	Long: `Set the default organization for CLI commands.

Examples:
  hibou config set-org forgejo/devtools
  hibou config set-org github/my-org`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		org := strings.TrimSpace(args[0])
		parts := strings.SplitN(org, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("org must be in 'provider/slug' format (e.g., 'forgejo/devtools')")
		}

		cfg, err := cliconfig.Load()
		if err != nil {
			return err
		}
		cfg.Org = org
		if err := cliconfig.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("Default org set to %s\n", org)
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current CLI configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := cliconfig.Load()
		if err != nil {
			return err
		}

		fmt.Printf("Config file: %s\n", cliconfig.DefaultPath())
		fmt.Printf("Server:      %s\n", valueOrNone(cfg.Server))
		fmt.Printf("Token:       %s\n", maskToken(cfg.Token))
		fmt.Printf("Org:         %s\n", valueOrNone(cfg.Org))
		return nil
	},
}

func valueOrNone(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

func maskToken(token string) string {
	if token == "" {
		return "(not set)"
	}
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "..." + token[len(token)-4:]
}

func init() {
	configCmd.AddCommand(configSetOrgCmd, configShowCmd)
}

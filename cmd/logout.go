package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliconfig"
)

var logoutKeepToken bool

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear stored credentials and revoke the browser-login token",
	Long: `Clear the stored token. A token from browser login (hibou login in a
terminal) is also revoked on the server, so it stops working everywhere.
A token you pasted is only cleared locally: it may be in use elsewhere,
so revoke it under Settings > API Keys if you no longer need it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := cliconfig.Load()
		if err != nil {
			return err
		}
		if cfg.Token == "" {
			fmt.Println("Not logged in.")
			return nil
		}

		switch {
		case logoutKeepToken:
		case cfg.TokenID != "" && cfg.Server != "":
			if err := revokeCurrentToken(cfg.Server, cfg.Token); err != nil {
				fmt.Printf("warning: could not revoke the token on %s (%v); revoke it at %s/settings/api-keys\n", cfg.Server, err, cfg.Server)
			} else {
				fmt.Println("Token revoked on the server.")
			}
		case cfg.Server != "":
			fmt.Printf("This token was pasted, not created by browser login: it stays valid until you revoke it at %s/settings/api-keys\n", cfg.Server)
		}

		cfg.Token = ""
		cfg.TokenID = ""
		if err := cliconfig.Save(cfg); err != nil {
			return err
		}
		fmt.Println("Logged out. Token cleared.")
		return nil
	},
}

func init() {
	logoutCmd.Flags().BoolVar(&logoutKeepToken, "keep-token", false, "Only clear the local copy; leave the token valid on the server")
}

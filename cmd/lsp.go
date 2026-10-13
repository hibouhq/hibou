package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/lsp"
	buildversion "github.com/hibouhq/hibou/internal/version"
)

var lspStdio bool

var lspCmd = &cobra.Command{
	Use:   "lsp",
	Short: "Run the hibou language server (stdio) for IDEs",
	Long: `Run the hibou language server used by the VS Code and IntelliJ extensions.
It shows hibou findings as diagnostics in the files they were found
in, mapped onto your working copy with git, and offers native suppression
directives and triage as code actions. No source code is sent to the server.

The protocol runs over stdin/stdout. Any LSP client can use it, for example
Neovim:

  vim.lsp.start({ name = "hibou", cmd = { "hibou", "lsp" }, root_dir = vim.fs.root(0, ".git") })

Credentials: the server URL comes from initializationOptions.server,
HIBOU_SERVER, or 'hibou login'; the token from HIBOU_TOKEN or 'hibou login'
(for the same server). Logs go to stderr.`,
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return lsp.Run(ctx, lsp.Config{
			In:      os.Stdin,
			Out:     os.Stdout,
			Log:     os.Stderr,
			Version: buildversion.Version,
		})
	},
}

func init() {
	// Accepted for clients that always pass it (vscode-languageclient's stdio
	// transport does); stdio is the only transport.
	lspCmd.Flags().BoolVar(&lspStdio, "stdio", true, "Use stdin/stdout (the only transport)")
	rootCmd.AddCommand(lspCmd)
}

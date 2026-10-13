package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/cliconfig"
)

var loginServer string
var loginToken string
var loginSSO bool
var loginTokenStdin bool
var loginAllowInsecureHTTP bool

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with a Hibou server",
	Long: `Log in to a Hibou server by providing the server URL and an API token.

You can get an API token from the Hibou web UI under Settings > API Keys.

Examples:
  # Interactive login
  hibou login

  # Non-interactive: pipe the token (stays out of shell history)
  printf '%s' "$HIBOU_TOKEN" | hibou login --server https://hibou.example.com --token-stdin

  # --token also works, but the token lands in your shell history
  hibou login --server https://hibou.example.com --token hb_xxxxx

  # Open the browser to create a token interactively
  hibou login --sso

Environment variables:
  HIBOU_SERVER    Server URL
  HIBOU_TOKEN     API token`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := cliconfig.Load()
		if err != nil {
			cfg = cliconfig.Config{}
		}

		server := strings.TrimSpace(loginServer)
		if server == "" {
			server = strings.TrimSpace(os.Getenv("HIBOU_SERVER"))
		}
		if server == "" {
			server = strings.TrimSpace(cfg.Server)
		}
		if server == "" {
			fmt.Print("Hibou server URL: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				server = strings.TrimSpace(scanner.Text())
			}
		}
		if server == "" {
			return errors.New("server URL is required")
		}
		server = strings.TrimRight(server, "/")
		if err := checkLoginServerURL(server, loginAllowInsecureHTTP); err != nil {
			return err
		}

		if loginSSO {
			settingsURL := server + "/settings"
			if err := openBrowser(settingsURL); err != nil {
				fmt.Printf("Open your browser to: %s\n", settingsURL)
			} else {
				fmt.Printf("Opened %s\n", settingsURL)
			}
			fmt.Println("1. Sign in with your SSO provider")
			fmt.Println("2. Open Settings > API Keys")
			fmt.Println("3. Create a new API key")
			fmt.Printf("4. Run: hibou login --server %s --token <your-key>\n", server)
			return nil
		}

		token := strings.TrimSpace(loginToken)
		if token != "" {
			fmt.Fprintln(os.Stderr, "warning: --token leaves the token in your shell history; prefer --token-stdin, HIBOU_TOKEN or the prompt")
		}
		if token == "" && loginTokenStdin {
			raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
			if err != nil {
				return fmt.Errorf("read token from stdin: %w", err)
			}
			token = strings.TrimSpace(string(raw))
		}
		if token == "" {
			token = strings.TrimSpace(os.Getenv("HIBOU_TOKEN"))
		}
		if token == "" {
			fmt.Print("API token (input hidden): ")
			read, err := readSecretLine()
			fmt.Println()
			if err != nil {
				return fmt.Errorf("read token: %w", err)
			}
			token = read
		}
		if token == "" {
			return fmt.Errorf("API token is required — create one at %s/settings", server)
		}

		fmt.Print("Verifying credentials... ")
		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequest(http.MethodGet, server+"/api/v1/users/me", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("x")
			return fmt.Errorf("could not reach server: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Println("x")
			return fmt.Errorf("authentication failed (HTTP %d) — check your token", resp.StatusCode)
		}
		fmt.Println("ok")

		cfg.Server = server
		cfg.Token = token
		if err := cliconfig.Save(cfg); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		fmt.Printf("Logged in to %s\n", server)
		fmt.Printf("Config saved to %s\n", cliconfig.DefaultPath())
		return nil
	},
}

func init() {
	loginCmd.Flags().StringVar(&loginServer, "server", "", "Hibou server URL")
	loginCmd.Flags().StringVar(&loginToken, "token", "", "API token")
	loginCmd.Flags().BoolVar(&loginSSO, "sso", false, "Open the browser to complete SSO login and create an API token")
	loginCmd.Flags().BoolVar(&loginTokenStdin, "token-stdin", false, "Read the API token from standard input")
	loginCmd.Flags().BoolVar(&loginAllowInsecureHTTP, "insecure-http", false, "Allow a plain http:// server that is not localhost (the token is sent in clear text)")
}

// checkLoginServerURL refuses to send a token over plain HTTP, except to a
// loopback server (local development) or with an explicit opt-in.
func checkLoginServerURL(server string, allowInsecure bool) error {
	parsed, err := url.Parse(server)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid server URL %q: expected https://host", server)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopbackHost(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("refusing to send an API token over plain HTTP to %s: use https:// (or --insecure-http if you accept the risk)", parsed.Host)
	default:
		return fmt.Errorf("invalid server URL %q: scheme must be https", server)
	}
}

func isLoopbackHost(host string) bool { return cliclient.IsLoopbackHost(host) }

// readSecretLine reads one line from stdin without echoing it when stdin is a
// terminal (stty, on Unix-like systems). Elsewhere, or when stdin is piped,
// the line is read as is.
func readSecretLine() (string, error) {
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 && runtime.GOOS != "windows" {
		if err := runStty("-echo"); err == nil {
			defer func() { _ = runStty("echo") }()
		}
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func runStty(arg string) error {
	cmd := exec.Command("stty", arg) // #nosec G204 -- constant binary, fixed arguments.
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func openBrowser(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("invalid URL: %s", rawURL)
	}
	cleanURL := parsed.String()

	if browser := strings.TrimSpace(os.Getenv("BROWSER")); browser != "" {
		return exec.Command(filepath.Base(browser), cleanURL).Start() // #nosec G204 G702 -- browser from user's $BROWSER env
	}

	switch runtime.GOOS {
	case "darwin":
		// #nosec G204 G702 -- URL validated above and binary name is constant.
		return exec.Command("open", cleanURL).Start()
	case "windows":
		// #nosec G204 G702 -- URL validated above and binary name is constant.
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", cleanURL).Start()
	default:
		// #nosec G204 G702 -- URL validated above and binary name is constant.
		return exec.Command("xdg-open", cleanURL).Start()
	}
}

package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/cliconfig"
	"github.com/hibouhq/hibou/internal/devicelogin"
)

var loginServer string
var loginToken string
var loginSSO bool
var loginTokenStdin bool
var loginAllowInsecureHTTP bool
var loginNoBrowser bool
var loginPreset string

var loginCmd = &cobra.Command{
	Use:   "login [server-url]",
	Short: "Authenticate with a Hibou server",
	Long: `Log in to a Hibou server.

In a terminal, hibou login shows a one-time code and a link. Open the link in
a browser where you are signed in to Hibou, check the code, and approve: the
CLI receives a token that works in every organization you belong to (ADR-043).
It works over SSH and in containers too, since the browser can be anywhere.

Scripts and CI pass an API token instead (create one under Settings > API Keys).

Examples:
  # Browser login
  hibou login hibou.example.com

  # Read-only token (no uploads)
  hibou login hibou.example.com --scope read-only

  # Non-interactive: pipe the token (stays out of shell history)
  printf '%s' "$HIBOU_TOKEN" | hibou login --server https://hibou.example.com --token-stdin

  # --token also works, but the token lands in your shell history
  hibou login --server https://hibou.example.com --token hb_xxxxx

Environment variables:
  HIBOU_SERVER    Server URL
  HIBOU_TOKEN     API token`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := cliconfig.Load()
		if err != nil {
			cfg = cliconfig.Config{}
		}

		server := ""
		if len(args) == 1 {
			server = args[0]
		}
		if server == "" {
			server = strings.TrimSpace(loginServer)
		}
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
		server, err = normalizeServerURL(server)
		if err != nil {
			return err
		}
		if err := checkLoginServerURL(server, loginAllowInsecureHTTP); err != nil {
			return err
		}

		token := strings.TrimSpace(loginToken)
		if token != "" {
			fmt.Fprintln(os.Stderr, "warning: --token leaves the token in your shell history; prefer --token-stdin, HIBOU_TOKEN or browser login")
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

		tokenID := ""
		if token == "" && (stdinIsTerminal() || loginSSO) {
			if err := probeHibouServer(server); err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			issued, err := browserLogin(ctx, server)
			switch {
			case errors.Is(err, devicelogin.ErrUnsupported):
				fmt.Fprintln(os.Stderr, "This server does not support browser login yet; paste an API token from Settings > API Keys.")
			case err != nil:
				return err
			default:
				token, tokenID = issued.AccessToken, issued.TokenID
				fmt.Printf("\n✓ Approved: token %q · all your orgs · preset %s", issued.TokenName, issued.Preset)
				if issued.ExpiresIn > 0 {
					fmt.Printf(" · expires %s", time.Now().Add(time.Duration(issued.ExpiresIn)*time.Second).Format("2006-01-02"))
				}
				fmt.Println()
			}
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
			return fmt.Errorf("API token is required — create one at %s/settings/api-keys", server)
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

		// A previous browser-login token for this server is replaced, not
		// left valid on the server (ADR-043 §6). A pasted token may be in use
		// elsewhere, so it is never revoked.
		if cfg.TokenID != "" && cfg.Token != "" && cfg.Token != token && sameServer(cfg.Server, server) {
			if err := revokeCurrentToken(server, cfg.Token); err == nil {
				fmt.Println("Revoked the previous login token.")
			}
		}

		cfg.Server = server
		cfg.Token = token
		cfg.TokenID = tokenID
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
	loginCmd.Flags().BoolVar(&loginSSO, "sso", false, "Use browser login")
	_ = loginCmd.Flags().MarkDeprecated("sso", "browser login is now the default in a terminal")
	loginCmd.Flags().BoolVar(&loginTokenStdin, "token-stdin", false, "Read the API token from standard input")
	loginCmd.Flags().BoolVar(&loginAllowInsecureHTTP, "insecure-http", false, "Allow a plain http:// server that is not localhost (the token is sent in clear text)")
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "Print the login link instead of offering to open a browser")
	loginCmd.Flags().StringVar(&loginPreset, "scope", "cli", "Access to request: cli (upload, gates, read) or read-only")
}

// browserLogin runs the device flow (RFC 8628): show the code and link, offer
// to open the browser, and wait for approval.
func browserLogin(ctx context.Context, server string) (*devicelogin.Token, error) {
	switch loginPreset {
	case "cli", "read-only":
	default:
		return nil, fmt.Errorf("--scope must be cli or read-only, got %q", loginPreset)
	}
	hostname, _ := os.Hostname()
	client := &devicelogin.Client{Server: server}
	auth, err := client.RequestCode(ctx, devicelogin.Request{
		ClientID:   devicelogin.ClientCLI,
		ClientName: hostname,
		Preset:     loginPreset,
	})
	if err != nil {
		return nil, err
	}

	link := auth.VerificationURIComplete
	if link == "" {
		link = auth.VerificationURI
	}
	fmt.Printf("\n  One-time code:  %s\n\n", auth.UserCode)
	fmt.Printf("Open %s\n", link)
	if !loginNoBrowser {
		fmt.Println("Press Enter to open it in your browser (Ctrl-C to cancel)…")
		go func() {
			if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
				return
			}
			if err := openBrowser(link); err != nil {
				fmt.Fprintln(os.Stderr, "Could not open a browser here; open the link above on any device.")
			}
		}()
	}
	fmt.Printf("Waiting for approval in the browser (expires in %d min)…\n", (auth.ExpiresIn+59)/60)

	token, err := client.Poll(ctx, auth)
	switch {
	case errors.Is(err, devicelogin.ErrDenied):
		return nil, errors.New("login was denied in the browser")
	case errors.Is(err, devicelogin.ErrExpired):
		return nil, errors.New("the code expired before it was approved; run hibou login again")
	case errors.Is(err, context.Canceled):
		return nil, errors.New("login cancelled")
	}
	return token, err
}

// normalizeServerURL accepts what people type ("hibou.example.com",
// "https://hibou.example.com/") and returns scheme://host[/path] with no
// trailing slash, query or fragment. Without a scheme it assumes https, or
// http for a loopback host (a local dev server).
func normalizeServerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		scheme := "https://"
		if parsed, err := url.Parse("//" + raw); err == nil && isLoopbackHost(parsed.Hostname()) {
			scheme = "http://"
		}
		raw = scheme + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid server URL %q: expected hibou.example.com or https://hibou.example.com", raw)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.RawQuery, parsed.Fragment, parsed.User = "", "", nil
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed.String(), nil
}

func sameServer(a, b string) bool {
	na, errA := normalizeServerURL(a)
	nb, errB := normalizeServerURL(b)
	return errA == nil && errB == nil && strings.EqualFold(na, nb)
}

// probeHibouServer checks the URL answers like a hibou server before showing
// a login code for it, so a typo fails with a clear message.
func probeHibouServer(server string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(server + "/api/v1/version") // #nosec G704 -- the server the user asked to log in to
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", server, err)
	}
	defer resp.Body.Close()
	var body struct {
		Data json.RawMessage `json:"data"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body) != nil || len(body.Data) == 0 {
		return fmt.Errorf("%s does not look like a hibou server (GET /api/v1/version answered HTTP %d)", server, resp.StatusCode)
	}
	return nil
}

// revokeCurrentToken asks the server to delete the token used to call it.
func revokeCurrentToken(server, token string) error {
	req, err := http.NewRequest(http.MethodDelete, server+"/api/v1/users/me/api-keys/current", nil) // #nosec G704 -- the configured hibou server
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req) // #nosec G704 -- the configured hibou server
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
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
	if stdinIsTerminal() && runtime.GOOS != "windows" {
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

// browserCommands reads $BROWSER the way xdg-open, Python's webbrowser and gh
// do: a list of commands separated by ":" (";" on Windows, where ":" is part
// of a path), each a command line in which %s stands for the URL (appended
// when absent). The command is used as given — dev containers point it at a
// helper script by absolute path (VS Code's browser.sh).
func browserCommands(env, url, goos string) [][]string {
	sep := ":"
	if goos == "windows" {
		sep = ";"
	}
	var commands [][]string
	for _, entry := range strings.Split(env, sep) {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		substituted := false
		for i, field := range fields[1:] {
			if strings.Contains(field, "%s") {
				fields[i+1] = strings.ReplaceAll(field, "%s", url)
				substituted = true
			}
		}
		if !substituted {
			fields = append(fields, url)
		}
		commands = append(commands, fields)
	}
	return commands
}

func openBrowser(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("invalid URL: %s", rawURL)
	}
	cleanURL := parsed.String()

	for _, args := range browserCommands(os.Getenv("BROWSER"), cleanURL, runtime.GOOS) {
		path, err := exec.LookPath(args[0])
		if err != nil {
			continue
		}
		// #nosec G204 G702 -- the user's own $BROWSER command, run as they would run it; URL validated above.
		if err := exec.Command(path, args[1:]...).Start(); err == nil {
			return nil
		}
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

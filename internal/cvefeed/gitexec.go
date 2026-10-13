package cvefeed

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// validateRemote accepts the remotes the feed may clone from: https (the
// public list or an operator mirror) and file:// (tests, a local mirror).
// Anything else — a bare path, ssh, git's ext:: transport, or a value that
// reads as an option — is refused before it reaches git.
func validateRemote(remote string) error {
	if strings.HasPrefix(remote, "-") {
		return fmt.Errorf("cvefeed: remote %q must not start with '-'", remote)
	}
	parsed, err := url.Parse(remote)
	if err != nil {
		return fmt.Errorf("cvefeed: remote: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		if parsed.Host == "" {
			return fmt.Errorf("cvefeed: remote %q has no host", redactRemote(parsed))
		}
	case "file":
		if parsed.Path == "" {
			return fmt.Errorf("cvefeed: remote %q has no path", remote)
		}
	default:
		return fmt.Errorf("cvefeed: remote %q: scheme must be https (or file)", redactRemote(parsed))
	}
	return nil
}

// redactRemote drops credentials an operator may have put in a mirror URL.
func redactRemote(parsed *url.URL) string {
	copied := *parsed
	copied.User = nil
	return copied.String()
}

// gitEnvPassthrough are the variables a git run keeps from the server's
// environment: how to reach the network (proxies) and which CAs to trust.
// Everything else — GIT_* overrides, credentials, the server's own secrets —
// stays out.
var gitEnvPassthrough = []string{
	"PATH",
	"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
	"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
	"TMPDIR",
}

// gitEnv is the minimal environment git runs with. HOME is a throwaway
// directory so no user or system config (credential helpers, url rewrites,
// hooks paths) applies, and a credential prompt can never hang the worker.
func gitEnv(home string) []string {
	env := make([]string, 0, len(gitEnvPassthrough)+5)
	for _, name := range gitEnvPassthrough {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return append(env,
		"HOME="+home,
		"XDG_CONFIG_HOME="+home,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
	)
}

// gitCommand builds a git command with the minimal environment. cleanup
// removes the temporary HOME; call it once the command has finished.
func gitCommand(ctx context.Context, dir string, args ...string) (*exec.Cmd, func(), error) {
	home, err := os.MkdirTemp("", "hibou-git-home-*")
	if err != nil {
		return nil, nil, fmt.Errorf("git home: %w", err)
	}
	cmd := exec.CommandContext(ctx, "git", args...) // #nosec G204 -- args are built in this package, never from record content
	cmd.Dir = dir
	cmd.Env = gitEnv(home)
	return cmd, func() { _ = os.RemoveAll(home) }, nil
}

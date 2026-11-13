package cvefeed

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/hibouhq/hibou/internal/gitexec"
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

// gitEnv is the minimal environment git runs with. HOME is a throwaway
// directory so no user or system config (credential helpers, url rewrites,
// hooks paths) applies. The shared policy preserves network/CA settings,
// excludes server secrets and disables credential prompts.
func gitEnv(home string) []string {
	return gitexec.Environment(home, false)
}

// gitCommand builds a git command with the minimal environment. cleanup
// removes the temporary HOME; call it once the command has finished.
func gitCommand(ctx context.Context, dir string, args ...string) (*exec.Cmd, func(), error) {
	home, err := os.MkdirTemp("", "hibou-git-home-*")
	if err != nil {
		return nil, nil, fmt.Errorf("git home: %w", err)
	}
	cmd := gitexec.Command(ctx, gitexec.Config{Dir: dir, Home: home}, args...)
	return cmd, func() { _ = os.RemoveAll(home) }, nil
}

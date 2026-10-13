package secretscan

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Subprocesses (git, gitleaks, trufflehog, betterleaks) parse attacker-
// controlled repositories. They get an explicit, minimal environment so the
// server's HIBOU_* secrets (database DSN, forge App private key, session
// keys…) never reach them, and the forge token reaches only git, through the
// environment rather than argv or .git/config.

// passthroughEnv lists the only inherited variables: what the tools need to
// find binaries, reach the network and trust a custom CA.
var passthroughEnv = []string{
	"PATH",
	"TMPDIR",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO",
	"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
	"https_proxy", "http_proxy", "no_proxy",
}

// scannerEnv builds the environment for a scanner subprocess. home must be a
// directory Hibou created (never the cloned repository). extra entries are
// appended as-is ("KEY=value").
func scannerEnv(home string, extra ...string) []string {
	env := make([]string, 0, len(passthroughEnv)+8+len(extra))
	for _, key := range passthroughEnv {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	if _, ok := os.LookupEnv("PATH"); !ok {
		env = append(env, "PATH=/usr/local/bin:/usr/bin:/bin")
	}
	env = append(env,
		"HOME="+home,
		"LANG=C",
		// Never prompt for credentials, and never read the host's git config:
		// only what Hibou sets below or on the command line applies.
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
	)
	return append(env, extra...)
}

// gitAuthEnv returns the GIT_CONFIG_* entries that send the forge token as an
// HTTP Authorization header, scoped to the clone URL's origin. Passing it in
// the environment keeps it out of argv (/proc/*/cmdline), out of the remote
// URL persisted in .git/config, and out of git's error output.
func gitAuthEnv(cloneURL, token string) ([]string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil
	}
	parsed, err := url.Parse(strings.TrimSpace(cloneURL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errors.New("token-authenticated clone requires an http(s) clone URL")
	}
	// Over plain http the token would cross the network readable by anyone
	// on the path; only a development instance (local forge) may do that.
	if parsed.Scheme != "https" && !developmentMode() {
		return nil, errors.New("refusing to send the forge token to a non-https clone URL (allowed only in development)")
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http." + parsed.Scheme + "://" + parsed.Host + "/.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: Basic " + credentials,
	}, nil
}

var (
	devMu  sync.RWMutex
	devSet bool
	devOn  bool
)

// SetDevelopment records whether the instance runs in development mode
// (config development / HIBOU_DEVELOPMENT). Without a call the environment
// variable decides.
func SetDevelopment(enabled bool) {
	devMu.Lock()
	devSet, devOn = true, enabled
	devMu.Unlock()
}

func developmentMode() bool {
	devMu.RLock()
	set, on := devSet, devOn
	devMu.RUnlock()
	if set {
		return on
	}
	enabled, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("HIBOU_DEVELOPMENT")))
	return err == nil && enabled
}

// stripURLCredentials drops any userinfo from a clone URL so a token embedded
// by a caller is never persisted or echoed back.
func stripURLCredentials(cloneURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(cloneURL))
	if err != nil || parsed.User == nil {
		return cloneURL
	}
	parsed.User = nil
	return parsed.String()
}

var (
	urlUserinfoPattern  = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@`)
	authHeaderPattern   = regexp.MustCompile(`(?i)(authorization:\s*(?:basic|bearer|token)\s+)\S+`)
	forgeTokenPattern   = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})`)
	commitSHAPattern    = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)
	redactedPlaceholder = "***"
)

// scrubSecrets removes credentials from subprocess output before it lands in
// an error string (and from there in logs, events and the database).
func scrubSecrets(output string, secrets ...string) string {
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if len(secret) < 4 {
			continue
		}
		output = strings.ReplaceAll(output, secret, redactedPlaceholder)
		output = strings.ReplaceAll(output, base64.StdEncoding.EncodeToString([]byte("x-access-token:"+secret)), redactedPlaceholder)
	}
	output = urlUserinfoPattern.ReplaceAllString(output, "${1}"+redactedPlaceholder+"@")
	output = authHeaderPattern.ReplaceAllString(output, "${1}"+redactedPlaceholder)
	return forgeTokenPattern.ReplaceAllString(output, redactedPlaceholder)
}

// validCommitSHA reports whether value is a full lowercase hex object id
// (SHA-1, or SHA-256 repositories). Range SHAs end up in --log-opts and git
// arguments, so anything else (options, revision expressions) is refused.
func validCommitSHA(value string) bool {
	return commitSHAPattern.MatchString(value)
}

// validateCommitRange checks both ends of a diff range; an empty end keeps
// its existing meaning (git defaults), anything else must be a full SHA.
func validateCommitRange(from, to string) error {
	if from != "" && !validCommitSHA(from) {
		return fmt.Errorf("invalid diff base commit %q", truncateText(from, 80))
	}
	if to != "" && !validCommitSHA(to) {
		return fmt.Errorf("invalid diff head commit %q", truncateText(to, 80))
	}
	return nil
}

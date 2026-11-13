// Package gitexec centralizes safe Git process construction and bounded local
// execution. Repository authorization and clone/ref selection remain callers'
// responsibilities.
package gitexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hibouhq/hibou/internal/executil"
)

type Config struct {
	Dir  string
	Home string
	Env  []string
	// LocalOnly forbids transports, including lazy fetching in partial clones.
	LocalOnly bool
	// UserConfig is for trusted IDE Git metadata queries, which need user URL
	// mappings. Worker/clone/patch execution must leave it false.
	UserConfig  bool
	StdoutLimit int
	StderrLimit int
}

var passthrough = []string{
	"PATH", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
	"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "no_proxy", "all_proxy",
}

func Environment(home string, userConfig bool, extra ...string) []string {
	env := make([]string, 0, len(passthrough)+12+len(extra))
	for _, name := range passthrough {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	if os.Getenv("PATH") == "" {
		env = append(env, "PATH=/usr/local/bin:/usr/bin:/bin")
	}
	xdg := home
	if userConfig {
		xdg = os.Getenv("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
	}
	env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+xdg, "LANG=C", "GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM="+os.DevNull, "GIT_ATTR_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "GIT_LITERAL_PATHSPECS=1")
	if !userConfig {
		env = append(env, "GIT_CONFIG_GLOBAL="+os.DevNull)
	} else if path := os.Getenv("GIT_CONFIG_GLOBAL"); path != "" {
		env = append(env, "GIT_CONFIG_GLOBAL="+path)
	}
	return append(env, extra...)
}

func Command(ctx context.Context, cfg Config, args ...string) *exec.Cmd {
	prefix := []string{"--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.attributesFile=" + os.DevNull, "-c", "core.autocrlf=false", "-c", "protocol.ext.allow=never"}
	if cfg.LocalOnly {
		prefix = append(prefix, "-c", "protocol.allow=never")
	}
	// #nosec G204 -- fixed Git executable; callers supply structured argv, not shell commands.
	cmd := exec.CommandContext(ctx, "git", append(prefix, args...)...)
	cmd.Dir = cfg.Dir
	cmd.Env = Environment(cfg.Home, cfg.UserConfig, cfg.Env...)
	return cmd
}

func Run(ctx context.Context, cfg Config, input []byte, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("git subcommand is required")
	}
	if cfg.StdoutLimit == 0 {
		cfg.StdoutLimit = 32 << 20
	}
	if cfg.StderrLimit == 0 {
		cfg.StderrLimit = 64 << 10
	}
	cmd := Command(ctx, cfg, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	stdout, stderr := executil.NewBuffer(cfg.StdoutLimit), executil.NewBuffer(cfg.StderrLimit)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := errors.Join(cmd.Run(), stdout.Err(), stderr.Err()); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(string(stderr.Bytes())))
	}
	return stdout.Bytes(), nil
}

package gitexec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/executil"
)

func TestEnvironmentExcludesSecretsAndGitInjection(t *testing.T) {
	t.Setenv("HIBOU_TOKEN", "must-not-inherit")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
	t.Setenv("GIT_CONFIG_VALUE_0", "malicious")
	t.Setenv("HTTPS_PROXY", "https://proxy.example.test")
	env := strings.Join(Environment(t.TempDir(), false), "\n")
	for _, secret := range []string{"must-not-inherit", "GIT_CONFIG_COUNT", "malicious"} {
		if strings.Contains(env, secret) {
			t.Fatalf("inherited unsafe environment: %s", secret)
		}
	}
	if !strings.Contains(env, "HTTPS_PROXY=https://proxy.example.test") {
		t.Fatal("approved network configuration lost")
	}
}

func TestLocalRunPreservesLiteralPathsAndDisablesExecution(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	cfg := Config{Dir: root, Home: home, LocalOnly: true}
	if _, err := Run(t.Context(), cfg, nil, "init", "-q"); err != nil {
		t.Fatal(err)
	}
	name := ":(glob)not-a-pattern"
	if err := os.WriteFile(filepath.Join(root, name), []byte("literal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(t.Context(), cfg, nil, "add", "--", name); err != nil {
		t.Fatal(err)
	}
	data, err := Run(t.Context(), cfg, nil, "ls-files", "-z")
	if err != nil || string(data) != name+"\x00" {
		t.Fatalf("path interpreted: %q %v", data, err)
	}
	cmd := Command(t.Context(), cfg, "status", "--short")
	if !strings.Contains(strings.Join(cmd.Args, " "), "protocol.allow=never") {
		t.Fatal("local Git can open a transport")
	}
}

func TestRunBoundsOutput(t *testing.T) {
	cfg := Config{Dir: t.TempDir(), Home: t.TempDir(), LocalOnly: true, StdoutLimit: 1}
	_, err := Run(t.Context(), cfg, nil, "--version")
	if !errors.Is(err, executil.ErrOutputLimit) {
		t.Fatalf("output was not bounded: %v", err)
	}
}

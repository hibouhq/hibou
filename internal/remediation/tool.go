package remediation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/executil"
)

// Tool is an operator/local-user approved, preinstalled executable. It is not
// populated from repository files or a remote remediation request.
type Tool struct {
	Path          string
	VersionOutput string
	// PATH is profile-owned: scripts such as npm need the pinned language runtime.
	PATH                 string
	RuntimePath          string
	RuntimeVersionOutput string
	RegistryURL          string
	RegistryOrigin       string
	SandboxUID           uint32
	SandboxGID           uint32
}

func (t Tool) validate() error {
	if !filepath.IsAbs(t.Path) || t.VersionOutput == "" || t.PATH == "" {
		return errors.New("tool requires an approved absolute path, exact version output and runtime PATH")
	}
	info, err := os.Stat(t.Path)
	if err != nil {
		return fmt.Errorf("tool unavailable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("tool is not a regular executable")
	}
	if t.RuntimePath != "" && (!filepath.IsAbs(t.RuntimePath) || t.RuntimeVersionOutput == "") {
		return errors.New("runtime requires an approved absolute path and exact version")
	}
	return nil
}

// Run never inherits the Hibou process environment or executes a shell command.
// The caller must provide an isolated/trusted execution environment; this
// minimal environment is not a sandbox.
func (t Tool) Run(ctx context.Context, root, home string, args ...string) error {
	if err := t.validate(); err != nil {
		return err
	}
	if t.SandboxUID != 0 {
		if err := prepareSandboxOwnership(root, home, t.SandboxUID, t.SandboxGID); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	version, err := t.command(ctx, root, home, "--version")
	if err != nil {
		return fmt.Errorf("check tool identity: %w", err)
	}
	if strings.TrimSpace(string(version)) != t.VersionOutput {
		return errors.New("installed tool version differs from the approved profile")
	}
	if t.RuntimePath != "" {
		runtime := t
		runtime.Path = t.RuntimePath
		version, err := runtime.command(ctx, root, home, "--version")
		if err != nil {
			return fmt.Errorf("check runtime identity: %w", err)
		}
		if strings.TrimSpace(string(version)) != t.RuntimeVersionOutput {
			return errors.New("installed runtime differs from the approved profile")
		}
	}
	if _, err := t.command(ctx, root, home, args...); err != nil {
		return fmt.Errorf("dependency tool failed: %w", err)
	}
	return nil
}

// InspectLocalNPM is called only after IDE workspace trust/user consent.
// It locates existing tools, never downloads or installs them.
func InspectLocalNPM(ctx context.Context) (Tool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	npm, err := exec.LookPath("npm")
	if err != nil {
		return Tool{}, errors.New("npm is not installed; no automatic installation was attempted")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return Tool{}, errors.New("node.js is not installed")
	}
	npm, err = filepath.Abs(npm)
	if err != nil {
		return Tool{}, err
	}
	node, err = filepath.Abs(node)
	if err != nil {
		return Tool{}, err
	}
	home, err := os.MkdirTemp("", "hibou-tool-inspect-")
	if err != nil {
		return Tool{}, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	tool := Tool{Path: npm, PATH: filepath.Dir(node) + string(os.PathListSeparator) + os.Getenv("PATH")}
	version, err := tool.command(ctx, home, home, "--version")
	if err != nil {
		return Tool{}, err
	}
	tool.VersionOutput = strings.TrimSpace(string(version))
	runtime := tool
	runtime.Path = node
	version, err = runtime.command(ctx, home, home, "--version")
	if err != nil {
		return Tool{}, err
	}
	tool.RuntimePath, tool.RuntimeVersionOutput = node, strings.TrimSpace(string(version))
	return tool, nil
}
func (t Tool) command(ctx context.Context, root, home string, args ...string) ([]byte, error) {
	// #nosec G204 -- executable belongs to the approved profile; arguments are adapter-owned, never shell commands.
	cmd := exec.CommandContext(ctx, t.Path, args...)
	if err := superviseProcess(cmd); err != nil {
		return nil, err
	}
	if err := sandboxCredential(cmd, t.SandboxUID, t.SandboxGID); err != nil {
		return nil, err
	}
	cmd.Dir = root
	cmd.Env = []string{
		"PATH=" + t.PATH, "HOME=" + home, "LANG=C", "CI=true",
		"TMPDIR=" + home, "GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"NPM_CONFIG_USERCONFIG=" + filepath.Join(home, "user.npmrc"), "NPM_CONFIG_GLOBALCONFIG=" + filepath.Join(home, "global.npmrc"),
		"NPM_CONFIG_AUDIT=false", "NPM_CONFIG_FUND=false", "NPM_CONFIG_IGNORE_SCRIPTS=true",
		"NPM_CONFIG_UPDATE_NOTIFIER=false",
		"COREPACK_ENABLE_NETWORK=0", "COREPACK_ENABLE_DOWNLOAD_PROMPT=0", "MISE_AUTO_INSTALL=0",
		"PIP_DISABLE_PIP_VERSION_CHECK=1", "PIP_NO_INPUT=1",
		"PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1",
	}
	if t.RegistryURL != "" {
		cmd.Env = append(cmd.Env, "NPM_CONFIG_REGISTRY="+t.RegistryURL)
	}
	output := executil.NewBuffer(64 << 10)
	cmd.Stdout, cmd.Stderr = output, output
	if err := errors.Join(cmd.Run(), output.Err()); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Tool output can contain private registry information. It must not be
		// interpolated into an API/LSP error without credential redaction.
		return nil, &toolFailure{cause: err, diagnostics: append([]byte(nil), output.Bytes()...)}
	}
	return output.Bytes(), nil
}

type Relocker interface {
	Validate(Unit) error
	Relock(context.Context, string, Unit) error
}

// NativeRelocker owns the supported command lines. Tools must be provisioned
// ahead of time; missing versions are errors, never bootstrap instructions.
type NativeRelocker struct {
	Manager string
	Tool    Tool
}

func (r NativeRelocker) Validate(u Unit) error {
	if r.Manager != u.Manager {
		return errors.New("tool profile does not match the project's package manager")
	}
	if err := r.Tool.validate(); err != nil {
		return err
	}
	manifest, lock := filepath.Base(u.Manifest), filepath.Base(u.Lockfile)
	if filepath.Dir(u.Manifest) != filepath.Dir(u.Lockfile) {
		return errors.New("manifest and lockfile must share the supported project directory")
	}
	switch {
	case u.Manager == "npm" && manifest == "package.json" && lock == "package-lock.json":
	case u.Manager == "pip-tools" && manifest == "requirements.in" && lock == "requirements.txt":
	case u.Manager == "poetry" && manifest == "pyproject.toml" && lock == "poetry.lock":
	case u.Manager == "pipenv" && manifest == "Pipfile" && lock == "Pipfile.lock":
	default:
		return errors.New("unsupported manager/manifest/lockfile combination")
	}
	return nil
}

func (r NativeRelocker) Relock(ctx context.Context, root string, u Unit) error {
	if err := r.Validate(u); err != nil {
		return err
	}
	home, err := os.MkdirTemp("", "hibou-remediation-tool-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(home) }()
	dir := filepath.Join(root, filepath.FromSlash(filepath.Dir(u.Manifest)))
	var args []string
	switch u.Manager {
	case "npm":
		args = []string{"install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"}
	case "pip-tools":
		args = []string{"--generate-hashes", "--output-file=requirements.txt", "requirements.in"}
	case "poetry":
		args = []string{"lock"}
	case "pipenv":
		args = []string{"lock"}
	}
	return r.Tool.Run(ctx, dir, home, args...)
}

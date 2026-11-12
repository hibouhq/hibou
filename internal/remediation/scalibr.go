package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/guidedremediation"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scalibr/inventory"
)

// SCALIBR intentionally uses only manifest strategies with injected clients.
// Upstream's lockfile writer and relocker acquire their own registry/tool
// configuration; those paths must not bypass Hibou's execution policy.
type SCALIBR struct {
	Resolver    resolve.Client
	Enricher    enricher.Enricher
	Maven       *datasource.MavenRegistryAPIClient
	VerifyFiles func(context.Context, string, Unit, UnitResult) (Verification, error)
	Relocker    Relocker
}

func (s SCALIBR) Validate(unit Unit) error {
	if len(unit.VersionTargets) > 0 {
		return errors.New("exact targets require the native package-manager adapter")
	}
	if s.Resolver == nil || s.Enricher == nil || s.VerifyFiles == nil {
		return errors.New("SCALIBR requires an approved resolver, vulnerability enricher and independent verifier")
	}
	for _, file := range unit.RequiredFiles {
		if lockedDependencyFile(filepath.Base(file)) && file != unit.Lockfile && file != unit.Manifest {
			return fmt.Errorf("lockfile %q is not bound to a supported relock workflow", file)
		}
	}
	if unit.Lockfile != "" {
		if s.Relocker == nil {
			return errors.New("locked projects require a supervised relock/verification adapter; built-in SCALIBR relocking is disabled")
		}
		if err := s.Relocker.Validate(unit); err != nil {
			return err
		}
	}
	if _, err := upgradeLevel(unit.UpgradeLevel); err != nil {
		return err
	}
	switch unit.Manager {
	case "npm":
		if filepath.Base(unit.Manifest) != "package.json" {
			return errors.New("npm remediation requires package.json")
		}
	case "pip-tools":
		if base := filepath.Base(unit.Manifest); base != "requirements.in" && base != "requirements.txt" {
			return errors.New("pip-tools remediation requires requirements.in or requirements.txt")
		}
	case "maven":
		if filepath.Base(unit.Manifest) != "pom.xml" || s.Maven == nil {
			return errors.New("maven remediation requires pom.xml and an approved Maven metadata client")
		}
	case "poetry":
		if filepath.Base(unit.Manifest) != "pyproject.toml" || unit.Lockfile == "" {
			return errors.New("poetry remediation requires pyproject.toml and poetry.lock")
		}
	case "pipenv":
		if filepath.Base(unit.Manifest) != "Pipfile" || unit.Lockfile == "" {
			return errors.New("pipenv remediation requires Pipfile and Pipfile.lock")
		}
	default:
		return fmt.Errorf("unsupported remediation manager %q", unit.Manager)
	}
	return nil
}

func (s SCALIBR) Generate(ctx context.Context, root string, unit Unit) (UnitResult, error) {
	if err := s.Validate(unit); err != nil {
		return UnitResult{}, err
	}
	if unit.Manager == "npm" {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(unit.Manifest)))
		if err != nil {
			return UnitResult{}, err
		}
		var manifest struct {
			PackageManager string `json:"packageManager"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return UnitResult{}, err
		}
		if manifest.PackageManager != "" && !strings.HasPrefix(manifest.PackageManager, "npm@") {
			return UnitResult{}, errors.New("manifest declares another package manager; npm substitution is forbidden")
		}
	}
	level, err := upgradeLevel(unit.UpgradeLevel)
	if err != nil {
		return UnitResult{}, err
	}
	guard := &resolutionGuard{ctx: ctx}
	client := &guardedResolver{Client: s.Resolver, guard: guard}
	opts := options.FixVulnsOptions{
		Manifest:           filepath.Join(root, filepath.FromSlash(unit.Manifest)),
		ProjectRoot:        root,
		Strategy:           strategy.StrategyRelax,
		NoIntroduce:        true,
		ResolveClient:      client,
		VulnEnricher:       guardedEnricher{Enricher: s.Enricher, guard: guard},
		MavenClient:        s.Maven,
		RemediationOptions: options.DefaultRemediationOptions(),
	}
	opts.ExplicitVulns = append([]string(nil), unit.Vulns...)
	opts.UpgradeConfig.SetDefault(level)
	if unit.Manager == "maven" {
		opts.Strategy = strategy.StrategyOverride
	}
	result, err := guidedremediation.FixVulns(opts)
	if err != nil {
		return UnitResult{}, err
	}
	if err := errors.Join(ctx.Err(), guard.err()); err != nil {
		return UnitResult{}, fmt.Errorf("incomplete dependency resolution: %w", err)
	}
	if len(result.Errors) != 0 {
		return UnitResult{}, errors.New("SCALIBR reported unresolved dependency requirements")
	}
	out := UnitResult{ID: unit.ID, Updates: []Update{}}
	for _, patch := range result.Patches {
		if len(patch.Introduced) != 0 {
			return UnitResult{}, errors.New("SCALIBR patch introduces vulnerabilities")
		}
		for _, update := range patch.PackageUpdates {
			out.Updates = append(out.Updates, Update{Name: update.Name, From: update.VersionFrom, To: update.VersionTo})
		}
	}
	if unit.Lockfile != "" {
		if err := s.Relocker.Relock(ctx, root, unit); err != nil {
			return UnitResult{}, fmt.Errorf("relock failed: %w", err)
		}
	}
	return out, nil
}

func lockedDependencyFile(name string) bool {
	switch name {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
		"poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "pylock.toml", "Cargo.lock", "composer.lock", "Gemfile.lock", "packages.lock.json", "gradle.lockfile", "go.sum", "go.work.sum":
		return true
	}
	return false
}

func (s SCALIBR) Verify(ctx context.Context, root string, unit Unit, result UnitResult) (Verification, error) {
	if s.VerifyFiles == nil {
		return Verification{}, errors.New("independent remediation verification is required")
	}
	return s.VerifyFiles(ctx, root, unit, result)
}

func upgradeLevel(level string) (upgrade.Level, error) {
	switch level {
	case "", "minor":
		return upgrade.Minor, nil
	case "patch":
		return upgrade.Patch, nil
	case "major":
		return upgrade.Major, nil
	default:
		return upgrade.None, fmt.Errorf("invalid upgrade level %q", level)
	}
}

// Upstream v0.5.3 starts work with context.Background and may log metadata
// failures while continuing. Bind every injectable client to the job context
// and retain failures so incomplete resolution cannot yield a ready artifact.
type resolutionGuard struct {
	ctx     context.Context
	mu      sync.Mutex
	failure error
}

func (g *resolutionGuard) record(err error) {
	if err != nil {
		g.mu.Lock()
		if g.failure == nil {
			g.failure = err
		}
		g.mu.Unlock()
	}
}

func (g *resolutionGuard) err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failure
}

type guardedResolver struct {
	resolve.Client
	guard *resolutionGuard
}

func (c *guardedResolver) Version(_ context.Context, key resolve.VersionKey) (resolve.Version, error) {
	if err := c.guard.ctx.Err(); err != nil {
		return resolve.Version{}, err
	}
	out, err := c.Client.Version(c.guard.ctx, key)
	c.guard.record(err)
	return out, err
}

func (c *guardedResolver) Versions(_ context.Context, key resolve.PackageKey) ([]resolve.Version, error) {
	if err := c.guard.ctx.Err(); err != nil {
		return nil, err
	}
	out, err := c.Client.Versions(c.guard.ctx, key)
	c.guard.record(err)
	return out, err
}

func (c *guardedResolver) Requirements(_ context.Context, key resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	if err := c.guard.ctx.Err(); err != nil {
		return nil, err
	}
	out, err := c.Client.Requirements(c.guard.ctx, key)
	c.guard.record(err)
	return out, err
}

func (c *guardedResolver) MatchingVersions(_ context.Context, key resolve.VersionKey) ([]resolve.Version, error) {
	if err := c.guard.ctx.Err(); err != nil {
		return nil, err
	}
	out, err := c.Client.MatchingVersions(c.guard.ctx, key)
	c.guard.record(err)
	return out, err
}

type guardedEnricher struct {
	enricher.Enricher
	guard *resolutionGuard
}

func (e guardedEnricher) Enrich(_ context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	if err := e.guard.ctx.Err(); err != nil {
		return err
	}
	err := e.Enricher.Enrich(e.guard.ctx, input, inv)
	e.guard.record(err)
	return err
}

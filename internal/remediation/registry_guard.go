package remediation

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"deps.dev/util/resolve"
	purl "github.com/package-url/packageurl-go"
)

type namespaceGuardResolver struct {
	resolve.Client
	match   MatchPackages
	mu      sync.Mutex
	checked map[string]bool
}

func (c *namespaceGuardResolver) check(ctx context.Context, key resolve.PackageKey) error {
	if key.System != resolve.NPM || !validNPMName(key.Name) {
		return errors.New("unsupported registry ecosystem")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checked[key.Name] {
		return nil
	}
	p, err := purl.FromString("pkg:npm/" + key.Name + "@0.0.0")
	if err != nil {
		return err
	}
	if _, err := checkedMatches(ctx, c.match, []string{p.ToString()}); err != nil {
		return fmt.Errorf("registry namespace approval: %w", err)
	}
	c.checked[key.Name] = true
	return nil
}

func (c *namespaceGuardResolver) Version(ctx context.Context, k resolve.VersionKey) (resolve.Version, error) {
	if err := c.check(ctx, k.PackageKey); err != nil {
		return resolve.Version{}, err
	}
	return c.Client.Version(ctx, k)
}
func (c *namespaceGuardResolver) Versions(ctx context.Context, k resolve.PackageKey) ([]resolve.Version, error) {
	if err := c.check(ctx, k); err != nil {
		return nil, err
	}
	return c.Client.Versions(ctx, k)
}
func (c *namespaceGuardResolver) Requirements(ctx context.Context, k resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	if err := c.check(ctx, k.PackageKey); err != nil {
		return nil, err
	}
	return c.Client.Requirements(ctx, k)
}
func (c *namespaceGuardResolver) MatchingVersions(ctx context.Context, k resolve.VersionKey) ([]resolve.Version, error) {
	if err := c.check(ctx, k.PackageKey); err != nil {
		return nil, err
	}
	return c.Client.MatchingVersions(ctx, k)
}

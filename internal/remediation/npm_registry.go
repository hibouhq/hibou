package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/tidwall/sjson"
)

func publicNPMConfigAllowed(directory string) error {
	for _, name := range []string{"npm_config_registry", "NPM_CONFIG_REGISTRY"} {
		if os.Getenv(name) != "" {
			return errors.New("registry environment override needs an approved profile")
		}
	}
	config, err := datasource.LoadNPMRegistryConfig(directory)
	if err != nil {
		return err
	}
	if len(config.ScopeURLs) != 1 || strings.TrimRight(config.ScopeURLs[""], "/") != "https://registry.npmjs.org" {
		return errors.New("custom registries require a separately approved profile; no public fallback was attempted")
	}
	return nil
}

func publicNPMResolver(ctx context.Context, match MatchPackages, registryClient *http.Client) (resolve.Client, func() error, error) {
	dir, err := os.MkdirTemp("", "hibou-npm-registry-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := publicNPMConfigAllowed(dir); err != nil {
		cleanup()
		return nil, nil, err
	}
	proxy, err := startNPMProxyWithClient(ctx, match, registryClient)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("registry="+proxy.URL+"\n"), 0o600); err != nil {
		_ = proxy.close()
		cleanup()
		return nil, nil, err
	}
	client, err := resolution.NewNPMRegistryClient(dir)
	if err != nil {
		_ = proxy.close()
		cleanup()
		return nil, nil, err
	}
	return client, func() error { err := proxy.close(); cleanup(); return err }, nil
}

func approvedNPMLocation(location *url.URL, mirror string) bool {
	if location == nil || location.Scheme != "https" || location.User != nil || location.RawQuery != "" || location.Fragment != "" {
		return false
	}
	if location.Host == "registry.npmjs.org" {
		return true
	}
	base, err := url.Parse(mirror)
	return err == nil && base.Scheme == "https" && base.Host != "" && location.Host == base.Host &&
		strings.HasPrefix(location.Path, strings.TrimSuffix(base.Path, "/")+"/")
}

func canonicalizeProxyLocations(root string, u Unit, registry, origin string) error {
	sources := []string{registry}
	if origin == "" {
		origin = "https://registry.npmjs.org/"
	} else {
		sources = append(sources, "https://registry.npmjs.org/")
	}
	return rewriteNPMLocations(root, u.Lockfile, sources, origin)
}

func rewriteNPMLocations(root, lockfile string, sources []string, destination string) error {
	fsRoot, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer fsRoot.Close()
	data, err := fsRoot.ReadFile(lockfile)
	if err != nil {
		return err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return err
	}
	for location, p := range lock.Packages {
		for _, source := range sources {
			if source == "" {
				continue
			}
			prefix := strings.TrimSuffix(source, "/") + "/"
			if strings.HasPrefix(p.Resolved, prefix) {
				escaped := strings.NewReplacer("\\", "\\\\", ".", "\\.").Replace(location)
				updated, err := sjson.SetBytes(data, "packages."+escaped+".resolved", strings.TrimSuffix(destination, "/")+"/"+strings.TrimPrefix(p.Resolved, prefix))
				if err != nil {
					return err
				}
				data = updated
				break
			}
		}
	}
	return fsRoot.WriteFile(lockfile, data, 0o600)
}

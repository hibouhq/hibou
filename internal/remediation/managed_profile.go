package remediation

import (
	"context"
	"errors"
	"path"
	"slices"
	"strings"
)

// Ancestor controls affect nested projects even when their own lockfile is
// independent. Do not silently drop them when creating a sparse unit workspace.
func managedNPMControlReason(manifest string, paths []string) string {
	module := path.Dir(manifest)
	for _, file := range paths {
		switch path.Base(file) {
		case ".npmrc", ".nvmrc", ".node-version", ".tool-versions":
			parent := path.Dir(file)
			if parent == "." || parent == module || strings.HasPrefix(module, parent+"/") {
				return "Managed public npm profile does not support ancestor registry/runtime control " + file
			}
		}
	}
	return ""
}

// PrepareManagedModules runs bounded committed-data discovery, not native
// dependency tooling. It may run in the trusted controller, never a Job.
func PrepareManagedModules(ctx context.Context, repository string, input ManagedInput, snapshot ManagedSnapshot, match MatchPackages) (*ManagedResult, error) {
	if snapshot.SourceSHA != input.BaseSHA || match == nil {
		return nil, errors.New("managed discovery source/evidence mismatch")
	}
	manifests, err := DiscoverNPMManifests(ctx, repository, input.BaseSHA)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(snapshot.Files))
	for name := range snapshot.Files {
		paths = append(paths, name)
	}
	slices.Sort(paths)
	backend := NPMBackend{Tool: input.Tool, Match: match}
	result := &ManagedResult{Modules: []ManagedModule{}}
	if len(manifests) == 0 {
		result.Unavailable = "No npm modules exist at the pinned source; this profile supports independent package-lock v3 modules only."
	}
	for _, manifest := range manifests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if reason := managedNPMControlReason(manifest, paths); reason != "" {
			result.Modules = append(result.Modules, ManagedModule{Manifest: manifest, Unavailable: reason})
			continue
		}
		unit, err := backend.PrepareMetadata(ctx, repository, input.BaseSHA, manifest, input.Vulns, "patch")
		module := ManagedModule{Manifest: manifest}
		if err != nil {
			module.Unavailable = err.Error()
		} else {
			module.Unit = &unit
		}
		result.Modules = append(result.Modules, module)
	}
	return result, nil
}

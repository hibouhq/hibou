package remediation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ManagedInput is controller-created, never accepted directly from an API caller.
type ManagedInput struct {
	Operation string         `json:"operation"`
	Profile   string         `json:"profile"`
	BaseSHA   string         `json:"base_sha"`
	Units     []Unit         `json:"units,omitempty"`
	Vulns     []string       `json:"vulns,omitempty"`
	Tool      Tool           `json:"tool"`
	Candidate *ManagedResult `json:"candidate,omitempty"`
}

type ManagedModule struct {
	Manifest    string `json:"manifest"`
	Unit        *Unit  `json:"unit,omitempty"`
	Unavailable string `json:"unavailable,omitempty"`
}

type ManagedResult struct {
	Modules     []ManagedModule   `json:"modules,omitempty"`
	Artifact    *Artifact         `json:"artifact,omitempty"`
	Error       string            `json:"error,omitempty"`
	Files       map[string][]byte `json:"files,omitempty"`
	Unavailable string            `json:"unavailable,omitempty"`
}

// ExecuteManaged is only for a fixed, operator-built isolated executor image.
// The controller API must never call this in its own process.
func ExecuteManaged(ctx context.Context, input ManagedInput, repository, scratch string, match MatchPackages, registry *http.Client) (*ManagedResult, error) {
	if os.Geteuid() == 0 || input.Tool.SandboxUID != 0 || input.Tool.SandboxGID != 0 {
		return nil, errors.New("managed execution requires a non-root workload without UID switching")
	}
	if !filepath.IsAbs(scratch) || scratch == "/" || input.Tool.RuntimePath == "" || match == nil || registry == nil {
		return nil, errors.New("managed executor requires an approved runtime and private scratch")
	}
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return nil, err
	}
	home, err := os.MkdirTemp(scratch, "hibou-profile-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	if err := input.Tool.Run(ctx, home, home, "--version"); err != nil {
		return nil, fmt.Errorf("approved toolchain unavailable: %w", err)
	}
	backend := NPMBackend{Tool: input.Tool, Match: match, RegistryClient: registry}
	switch input.Operation {
	case "prepare":
		manifests, err := DiscoverNPMManifests(ctx, repository, input.BaseSHA)
		if err != nil {
			return nil, err
		}
		if len(manifests) > MaxUnits {
			return nil, errors.New("repository exceeds managed module limit")
		}
		listing, err := gitOutput(ctx, repository, home, "ls-tree", "-r", "--name-only", "-z", input.BaseSHA)
		if err != nil {
			return nil, err
		}
		inputPaths := strings.Split(string(listing), "\x00")
		result := &ManagedResult{Modules: []ManagedModule{}}
		if len(manifests) == 0 {
			result.Unavailable = "No npm package.json modules exist at the pinned source. This managed profile does not support other ecosystems."
		}
		for _, manifest := range manifests {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if reason := managedNPMControlReason(manifest, inputPaths); reason != "" {
				result.Modules = append(result.Modules, ManagedModule{Manifest: manifest, Unavailable: reason})
				continue
			}
			unit, err := backend.Prepare(ctx, repository, input.BaseSHA, manifest, input.Vulns, "patch")
			module := ManagedModule{Manifest: manifest}
			if err != nil {
				module.Unavailable = err.Error()
			} else {
				module.Unit = &unit
			}
			result.Modules = append(result.Modules, module)
		}
		return result, nil
	case "generate":
		artifact, err := (Engine{Backend: backend, TempDir: scratch}).Generate(ctx, Request{
			Repository: repository, BaseSHA: input.BaseSHA, Units: input.Units,
		})
		if err != nil {
			return nil, err
		}
		files, err := managedArtifactFiles(ctx, repository, scratch, *artifact)
		if err != nil {
			return nil, err
		}
		return &ManagedResult{Artifact: artifact, Files: files}, nil
	case "verify":
		if input.Candidate == nil {
			return nil, errors.New("independent verification requires a candidate")
		}
		if err := VerifyManagedCandidate(ctx, repository, input, input.Candidate, backend, true); err != nil {
			return nil, err
		}
		return input.Candidate, nil
	default:
		return nil, errors.New("unknown managed operation")
	}
}

func managedArtifactFiles(ctx context.Context, repository, scratch string, a Artifact) (map[string][]byte, error) {
	root, err := os.MkdirTemp(scratch, "hibou-publication-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(root) }()
	return verifyPatchContents(ctx, repository, root, a)
}

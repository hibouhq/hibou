package scanrun

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scanplan"
)

// ErrNotInEmbeddedCatalog: the server planned a scanner, version or artifact
// this CLI build does not pin. The CLI only runs what its own embedded
// catalog names; a newer server catalog needs a newer CLI.
var ErrNotInEmbeddedCatalog = errors.New("not pinned by this CLI's embedded scanner catalog (upgrade the hibou CLI)")

// ErrUnsafePath: a plan target or exclusion that could be read as an option
// or escape the checkout.
var ErrUnsafePath = errors.New("unsafe plan path")

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Resolver binds a server plan to the CLI's embedded catalog (P1). The
// server decides which scanners run on which targets and where artifacts
// are downloaded from; everything that decides what is executed — engine,
// command arguments, exit codes, sha256 pins, Maven coordinates — comes from
// Catalog, which is compiled into this binary.
type Resolver struct {
	// Catalog is the CLI's embedded catalog (scancatalog.Load).
	Catalog *scancatalog.Catalog
	// GOOS/GOARCH select the binary distributions this runner may execute.
	GOOS, GOARCH string
	// BundleDir is the imported offline bundle on this runner. An offline
	// (file://) location is re-derived under it from the embedded catalog;
	// without it, offline locations are refused.
	BundleDir string
}

// Resolve returns the job and catalog entry to execute. served is the
// server's catalog entry for the job's scanner (GET /scanner-catalog), used
// for its locations only; it may be nil.
func (r Resolver) Resolve(job scanplan.Job, served *CatalogEntry) (scanplan.Job, CatalogEntry, error) {
	if r.Catalog == nil {
		return job, CatalogEntry{}, errors.New("no embedded scanner catalog")
	}
	local, ok := r.Catalog.Scanner(job.ScannerID)
	if !ok {
		return job, CatalogEntry{}, fmt.Errorf("scanner %q: %w", job.ScannerID, ErrNotInEmbeddedCatalog)
	}
	if served != nil {
		if served.ID != "" && served.ID != local.ID {
			return job, CatalogEntry{}, fmt.Errorf("server catalog entry %q does not match planned scanner %q", served.ID, local.ID)
		}
		if served.EngineVersion != "" && served.EngineVersion != local.EngineVersion {
			return job, CatalogEntry{}, fmt.Errorf("scanner %s: server catalog has version %s, this CLI pins %s: %w", local.ID, served.EngineVersion, local.EngineVersion, ErrNotInEmbeddedCatalog)
		}
		if served.AdapterVersion != "" && served.AdapterVersion != local.AdapterVersion {
			return job, CatalogEntry{}, fmt.Errorf("scanner %s: server catalog has adapter %s, this CLI pins %s: %w", local.ID, served.AdapterVersion, local.AdapterVersion, ErrNotInEmbeddedCatalog)
		}
	}
	if err := ValidatePlanPaths(job.Targets, job.Exclusions); err != nil {
		return job, CatalogEntry{}, fmt.Errorf("job %s: %w", job.ID, err)
	}

	trusted := job
	trusted.ScannerID = local.ID
	trusted.Targets = append([]string(nil), job.Targets...)
	trusted.Exclusions = append([]string(nil), job.Exclusions...)
	trusted.Command = append([]string(nil), local.Command.Args...)
	if job.Artifact != nil {
		distribution, err := r.pinnedDistribution(local, job.Artifact.SHA256)
		if err != nil {
			return job, CatalogEntry{}, err
		}
		location, err := r.location(local, distribution, *job.Artifact)
		if err != nil {
			return job, CatalogEntry{}, err
		}
		trusted.Artifact = &location
	}

	entry := CatalogEntry{Scanner: *local}
	entry.Distributions = make([]ResolvedDistribution, 0, len(local.Distributions))
	for i := range local.Distributions {
		distribution := &local.Distributions[i]
		resolved := ResolvedDistribution{Distribution: *distribution, Unavailable: "no location from the server"}
		if servedDistribution := matchServed(served, distribution); servedDistribution != nil {
			resolved.Unavailable = servedDistribution.Unavailable
			if servedDistribution.Location != nil {
				location, err := r.location(local, distribution, *servedDistribution.Location)
				if err != nil {
					resolved.Unavailable = err.Error()
				} else {
					resolved.Location = &location
					resolved.Unavailable = ""
				}
			}
		}
		entry.Distributions = append(entry.Distributions, resolved)
	}
	return trusted, entry, nil
}

// pinnedDistribution finds the embedded distribution the server's artifact
// names by sha256. A binary must also be built for this runner.
func (r Resolver) pinnedDistribution(local *scancatalog.Scanner, digest string) (*scancatalog.Distribution, error) {
	if !sha256Hex.MatchString(digest) {
		return nil, fmt.Errorf("scanner %s: artifact sha256 %q is not 64 lowercase hex characters", local.ID, digest)
	}
	for i := range local.Distributions {
		distribution := &local.Distributions[i]
		if distribution.SHA256 != digest {
			continue
		}
		if distribution.Kind == scancatalog.KindBinary && (distribution.OS != r.GOOS || distribution.Arch != r.GOARCH) {
			return nil, fmt.Errorf("scanner %s: artifact %s is built for %s/%s, this runner is %s/%s", local.ID, distribution.Asset, distribution.OS, distribution.Arch, r.GOOS, r.GOARCH)
		}
		return distribution, nil
	}
	return nil, fmt.Errorf("scanner %s %s: artifact sha256 %s: %w", local.ID, local.EngineVersion, digest, ErrNotInEmbeddedCatalog)
}

// matchServed finds the server's resolved distribution for an embedded one:
// same kind and sha256. Coordinates and every other field stay embedded.
func matchServed(served *CatalogEntry, distribution *scancatalog.Distribution) *ResolvedDistribution {
	if served == nil {
		return nil
	}
	for i := range served.Distributions {
		candidate := &served.Distributions[i]
		if candidate.Kind == distribution.Kind && candidate.SHA256 == distribution.SHA256 {
			return candidate
		}
	}
	return nil
}

// location keeps only the download URL from the server, with the embedded
// sha256. An https URL (upstream, mirror, approved location) is kept as is:
// the digest is verified after download. An offline location is re-derived
// under the runner's own bundle directory; the server's path is ignored.
func (r Resolver) location(local *scancatalog.Scanner, distribution *scancatalog.Distribution, served scancatalog.Location) (scancatalog.Location, error) {
	parsed, err := url.Parse(served.URL)
	if err != nil {
		return scancatalog.Location{}, fmt.Errorf("artifact location: %w", err)
	}
	switch parsed.Scheme {
	case "https":
		if parsed.Host == "" {
			return scancatalog.Location{}, fmt.Errorf("artifact location %q has no host", served.URL)
		}
		return scancatalog.Location{ScannerID: local.ID, URL: served.URL, SHA256: distribution.SHA256, Source: served.Source}, nil
	case "file":
		if r.BundleDir == "" {
			return scancatalog.Location{}, errors.New("the plan resolves an offline bundle: pass --bundle-dir (or HIBOU_SCANNER_BUNDLE_DIR) with the imported bundle on this runner")
		}
		location, err := scancatalog.DistributionConfig{Mode: scancatalog.ModeOffline, BundleDir: r.BundleDir}.Resolve(local, distribution)
		if err != nil {
			return scancatalog.Location{}, err
		}
		return location, nil
	}
	return scancatalog.Location{}, fmt.Errorf("artifact location scheme %q is not allowed (https or an offline bundle only)", parsed.Scheme)
}

// ValidatePlanPaths refuses plan targets and exclusions that could reach a
// scanner as an option or point outside the checkout: absolute paths, ".."
// segments, a leading "-", NUL. "." (the repository) is allowed.
func ValidatePlanPaths(targets, exclusions []string) error {
	for _, target := range targets {
		if err := validatePlanPath(target); err != nil {
			return fmt.Errorf("target %q: %w", target, err)
		}
	}
	for _, exclusion := range exclusions {
		if err := validatePlanPath(exclusion); err != nil {
			return fmt.Errorf("exclusion %q: %w", exclusion, err)
		}
	}
	return nil
}

func validatePlanPath(value string) error {
	switch {
	case value == "":
		return fmt.Errorf("%w: empty", ErrUnsafePath)
	case strings.ContainsRune(value, 0):
		return fmt.Errorf("%w: NUL byte", ErrUnsafePath)
	case strings.HasPrefix(value, "-"):
		return fmt.Errorf("%w: starts with '-'", ErrUnsafePath)
	case strings.HasPrefix(value, "/"), strings.HasPrefix(value, `\`), filepath.IsAbs(value), filepath.VolumeName(value) != "":
		return fmt.Errorf("%w: absolute", ErrUnsafePath)
	}
	for _, segment := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return fmt.Errorf("%w: '..' segment", ErrUnsafePath)
		}
	}
	return nil
}

// withinRoot joins a validated module path to root and checks the result,
// symbolic links resolved, stays under root.
func withinRoot(root, module string) (string, error) {
	if err := validatePlanPath(module); err != nil {
		return "", err
	}
	joined := filepath.Join(root, filepath.FromSlash(module))
	if !under(filepath.Clean(root), joined) {
		return "", fmt.Errorf("%w: %s leaves the source root", ErrUnsafePath, module)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	realDir, err := filepath.EvalSymlinks(joined)
	if errors.Is(err, os.ErrNotExist) {
		return joined, nil // a missing module fails later as a prerequisite
	}
	if err != nil {
		return "", err
	}
	if !under(realRoot, realDir) {
		return "", fmt.Errorf("%w: %s resolves outside the source root", ErrUnsafePath, module)
	}
	return joined, nil
}

func under(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

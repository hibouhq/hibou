package scancatalog

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Distribution modes (ADR-035 "Offline distribution and location overrides").
const (
	// ModeUpstream: approved locations and mirrors first, upstream as the
	// last resort.
	ModeUpstream = "upstream"
	// ModeMirror: approved locations or the installation mirror only; never
	// upstream.
	ModeMirror = "mirror"
	// ModeOffline: the local verified bundle only; no network at all.
	ModeOffline = "offline"
)

// DistributionConfig is the operator's control over where scanner artifacts
// come from. A mirror changes the location, never the pinned version, the
// sha256, or the ruleset (ADR-035).
type DistributionConfig struct {
	Mode string
	// MirrorBaseURL serves binaries as <base>/<scanner-id>/<engine-version>/<asset>.
	MirrorBaseURL string
	// MavenMirrorURL replaces https://repo1.maven.org/maven2 for Maven artifacts.
	MavenMirrorURL string
	// Locations are approved per-scanner base URLs, same layout as the mirror
	// without the scanner id: <base>/<engine-version>/<asset>.
	Locations map[string]string
	// BundleDir is the read-only directory an offline bundle was imported
	// into: <dir>/<scanner-id>/<engine-version>/<asset or coordinates path>.
	BundleDir string
	// ApprovedHosts restricts every resolved https URL. Empty in upstream
	// mode means "the catalog's own hosts and the configured mirrors".
	ApprovedHosts []string
	// CABundle is a PEM file trusted for mirror TLS (internal CAs).
	CABundle string
}

const mavenCentralBase = "https://repo1.maven.org/maven2"

// Normalize fills the default mode and trims inputs.
func (c DistributionConfig) Normalize() DistributionConfig {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = ModeUpstream
	}
	c.MirrorBaseURL = strings.TrimRight(strings.TrimSpace(c.MirrorBaseURL), "/")
	c.MavenMirrorURL = strings.TrimRight(strings.TrimSpace(c.MavenMirrorURL), "/")
	c.BundleDir = strings.TrimSpace(c.BundleDir)
	locations := make(map[string]string, len(c.Locations))
	for id, base := range c.Locations {
		locations[strings.TrimSpace(id)] = strings.TrimRight(strings.TrimSpace(base), "/")
	}
	c.Locations = locations
	return c
}

// Validate rejects configurations that could silently fetch from somewhere
// unapproved: unknown mode, plain http, credentials in URLs, an offline mode
// without a bundle, a location for a scanner the catalog does not have, or a
// configured URL outside the approved hosts.
func (c DistributionConfig) Validate(catalog *Catalog) error {
	c = c.Normalize()
	switch c.Mode {
	case ModeUpstream, ModeMirror, ModeOffline:
	default:
		return fmt.Errorf("scanner_distribution.mode %q: must be upstream, mirror or offline", c.Mode)
	}
	if c.Mode == ModeOffline && c.BundleDir == "" {
		return errors.New("scanner_distribution.mode offline needs bundle_dir")
	}
	if c.BundleDir != "" && !filepath.IsAbs(c.BundleDir) {
		return errors.New("scanner_distribution.bundle_dir must be an absolute path")
	}
	check := func(field, raw string) error {
		if raw == "" {
			return nil
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("scanner_distribution.%s %q must be an https URL", field, raw)
		}
		if parsed.User != nil {
			return fmt.Errorf("scanner_distribution.%s must not carry credentials in the URL", field)
		}
		if len(c.ApprovedHosts) > 0 && !hostApproved(parsed.Hostname(), c.ApprovedHosts) {
			return fmt.Errorf("scanner_distribution.%s host %q is not in approved_hosts", field, parsed.Hostname())
		}
		return nil
	}
	if err := check("mirror_base_url", c.MirrorBaseURL); err != nil {
		return err
	}
	if err := check("maven_mirror_url", c.MavenMirrorURL); err != nil {
		return err
	}
	ids := make([]string, 0, len(c.Locations))
	for id := range c.Locations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if catalog != nil {
			if _, ok := catalog.Scanner(id); !ok {
				return fmt.Errorf("scanner_distribution.locations: unknown scanner %q", id)
			}
		}
		if err := check("locations."+id, c.Locations[id]); err != nil {
			return err
		}
	}
	if c.Mode == ModeMirror && c.MirrorBaseURL == "" && len(c.Locations) == 0 && c.MavenMirrorURL == "" {
		return errors.New("scanner_distribution.mode mirror needs mirror_base_url, maven_mirror_url or locations")
	}
	return nil
}

func hostApproved(host string, approved []string) bool {
	host = strings.ToLower(host)
	for _, candidate := range approved {
		if strings.EqualFold(strings.TrimSpace(candidate), host) {
			return true
		}
	}
	return false
}

// Location is where one artifact is fetched from, with the pin it must match.
type Location struct {
	ScannerID string `json:"scanner_id"`
	// URL is https, or file:// for an offline bundle.
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	// Source is approved-location, mirror, bundle or upstream.
	Source string `json:"source"`
}

// ErrUnavailable means no location the configuration allows serves the
// artifact: setup must fail and name it, never fall back (ADR-035).
var ErrUnavailable = errors.New("artifact unavailable under the scanner distribution policy")

// Resolve picks the location of one distribution artifact. Precedence:
// offline bundle (offline mode only), approved per-scanner location,
// installation mirror, then upstream in upstream mode only.
func (c DistributionConfig) Resolve(scanner *Scanner, distribution *Distribution) (Location, error) {
	c = c.Normalize()
	location := Location{ScannerID: scanner.ID, SHA256: distribution.SHA256}
	relative := artifactPath(distribution)
	if relative == "" {
		return location, fmt.Errorf("%w: %s has no artifact name", ErrUnavailable, distribution.URL)
	}
	if c.Mode == ModeOffline {
		location.URL = "file://" + filepath.ToSlash(filepath.Join(c.BundleDir, scanner.ID, scanner.EngineVersion, filepath.FromSlash(relative)))
		location.Source = "bundle"
		return location, nil
	}
	if distribution.Kind == KindMaven {
		if c.MavenMirrorURL != "" {
			location.URL = c.MavenMirrorURL + strings.TrimPrefix(distribution.URL, mavenCentralBase)
			location.Source = "mirror"
			return location, nil
		}
	} else {
		if base, ok := c.Locations[scanner.ID]; ok && base != "" {
			location.URL = base + "/" + url.PathEscape(scanner.EngineVersion) + "/" + relative
			location.Source = "approved-location"
			return location, nil
		}
		if c.MirrorBaseURL != "" {
			location.URL = c.MirrorBaseURL + "/" + scanner.ID + "/" + url.PathEscape(scanner.EngineVersion) + "/" + relative
			location.Source = "mirror"
			return location, nil
		}
	}
	if c.Mode == ModeMirror {
		return location, fmt.Errorf("%w: %s %s has no mirror or approved location (mirror mode never falls back upstream)", ErrUnavailable, scanner.ID, relative)
	}
	location.URL = distribution.URL
	location.Source = "upstream"
	return location, nil
}

// artifactPath is the artifact's name inside a mirror or bundle: the asset
// for binaries, the Maven repository path for Maven artifacts.
func artifactPath(distribution *Distribution) string {
	switch distribution.Kind {
	case KindBinary:
		return url.PathEscape(distribution.Asset)
	case KindMaven:
		parsed, err := url.Parse(distribution.URL)
		if err != nil {
			return ""
		}
		return strings.TrimPrefix(path.Clean(strings.TrimPrefix(parsed.Path, "/maven2")), "/")
	}
	return ""
}

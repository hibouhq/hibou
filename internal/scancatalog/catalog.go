// Package scancatalog is the versioned catalog of scanners hibou supports in
// CI (ADR-035 §2): what each scanner can analyse, how it is distributed and
// verified, and how to run it. The catalog is data embedded in the binary;
// executables are never shipped in the server (ADR-035 §1).
package scancatalog

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

//go:embed catalog.json
var embeddedCatalog []byte

// SchemaVersion is the catalog format this build reads.
const SchemaVersion = 1

// Support statuses.
const (
	StatusSupported = "supported"
	StatusPreview   = "preview"
)

// Ruleset statuses: only an approved ruleset is selectable by plans.
const (
	RulesetApproved             = "approved"
	RulesetLicenseReviewPending = "license-review-pending"
)

// Distribution kinds.
const (
	KindBinary = "binary"
	KindMaven  = "maven"
	KindOCI    = "oci"
)

// Catalog is the whole catalog document.
type Catalog struct {
	SchemaVersion int       `json:"schema_version"`
	Revision      string    `json:"revision"`
	Scanners      []Scanner `json:"scanners"`
	Rulesets      []Ruleset `json:"rulesets"`
}

// Scanner is one versioned catalog entry.
type Scanner struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Engine         string            `json:"engine"`
	EngineVersion  string            `json:"engine_version"`
	AdapterVersion string            `json:"adapter_version"`
	License        string            `json:"license"`
	SupportStatus  string            `json:"support_status"`
	Prerelease     bool              `json:"prerelease"`
	ProducerNames  []string          `json:"producer_names"`
	Homepage       string            `json:"homepage,omitempty"`
	Notes          string            `json:"notes,omitempty"`
	Distributions  []Distribution    `json:"distributions"`
	Rulesets       []string          `json:"rulesets"`
	Capabilities   []Capability      `json:"capabilities"`
	Applicability  Applicability     `json:"applicability"`
	Stages         Stages            `json:"stages"`
	DiffSupport    string            `json:"diff_support"`
	Resources      Resources         `json:"resources"`
	ExitCodes      map[string]string `json:"exit_codes"`
	Command        Command           `json:"command"`
	SARIF          SARIFTraits       `json:"sarif"`
}

// Distribution is one verified artifact of a scanner for one platform.
type Distribution struct {
	Kind        string     `json:"kind"`
	OS          string     `json:"os,omitempty"`
	Arch        string     `json:"arch,omitempty"`
	Libc        string     `json:"libc,omitempty"`
	Asset       string     `json:"asset,omitempty"`
	Coordinates string     `json:"coordinates,omitempty"`
	URL         string     `json:"url"`
	SHA256      string     `json:"sha256"`
	Size        int64      `json:"size,omitempty"`
	Signature   *Signature `json:"signature,omitempty"`
}

// Signature points at a detached signature. Verification of the signer's
// identity is a setup-adapter concern; the sha256 is always enforced.
type Signature struct {
	Kind           string `json:"kind"`
	SignatureURL   string `json:"signature_url"`
	CertificateURL string `json:"certificate_url"`
}

// Capability is one language × analysis pair. Evidence is "declared" (the
// engine says so) or "measured:<where>" (a fixture run showed it); ADR-035 §2
// forbids inferring that every language gets every capability.
type Capability struct {
	Language   string `json:"language"`
	Capability string `json:"capability"`
	Evidence   string `json:"evidence"`
}

// Measured reports whether a fixture run backs the capability.
func (c Capability) Measured() bool { return strings.HasPrefix(c.Evidence, "measured:") }

// Applicability predicates: what in a repository makes the scanner relevant.
type Applicability struct {
	Extensions   []string `json:"extensions,omitempty"`
	Manifests    []string `json:"manifests,omitempty"`
	BuildSystems []string `json:"build_systems,omitempty"`
}

// Stages: what the scanner needs before it runs and what it produces.
type Stages struct {
	Requires []string `json:"requires"`
	Produces []string `json:"produces"`
}

// Resources is the default budget of one run.
type Resources struct {
	CPU            int `json:"cpu"`
	MemoryMB       int `json:"memory_mb"`
	TimeoutSeconds int `json:"timeout_seconds"`
}

// Command is the argument template; {sarif}, {rules} and {targets} are filled
// by the adapter, never by shell interpolation.
type Command struct {
	Args []string `json:"args"`
}

// SARIFTraits are the quirks of the scanner's report that ingestion relies on.
type SARIFTraits struct {
	Fingerprint string `json:"fingerprint"`
	Paths       string `json:"paths"`
	CodeFlows   string `json:"code_flows"`
}

// Ruleset is a rules distribution a scanner can run.
type Ruleset struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Source   string `json:"source"`
	Revision string `json:"revision"`
	License  string `json:"license"`
	Status   string `json:"status"`
	Notes    string `json:"notes,omitempty"`
}

// Selectable reports whether plans may use the ruleset.
func (r Ruleset) Selectable() bool { return r.Status == RulesetApproved }

// Load parses and validates the embedded catalog.
func Load() (*Catalog, error) {
	return Parse(embeddedCatalog)
}

// Parse decodes and validates a catalog document.
func Parse(data []byte) (*Catalog, error) {
	var catalog Catalog
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decode scanner catalog: %w", err)
	}
	if err := catalog.Validate(); err != nil {
		return nil, err
	}
	return &catalog, nil
}

var (
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

// Validate checks the invariants every consumer relies on: unique ids,
// pinned https artifacts with a sha256, known rulesets, declared evidence.
func (c *Catalog) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("scanner catalog schema %d, this build reads %d", c.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(c.Revision) == "" {
		return errors.New("scanner catalog has no revision")
	}
	rulesets := make(map[string]bool, len(c.Rulesets))
	for _, ruleset := range c.Rulesets {
		if !idPattern.MatchString(ruleset.ID) || rulesets[ruleset.ID] {
			return fmt.Errorf("ruleset id %q is invalid or duplicated", ruleset.ID)
		}
		rulesets[ruleset.ID] = true
		if ruleset.Status != RulesetApproved && ruleset.Status != RulesetLicenseReviewPending {
			return fmt.Errorf("ruleset %s: unknown status %q", ruleset.ID, ruleset.Status)
		}
	}
	seen := make(map[string]bool, len(c.Scanners))
	for _, scanner := range c.Scanners {
		if !idPattern.MatchString(scanner.ID) || seen[scanner.ID] {
			return fmt.Errorf("scanner id %q is invalid or duplicated", scanner.ID)
		}
		seen[scanner.ID] = true
		if scanner.SupportStatus != StatusSupported && scanner.SupportStatus != StatusPreview {
			return fmt.Errorf("scanner %s: unknown support status %q", scanner.ID, scanner.SupportStatus)
		}
		if scanner.Prerelease && scanner.SupportStatus != StatusPreview {
			return fmt.Errorf("scanner %s: a pre-release must be in preview", scanner.ID)
		}
		if len(scanner.ProducerNames) == 0 {
			return fmt.Errorf("scanner %s: no producer names (its SARIF driver names)", scanner.ID)
		}
		if len(scanner.Distributions) == 0 {
			return fmt.Errorf("scanner %s: no distribution", scanner.ID)
		}
		for _, distribution := range scanner.Distributions {
			if err := distribution.validate(); err != nil {
				return fmt.Errorf("scanner %s: %w", scanner.ID, err)
			}
		}
		for _, ruleset := range scanner.Rulesets {
			if !rulesets[ruleset] {
				return fmt.Errorf("scanner %s: unknown ruleset %q", scanner.ID, ruleset)
			}
		}
		if len(scanner.Capabilities) == 0 {
			return fmt.Errorf("scanner %s: no capability", scanner.ID)
		}
		for _, capability := range scanner.Capabilities {
			if capability.Language == "" || capability.Capability == "" {
				return fmt.Errorf("scanner %s: capability without language or name", scanner.ID)
			}
			if capability.Evidence != "declared" && !capability.Measured() {
				return fmt.Errorf("scanner %s: capability %s/%s has no evidence", scanner.ID, capability.Language, capability.Capability)
			}
		}
		for _, arg := range scanner.Command.Args {
			if strings.ContainsAny(arg, "`$;|&") {
				return fmt.Errorf("scanner %s: command argument %q contains shell syntax", scanner.ID, arg)
			}
		}
	}
	return nil
}

func (d Distribution) validate() error {
	switch d.Kind {
	case KindBinary:
		if d.OS == "" || d.Arch == "" || d.Asset == "" {
			return errors.New("binary distribution needs os, arch and asset")
		}
	case KindMaven:
		if strings.Count(d.Coordinates, ":") != 2 {
			return fmt.Errorf("maven distribution needs group:artifact:version coordinates, got %q", d.Coordinates)
		}
	case KindOCI:
	default:
		return fmt.Errorf("unknown distribution kind %q", d.Kind)
	}
	parsed, err := url.Parse(d.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("distribution url %q must be https", d.URL)
	}
	if !sha256Pattern.MatchString(d.SHA256) {
		return fmt.Errorf("distribution %s has no valid sha256", d.URL)
	}
	return nil
}

// Scanner returns the entry with the given id.
func (c *Catalog) Scanner(id string) (*Scanner, bool) {
	for i := range c.Scanners {
		if c.Scanners[i].ID == id {
			return &c.Scanners[i], true
		}
	}
	return nil, false
}

// Ruleset returns the ruleset with the given id.
func (c *Catalog) Ruleset(id string) (*Ruleset, bool) {
	for i := range c.Rulesets {
		if c.Rulesets[i].ID == id {
			return &c.Rulesets[i], true
		}
	}
	return nil, false
}

// ScannerForProducer maps a SARIF producer name (lower(tool.driver.name)) to
// the catalog entries that write it. Several entries can share a name (the
// OpenGrep release and its interfile pre-release): the producer run's
// digest, recorded by the adapter, tells them apart.
func (c *Catalog) ScannerForProducer(producer string) []*Scanner {
	out := make([]*Scanner, 0, 1)
	for i := range c.Scanners {
		for _, name := range c.Scanners[i].ProducerNames {
			if name == producer {
				out = append(out, &c.Scanners[i])
				break
			}
		}
	}
	return out
}

// BinaryFor returns the binary distribution for a platform; libc "" prefers
// glibc builds.
func (s *Scanner) BinaryFor(goos, goarch, libc string) (*Distribution, bool) {
	candidates := make([]*Distribution, 0, 2)
	for i := range s.Distributions {
		d := &s.Distributions[i]
		if d.Kind == KindBinary && d.OS == goos && d.Arch == goarch && (libc == "" || d.Libc == "" || d.Libc == libc) {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 0 {
		return nil, false
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Libc != "musl" && candidates[j].Libc == "musl" })
	return candidates[0], true
}

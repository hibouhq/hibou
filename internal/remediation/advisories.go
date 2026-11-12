package remediation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"deps.dev/util/semver"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/hibouhq/hibou/internal/advisorydb"
)

type AdvisoryMatch struct {
	Purl             string            `json:"purl"`
	Supported        bool              `json:"supported"`
	Decision         string            `json:"decision"`
	PrivateNamespace *bool             `json:"private_namespace"`
	Reason           string            `json:"reason"`
	Advisories       []MatchedAdvisory `json:"advisories"`
	Signals          *MatchSignals     `json:"signals,omitempty"`
}

type MatchSignals struct {
	RecommendedVersion string    `json:"recommended_version"`
	FetchedAt          time.Time `json:"fetched_at"`
}

type MatchedAdvisory struct {
	CanonicalID string             `json:"canonical_id"`
	VEXStatus   string             `json:"vex_status"`
	Ranges      []advisorydb.Range `json:"affected_ranges"`
}

// MatchPackages receives identities/versions only, never repository contents.
// Implementations must return one authoritative entry per requested PURL.
type MatchPackages func(context.Context, []string) ([]AdvisoryMatch, error)

var ErrAdvisoryEvidence = errors.New("authoritative advisory/policy evidence is unavailable")

type MatchEnricher struct {
	Match MatchPackages
}

func (MatchEnricher) Name() string                       { return "vulnmatch/hibou" }
func (MatchEnricher) Version() int                       { return 1 }
func (MatchEnricher) Requirements() *plugin.Capabilities { return nil }
func (MatchEnricher) RequiredPlugins() []string          { return nil }

func (e MatchEnricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	if e.Match == nil {
		return errors.New("hibou advisory matching is unavailable")
	}
	purls := make([]string, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		key := p.PURL()
		if key == nil {
			return errors.New("cannot establish package identity for remediation")
		}
		purls = append(purls, key.String())
	}
	if len(purls) == 0 {
		return nil
	}
	matches, err := checkedMatches(ctx, e.Match, purls)
	if err != nil {
		return err
	}
	for i, pkg := range inv.Packages {
		for _, match := range matches[purls[i]].Advisories {
			if match.VEXStatus == "not_affected" || match.VEXStatus == "fixed" {
				continue
			}
			vuln, err := match.OSV()
			if err != nil {
				return err
			}
			inv.PackageVulns = append(inv.PackageVulns, &inventory.PackageVuln{Package: pkg, Vulnerability: vuln})
		}
	}
	return nil
}

func (a MatchedAdvisory) OSV() (*osvpb.Vulnerability, error) {
	if a.CanonicalID == "" || len(a.Ranges) == 0 {
		return nil, errors.New("complete advisory ranges are required; upgrade the Hibou server")
	}
	v := &osvpb.Vulnerability{Id: a.CanonicalID}
	for _, r := range a.Ranges {
		if !strings.EqualFold(r.Ecosystem, "npm") || r.Release != "" {
			continue
		}
		if r.Package == "" || (r.Fixed != "" && r.LastAffected != "") {
			return nil, fmt.Errorf("unsupported affected interval in %s", a.CanonicalID)
		}
		introduced := r.Introduced
		if introduced == "" {
			introduced = "0"
		}
		for _, boundary := range []string{introduced, r.Fixed, r.LastAffected} {
			if boundary != "" && boundary != "0" {
				if _, err := semver.NPM.Parse(boundary); err != nil {
					return nil, fmt.Errorf("unsupported affected version in %s", a.CanonicalID)
				}
			}
		}
		events := []*osvpb.Event{{Introduced: introduced}}
		if r.Fixed != "" {
			events = append(events, &osvpb.Event{Fixed: r.Fixed})
		}
		if r.LastAffected != "" {
			events = append(events, &osvpb.Event{LastAffected: r.LastAffected})
		}
		v.Affected = append(v.Affected, &osvpb.Affected{
			Package: &osvpb.Package{Ecosystem: "npm", Name: r.Package},
			Ranges:  []*osvpb.Range{{Type: osvpb.Range_SEMVER, Events: events}},
		})
	}
	if len(v.Affected) == 0 {
		return nil, fmt.Errorf("advisory %s has no supported npm ranges", a.CanonicalID)
	}
	return v, nil
}

func checkedMatches(ctx context.Context, match MatchPackages, purls []string) (map[string]AdvisoryMatch, error) {
	unique := map[string]bool{}
	var requested []string
	for _, purl := range purls {
		if !unique[purl] {
			unique[purl] = true
			requested = append(requested, purl)
		}
	}
	results, err := match(ctx, requested)
	if err != nil {
		return nil, err
	}
	out := make(map[string]AdvisoryMatch, len(results))
	for _, entry := range results {
		if !unique[entry.Purl] || out[entry.Purl].Purl != "" || !entry.Supported || entry.PrivateNamespace == nil {
			return nil, errors.New("advisory matching returned incomplete, duplicate or unsupported package evidence")
		}
		if *entry.PrivateNamespace {
			return nil, errors.New("private namespace requires an approved private-registry adapter; no public lookup was performed")
		}
		out[entry.Purl] = entry
	}
	if len(out) != len(requested) {
		return nil, errors.New("advisory matching omitted package evidence")
	}
	return out, nil
}

package osv

import (
	"context"
	"errors"
	"strings"
)

// maxAliasHops stops a long alias list turning one check into a burst of
// requests.
const maxAliasHops = 4

// Coordinate is one package an advisory names.
type Coordinate struct {
	Ecosystem string
	Name      string
}

// PackagesForVuln returns the packages OSV names for one vulnerability ID
// (ADR-028 §10).
//
// Aliases are followed, and that is the difference between working and always
// answering "nothing": OSV serves a CVE ID from its CVE ecosystem, where
// affected[].package is null. /v1/vulns/CVE-2021-44228 names no package at all
// while its alias GHSA-jfh8-c2jp-5v3q carries ten Maven ones.
//
// Naming no packages, and an ID OSV does not serve, are both ordinary — an empty
// slice, not an error.
func (p *Provider) PackagesForVuln(ctx context.Context, vulnID string) ([]Coordinate, error) {
	record, err := p.fetchVuln(ctx, vulnID)
	if errors.Is(err, ErrVulnNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	coordinates := collectCoordinates(record.Affected, seen)
	if len(coordinates) > 0 {
		return coordinates, nil
	}

	// No coordinates on the record itself: it is the CVE-ecosystem copy, and the
	// packages are on whichever database reviewed it.
	hops := 0
	for _, alias := range record.Aliases {
		if hops >= maxAliasHops {
			break
		}
		if strings.EqualFold(alias, vulnID) {
			continue
		}
		hops++
		aliased, aliasErr := p.fetchVuln(ctx, alias)
		if aliasErr != nil {
			// A partial answer is still a comparison.
			continue
		}
		coordinates = append(coordinates, collectCoordinates(aliased.Affected, seen)...)
	}
	return coordinates, nil
}

// collectCoordinates appends the distinct packages an affected list names,
// deduplicating against everything already seen across records.
func collectCoordinates(affected []affectedPackage, seen map[string]struct{}) []Coordinate {
	coordinates := make([]Coordinate, 0, len(affected))
	for _, entry := range affected {
		name := strings.TrimSpace(entry.Package.Name)
		if name == "" {
			continue
		}
		ecosystem := normalizeVulnEcosystem(entry.Package.Ecosystem)
		key := ecosystem + ":" + name
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		coordinates = append(coordinates, Coordinate{Ecosystem: ecosystem, Name: name})
	}
	return coordinates
}

// normalizeVulnEcosystem maps OSV's spelling to ours and strips the distro
// release qualifier ("Debian:12"), which is not part of the coordinate.
func normalizeVulnEcosystem(ecosystem string) string {
	ecosystem = strings.TrimSpace(ecosystem)
	if base, _, found := strings.Cut(ecosystem, ":"); found {
		ecosystem = base
	}
	if mapped, ok := osvToInternalEcosystem[ecosystem]; ok {
		return mapped
	}
	return strings.ToLower(ecosystem)
}

// Package cvetriage turns watched products into advisory data.
//
// The problem it exists for: some advisories name a product and a version range
// and nothing else. "Apache Tomcat, 11.0.0-M1 through 11.0.23" is exact, and it
// is unmatchable — no upstream record says that means
// org.apache.tomcat:tomcat-catalina, so every purl-based scanner reports the
// image clean. The mapping is not data anyone publishes; it comes into being
// only when a person authors it.
//
// So the split here is deliberate, and it is the whole design:
//
//   - VERSION RANGES are mechanical. They come from the CNA record verbatim,
//     and a human never types one. People are good at identity and bad at
//     transcribing five branches of version bounds without error.
//   - IDENTITY is judgement, and it is asked once per product rather than once
//     per CVE. The next advisory for the same product resolves from the stored
//     mapping.
//
// What a decision produces is an ordinary advisory. It is written through the
// same ingest path every provider uses, under a source naming who authored it,
// and the normal purl matcher finds it on the next scan. Nothing downstream —
// reachability, delta, gates, VEX, triage — can tell it apart, which is why this
// package adds no matching lane of its own.
package cvetriage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/cvefeed"
)

// SourceTriage is the advisory source for anything a person authored here.
//
// One source, because triage is instance-wide. An earlier draft scoped
// decisions per organization; that has no deployment — on a single-company
// instance every org is the same company, and on a multi-tenant one a customer
// authoring for the others is an escalation, which is served by centrally
// curated advisories shipped as data instead.
const SourceTriage = "triage"

// Package is one coordinate a triager selected.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Decision is a completed triage: this advisory affects these packages.
//
// It carries no version ranges. That is not an omission — see the package doc.
type Decision struct {
	CVEID    string
	Packages []Package
	ActorID  uuid.UUID
}

// Validate rejects a decision that would author nonsense.
func (d Decision) Validate() error {
	if !cvefeed.ValidCVEID(d.CVEID) {
		return fmt.Errorf("cvetriage: malformed CVE id %q", d.CVEID)
	}
	if len(d.Packages) == 0 {
		return errors.New("cvetriage: a decision must name at least one package")
	}
	for _, pkg := range d.Packages {
		if strings.TrimSpace(pkg.Ecosystem) == "" || strings.TrimSpace(pkg.Name) == "" {
			return fmt.Errorf("cvetriage: incomplete package %+v", pkg)
		}
	}
	if d.ActorID == uuid.Nil {
		return errors.New("cvetriage: a decision must record who made it")
	}
	return nil
}

// Source names the advisory source a decision writes under.
func (d Decision) Source() string { return SourceTriage }

// BuildIngestResult turns a decision plus the CNA's record into advisory data.
//
// The alias is what makes this safe to author. Carrying the CVE id in Aliases
// means the ingester's canonical-id logic converges this onto the SAME advisory
// row as OSV's and NVD's records for that CVE — one advisory, one finding,
// several sources — rather than minting a parallel identity that would
// double-count the moment upstream catches up.
//
// Ranges are copied from the record, not recomputed: an inclusive bound stays
// last-affected and never becomes a fixed version, because naming a fix means
// naming a release nobody verified exists.
func BuildIngestResult(decision Decision, record cvefeed.Projection) (advisory.IngestResult, error) {
	if err := decision.Validate(); err != nil {
		return advisory.IngestResult{}, err
	}
	if record.ID != decision.CVEID {
		return advisory.IngestResult{}, fmt.Errorf(
			"cvetriage: decision is for %s but record is %s", decision.CVEID, record.ID)
	}

	ranges := make([]advisory.AffectedRange, 0, len(decision.Packages))
	for _, pkg := range decision.Packages {
		ecosystem := strings.ToLower(strings.TrimSpace(pkg.Ecosystem))
		for _, product := range record.Affected {
			for _, versionRange := range product.Ranges {
				ranges = append(ranges, advisory.AffectedRange{
					Ecosystem:    ecosystem,
					PackageName:  strings.TrimSpace(pkg.Name),
					Introduced:   versionRange.Introduced,
					Fixed:        versionRange.Fixed,
					LastAffected: versionRange.LastAffected,
					Source:       decision.Source(),
				})
			}
		}
	}
	if len(ranges) == 0 {
		return advisory.IngestResult{}, fmt.Errorf(
			"cvetriage: %s carries no usable version ranges to author", decision.CVEID)
	}

	result := advisory.IngestResult{
		ProviderID:     record.ID,
		Aliases:        []string{record.ID},
		Title:          summarize(record),
		Description:    record.Description,
		CWEIDs:         record.CWEs,
		AffectedRanges: ranges,
	}
	// No ratings of its own: the record's rating reaches the advisory as its
	// CVE-feed source, which every advisory with this CVE alias gets
	// (ADR-038 §2), so an authored advisory and an upstream one rate alike.
	if !record.Published.IsZero() {
		published := record.Published
		result.PublishedAt = &published
	}
	// A withdrawn record must carry that through: findings derived from it are
	// retired rather than left standing for someone to notice.
	if record.Withdrawn() {
		withdrawn := record.Updated
		if withdrawn.IsZero() {
			withdrawn = time.Now().UTC()
		}
		result.WithdrawnAt = &withdrawn
	}
	return result, nil
}

// summarize prefers the CNA's own one-line title where the description carries
// one, falling back to the id so an advisory is never nameless in a list.
func summarize(record cvefeed.Projection) string {
	description := strings.TrimSpace(record.Description)
	if description == "" {
		return record.ID
	}
	if line, _, found := strings.Cut(description, "\n"); found {
		description = strings.TrimSpace(line)
	}
	const maxTitle = 160
	if len(description) > maxTitle {
		return strings.TrimSpace(description[:maxTitle]) + "…"
	}
	return description
}

// Ingester is the advisory write path this package authors through. It is the
// same one every provider uses.
type Ingester interface {
	Ingest(ctx context.Context, providerName string, results []advisory.IngestResult) (map[string]uuid.UUID, error)
}

// Apply authors a triage decision as advisory data.
func Apply(ctx context.Context, ingester Ingester, decision Decision, record cvefeed.Projection) (uuid.UUID, error) {
	result, err := BuildIngestResult(decision, record)
	if err != nil {
		return uuid.Nil, err
	}
	ids, err := ingester.Ingest(ctx, decision.Source(), []advisory.IngestResult{result})
	if err != nil {
		return uuid.Nil, fmt.Errorf("author advisory for %s: %w", decision.CVEID, err)
	}
	if id, ok := ids[record.ID]; ok {
		return id, nil
	}
	for _, id := range ids {
		return id, nil
	}
	return uuid.Nil, fmt.Errorf("cvetriage: ingest returned no advisory for %s", decision.CVEID)
}

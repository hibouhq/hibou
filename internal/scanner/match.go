package scanner

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/sbom"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Stateless matching (ADR-046 §2): the CLI's local scan sends purls and
// versions only, and gets the organisation's advisory view back. Nothing
// is persisted; the same version comparison as the snapshot scan applies.

// PurlMatch is the advisories a package version matches.
type PurlMatch struct {
	Purl      string
	Ecosystem string
	Name      string
	Version   string
	// Supported is false when the purl has no version or its ecosystem is
	// not one the comparator knows: nothing was checked.
	Supported  bool
	Advisories []MatchedAdvisory
}

// MatchedAdvisory is one advisory as the finding drawer would show it.
type MatchedAdvisory struct {
	AdvisoryID    uuid.UUID
	CanonicalID   string
	Title         string
	Severity      string
	CVSSScore     *float64
	RatedBy       string
	IsMalware     bool
	MalwareType   string
	FixedVersions []string
	PublishedAt   *time.Time
}

// MatchPurls matches each purl against the stored advisories, in order.
func (s *Service) MatchPurls(ctx context.Context, purls []string) ([]PurlMatch, error) {
	state := newComponentMatchState(nil)
	out := make([]PurlMatch, 0, len(purls))
	for _, purl := range purls {
		purl = strings.TrimSpace(purl)
		match := PurlMatch{
			Purl:      purl,
			Ecosystem: sbom.EcosystemFromPURL(purl),
			Name:      sbom.PackageNameFromPURL(purl),
			Version:   sbom.VersionFromPURL(purl),
		}
		if match.Ecosystem == "" || match.Name == "" || match.Version == "" {
			out = append(out, match)
			continue
		}
		component := dbgen.Component{Purl: purl, Name: match.Name, Version: match.Version, Ecosystem: match.Ecosystem}
		ranges, err := s.loadAffectedRangesForComponent(ctx, component, state)
		if err != nil {
			return nil, err
		}
		match.Supported = true
		fixedByAdvisory := make(map[uuid.UUID][]string)
		for _, affectedRange := range ranges {
			if fixed := strings.TrimSpace(affectedRange.Fixed); fixed != "" {
				fixedByAdvisory[affectedRange.AdvisoryID] = append(fixedByAdvisory[affectedRange.AdvisoryID], fixed)
			}
		}
		seen := make(map[uuid.UUID]bool)
		for _, affectedRange := range ranges {
			if seen[affectedRange.AdvisoryID] || !s.componentMatchesAffectedRange(component, affectedRange) {
				continue
			}
			record, err := s.loadMatchedAdvisory(ctx, affectedRange.AdvisoryID, state)
			if err != nil {
				return nil, err
			}
			if record.WithdrawnAt.Valid {
				continue
			}
			seen[affectedRange.AdvisoryID] = true
			ratings, err := s.loadMatchedRatings(ctx, affectedRange.AdvisoryID, state)
			if err != nil {
				return nil, err
			}
			choice := advisory.FindingRating(ratings, record.IsMalware, component.Ecosystem, component.Purl)
			matched := MatchedAdvisory{
				AdvisoryID:    record.ID,
				CanonicalID:   record.CanonicalID,
				Title:         firstNonEmpty(strings.TrimSpace(record.Title), strings.TrimSpace(record.CanonicalID)),
				Severity:      string(choice.Severity),
				IsMalware:     record.IsMalware,
				FixedVersions: uniqueSorted(fixedByAdvisory[record.ID]),
			}
			if choice.Rating != nil {
				matched.CVSSScore = choice.Rating.Score
				matched.RatedBy = choice.Rating.Rater
			}
			if record.MalwareType.Valid {
				matched.MalwareType = string(record.MalwareType.MalwareType)
			}
			if record.PublishedAt.Valid {
				published := record.PublishedAt.Time
				matched.PublishedAt = &published
			}
			match.Advisories = append(match.Advisories, matched)
		}
		sort.Slice(match.Advisories, func(i, j int) bool {
			return match.Advisories[i].CanonicalID < match.Advisories[j].CanonicalID
		})
		out = append(out, match)
	}
	return out, nil
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

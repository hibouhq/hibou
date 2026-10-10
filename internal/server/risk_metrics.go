package server

import (
	"context"
	"strconv"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/store"
)

// attachRiskMetrics decorates a page of findings with EPSS and the ratings
// behind their severity (ADR-038 §6), in two batched queries. List rows get
// every rating only when raters disagree (the hover behind the list's
// marker); a detail view asks for them always. Best-effort like KEV: a failed
// lookup costs the decoration, not the list.
func (s *Server) attachRiskMetrics(ctx context.Context, vulnerabilities []store.Vulnerability, allRatings bool) {
	advisoryIDs := make([]uuid.UUID, 0, len(vulnerabilities))
	seen := make(map[uuid.UUID]struct{}, len(vulnerabilities))
	for i := range vulnerabilities {
		id := vulnerabilities[i].AdvisoryID
		if id == nil || !isAdvisoryBackedFindingType(vulnerabilities[i].Type) {
			continue
		}
		if _, ok := seen[*id]; !ok {
			seen[*id] = struct{}{}
			advisoryIDs = append(advisoryIDs, *id)
		}
	}
	if len(advisoryIDs) == 0 {
		return
	}

	ratingsByAdvisory := map[uuid.UUID][]advisory.Rating{}
	if rows, err := s.queries.ListAdvisoryRatings(ctx, advisoryIDs); err != nil {
		s.log.Warn().Err(err).Msg("failed to attach ratings")
	} else {
		for i, rating := range advisory.RatingsFromRows(rows) {
			ratingsByAdvisory[rows[i].AdvisoryID] = append(ratingsByAdvisory[rows[i].AdvisoryID], rating)
		}
	}

	epssByAdvisory := map[uuid.UUID]store.EPSSScore{}
	if rows, err := s.queries.ListEPSSForAdvisories(ctx, advisoryIDs); err != nil {
		s.log.Warn().Err(err).Msg("failed to attach epss")
	} else if len(rows) > 0 {
		date := ""
		if catalog, catalogErr := s.queries.GetEPSSCatalog(ctx); catalogErr == nil {
			date = catalog.ScoreDate.Format("2006-01-02")
		}
		for _, row := range rows {
			score, errScore := strconv.ParseFloat(row.Score, 64)
			percentile, errPercentile := strconv.ParseFloat(row.Percentile, 64)
			if errScore == nil && errPercentile == nil {
				epssByAdvisory[row.AdvisoryID] = store.EPSSScore{CVEID: row.CveID, Score: score, Percentile: percentile, Date: date}
			}
		}
	}

	for i := range vulnerabilities {
		finding := &vulnerabilities[i]
		if finding.AdvisoryID == nil || !isAdvisoryBackedFindingType(finding.Type) {
			continue
		}
		if epss, ok := epssByAdvisory[*finding.AdvisoryID]; ok {
			copied := epss
			finding.EPSS = &copied
		}
		ratings := ratingsByAdvisory[*finding.AdvisoryID]
		finding.RatingsDisagree = advisory.Disagree(ratings)
		if allRatings || finding.RatingsDisagree {
			finding.Ratings = findingRatings(ratings, finding)
		}
	}
}

// findingRatings renders ratings for the API, marking the one the finding's
// severity comes from.
func findingRatings(ratings []advisory.Rating, finding *store.Vulnerability) []store.FindingRating {
	out := make([]store.FindingRating, 0, len(ratings))
	usedVersion := ""
	if finding.CVSS != nil {
		usedVersion = finding.CVSS.Version
	}
	for _, rating := range ratings {
		severity, _ := rating.Severity()
		item := store.FindingRating{
			Rater:    rating.Rater,
			Provider: rating.Provider,
			Vector:   rating.Vector,
			Score:    rating.Score,
			Severity: string(severity),
		}
		if rating.Version != nil {
			item.Version = string(*rating.Version)
		}
		if rating.Label != nil {
			item.Label = string(*rating.Label)
		}
		item.Used = finding.RatedBy != "" && rating.Rater == finding.RatedBy && item.Version == usedVersion
		out = append(out, item)
	}
	return out
}

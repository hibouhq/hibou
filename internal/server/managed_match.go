package server

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisorydb"
	"github.com/hibouhq/hibou/internal/packagepolicy"
	"github.com/hibouhq/hibou/internal/provider/depsdev"
	"github.com/hibouhq/hibou/internal/remediation"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// managedMatch uses stored advisories/signals only. Cache misses must not
// trigger public package-policy lookups in mirror-only installations.
func (s *Server) managedMatch(repo *store.Repository) remediation.MatchPackages {
	return func(ctx context.Context, purls []string) ([]remediation.AdvisoryMatch, error) {
		if s.advisoryScanner == nil || s.packagePolicy == nil {
			return nil, remediation.ErrAdvisoryEvidence
		}
		org, err := s.queries.GetOrganizationByID(ctx, repo.OrgID)
		if err != nil || org == nil {
			return nil, remediation.ErrAdvisoryEvidence
		}
		cfg, resolved, err := s.loadBoundRepoConfig(ctx, repo)
		if err != nil || !resolved {
			return nil, errors.New("bound repository policy unavailable")
		}
		policy := s.policyFor(org, cfg)
		freshFor := s.cfg.DepsDev.Interval
		if freshFor <= 0 {
			freshFor = 24 * time.Hour
		}
		evaluator := packagepolicy.New(s.queries, packagepolicy.Options{
			FreshFor: freshFor, InstanceNamespaces: s.cfg.DepsDev.PrivateNamespaces,
		})
		decisions, err := evaluator.Evaluate(ctx, packagepolicy.Request{OrgID: org.ID, RepoID: &repo.ID, Purls: purls, Policy: policy})
		if err != nil {
			return nil, err
		}
		byPurl := make(map[string]packagepolicy.Decision, len(decisions))
		for _, decision := range decisions {
			byPurl[decision.Purl] = decision
		}
		matches, err := s.advisoryScanner.MatchPurls(ctx, purls)
		if err != nil {
			return nil, err
		}
		var ids []uuid.UUID
		for _, match := range matches {
			for _, advisory := range match.Advisories {
				ids = append(ids, advisory.AdvisoryID)
			}
		}
		ranges := map[uuid.UUID][]advisorydb.Range{}
		if len(ids) > 0 {
			rows, err := s.queries.ListAffectedRangesByAdvisoryIDs(ctx, ids)
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				ranges[row.AdvisoryID] = append(ranges[row.AdvisoryID], exportedAffectedRange(row))
			}
		}
		signals, err := s.queries.GetPackageSignalsByPurls(ctx, purls)
		if err != nil {
			return nil, err
		}
		namespaces := append(append([]string(nil), s.cfg.DepsDev.PrivateNamespaces...), policy.PrivateNamespaces...)
		result := make([]remediation.AdvisoryMatch, 0, len(matches))
		for _, match := range matches {
			private := depsdev.IsPrivate(match.Purl, namespaces)
			decision, exists := byPurl[match.Purl]
			if !exists {
				return nil, remediation.ErrAdvisoryEvidence
			}
			entry := remediation.AdvisoryMatch{
				Purl: match.Purl, Supported: match.Supported, PrivateNamespace: &private,
				Reason: decision.Reason, Advisories: []remediation.MatchedAdvisory{},
			}
			if row, ok := signals[match.Purl]; ok && time.Since(row.FetchedAt) >= 0 && time.Since(row.FetchedAt) <= freshFor {
				if decision.Evaluated {
					entry.Decision = decision.Decision
				}
				entry.Signals = &remediation.MatchSignals{RecommendedVersion: row.RecommendedVersion, FetchedAt: row.FetchedAt}
			}
			for _, advisory := range match.Advisories {
				vex, err := s.queries.GetEffectiveVEXStatus(ctx, dbgen.GetEffectiveVEXStatusParams{
					OrgID: org.ID, RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true},
					AdvisoryID: advisory.AdvisoryID, ComponentPurl: sql.NullString{String: match.Purl, Valid: true},
				})
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
				entry.Advisories = append(entry.Advisories, remediation.MatchedAdvisory{
					CanonicalID: advisory.CanonicalID, VEXStatus: string(vex.Status), Ranges: ranges[advisory.AdvisoryID],
				})
			}
			result = append(result, entry)
		}
		return result, nil
	}
}

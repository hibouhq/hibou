package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// findingDetailResponse aggregates everything the detail drawer needs in one
// round trip: the finding, its advisory, the triage decision, VEX statements,
// and where the fingerprint is currently detected.
type findingDetailResponse struct {
	Finding     *store.Vulnerability      `json:"finding"`
	Advisory    *findingAdvisoryResponse  `json:"advisory,omitempty"`
	Acceptance  *store.FindingAcceptance  `json:"acceptance,omitempty"`
	VEX         []findingVEXResponse      `json:"vex,omitempty"`
	Occurrences []store.FindingOccurrence `json:"occurrences"`
}

type findingAdvisoryResponse struct {
	CanonicalID string   `json:"canonical_id"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	CVSSScore   string   `json:"cvss_score,omitempty"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	// The three fields a dependency finding is actually triaged on: what to
	// upgrade to, where to read the details, and which other identifier the
	// same advisory travels under. Same enrichment the components view uses.
	FixedVersions []string `json:"fixed_versions,omitempty"`
	References    []string `json:"references,omitempty"`
	Aliases       []string `json:"aliases,omitempty"`
}

type findingVEXResponse struct {
	Status        string `json:"status"`
	Justification string `json:"justification,omitempty"`
	Source        string `json:"source"`
	Statement     string `json:"statement,omitempty"`
}

// @Summary      Finding detail
// @Description  One aggregated view of a finding by fingerprint: latest occurrence, advisory data, triage decision, VEX statements, and the refs currently detecting it.
// @Tags         vulnerabilities
// @Produce      json
// @Param        provider     path  string  true  "Forge provider"
// @Param        slug         path  string  true  "Organization slug"
// @Param        repoSlug     path  string  true  "Repository slug"
// @Param        fingerprint  path  string  true  "Finding fingerprint"
// @Success      200  {object}  api.Response{data=server.findingDetailResponse}
// @Failure      401  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/findings/{fingerprint} [get]
func (s *Server) handleGetFindingDetail(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	fingerprint := pathFingerprint(r)
	if fingerprint == "" {
		api.JSONError(w, http.StatusBadRequest, "fingerprint is required")
		return
	}

	finding, err := s.queries.GetLatestVulnerabilityByFingerprint(r.Context(), repo.ID, fingerprint)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding")
		return
	}
	if finding == nil {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return
	}

	response := findingDetailResponse{Finding: finding, Occurrences: []store.FindingOccurrence{}}
	if fixes, err := s.queries.ListFixingPullRequests(r.Context(), repo.ID, []string{fingerprint}); err == nil {
		finding.FixedInPRs = fixes
	}

	if acceptance, err := s.queries.GetActiveFindingAcceptance(r.Context(), repo.ID, fingerprint); err == nil && acceptance != nil {
		response.Acceptance = acceptance
	}

	if occurrences, err := s.queries.ListFindingOccurrences(r.Context(), repo.ID, fingerprint); err == nil {
		response.Occurrences = occurrences
	}

	if finding.AdvisoryID != nil {
		if advisory, err := s.queries.GetAdvisoryByID(r.Context(), *finding.AdvisoryID); err == nil && advisory.ID == *finding.AdvisoryID {
			response.Advisory = s.advisoryDetail(r.Context(), advisory)
			if statements, err := s.queries.ListVEXStatementsByAdvisory(r.Context(), dbgen.ListVEXStatementsByAdvisoryParams{
				OrgID:      org.ID,
				AdvisoryID: *finding.AdvisoryID,
			}); err == nil {
				for _, statement := range statements {
					entry := findingVEXResponse{
						Status: string(statement.Status),
						Source: string(statement.Source),
					}
					if statement.Justification.Valid {
						entry.Justification = string(statement.Justification.VexJustification)
					}
					if statement.ImpactStatement != "" {
						entry.Statement = statement.ImpactStatement
					} else if statement.ActionStatement != "" {
						entry.Statement = statement.ActionStatement
					}
					response.VEX = append(response.VEX, entry)
				}
			}
		}
	}

	api.JSON(w, http.StatusOK, response)
}

// pathFingerprint reads the fingerprint out of the URL. chi hands back the raw
// path segment, so a client that correctly percent-encodes the value (it must:
// dependency fingerprints are `advisory:component` pairs, and a fingerprint is
// free to contain a slash) would otherwise look up a literal "a%3Ab" and get a
// 404. Undecodable input falls back to the raw segment rather than erroring —
// it simply will not match anything.
func pathFingerprint(r *http.Request) string {
	raw := chi.URLParam(r, "fingerprint")
	if decoded, err := url.PathUnescape(raw); err == nil {
		raw = decoded
	}
	return strings.TrimSpace(raw)
}

func (s *Server) advisoryDetail(ctx context.Context, advisory dbgen.Advisory) *findingAdvisoryResponse {
	detail := &findingAdvisoryResponse{
		CanonicalID: advisory.CanonicalID,
		Title:       advisory.Title,
		Description: advisory.Description,
		Severity:    string(advisory.Severity),
		CVSSVector:  advisory.CvssVector,
		CWEs:        advisory.CweIds,
	}
	if advisory.CvssScore.Valid {
		detail.CVSSScore = advisory.CvssScore.String
	}

	// Fixed versions and references come from the same enrichment the
	// components view builds, so the drawer and the component modal never
	// disagree on "upgrade to X". Best-effort: a failure here costs detail,
	// not the response.
	advisoryIDs := []uuid.UUID{advisory.ID}
	if enrichmentByID, err := s.loadAdvisoryEnrichment(ctx, advisoryIDs, map[uuid.UUID]dbgen.Advisory{advisory.ID: advisory}); err == nil {
		enrichment := enrichmentByID[advisory.ID]
		detail.FixedVersions = enrichment.FixedVersions
		detail.References = enrichment.References
	}
	if aliases, err := s.queries.ListAliasesByAdvisoryIDs(ctx, advisoryIDs); err == nil {
		for _, alias := range aliases {
			if value := strings.TrimSpace(alias.Alias); value != "" && value != advisory.CanonicalID {
				detail.Aliases = append(detail.Aliases, value)
			}
		}
	}
	return detail
}

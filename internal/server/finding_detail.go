package server

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
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
	Finding  *store.Vulnerability     `json:"finding"`
	Advisory *findingAdvisoryResponse `json:"advisory,omitempty"`
	// KEV sits on the detail, not on the advisory: the gate also blocks
	// findings that have no advisory row (matched on the bare identifier), and
	// the exploited badge must appear on exactly the findings the gate blocks.
	KEV        *findingKEVResponse      `json:"kev,omitempty"`
	Acceptance *store.FindingAcceptance `json:"acceptance,omitempty"`
	// Dispute is the human-axis override of an in-source suppression
	// (ADR-026): present when someone contested the scanner's suppression.
	Dispute     *store.FindingDispute     `json:"dispute,omitempty"`
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
	IsMalware   bool     `json:"is_malware,omitempty"`
	MalwareType string   `json:"malware_type,omitempty"`
	// The three fields a dependency finding is actually triaged on: what to
	// upgrade to, where to read the details, and which other identifier the
	// same advisory travels under. Same enrichment the components view uses.
	FixedVersions []string `json:"fixed_versions,omitempty"`
	References    []string `json:"references,omitempty"`
	Aliases       []string `json:"aliases,omitempty"`
	// When the advisory became public, on UPSTREAM's clock. The finding's own
	// first_seen_at is ours, and the two beside each other invite the wrong
	// reading — the gap between them is how long the flaw was public before
	// this instance matched it.
	PublishedAt string `json:"published_at,omitempty"`
}

// findingKEVResponse says the finding's vulnerability is on an
// exploited-vulnerabilities catalog — evidence of active exploitation, which
// is what the gate blocks on unconditionally. Its presence is the flag.
type findingKEVResponse struct {
	// Sources names the catalogs that list it ("cisa", "euvd"), deduplicated —
	// two aliases on one catalog are still one source.
	Sources []string `json:"sources"`
	// Entries retain each catalog record's publisher identifier so clients can
	// link to the exact source record rather than only the source homepage.
	Entries []findingKEVEntryResponse `json:"entries"`
	// DateAdded is when the first-listed catalog recorded it; DueDate is
	// CISA's remediation deadline for US federal agencies (CISA rows only),
	// carried as an urgency signal.
	DateAdded string `json:"date_added,omitempty"`
	DueDate   string `json:"due_date,omitempty"`
	// RansomwareUse is true when CISA marks the entry as used in ransomware
	// campaigns (CISA rows only).
	RansomwareUse bool `json:"ransomware_use,omitempty"`
}

type findingKEVEntryResponse struct {
	Source     string `json:"source"`
	Identifier string `json:"identifier"`
	CVEID      string `json:"cve_id"`
}

var euvdIdentifierPattern = regexp.MustCompile(`^EUVD-\d{4}-\d+$`)

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

	if dispute, err := s.queries.GetFindingDispute(r.Context(), repo.ID, fingerprint); err == nil && dispute != nil {
		response.Dispute = dispute
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

	response.KEV = s.findingKEV(r.Context(), finding, response.Advisory)

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
		IsMalware:   advisory.IsMalware,
	}
	if advisory.CvssScore.Valid {
		detail.CVSSScore = advisory.CvssScore.String
	}
	if advisory.MalwareType.Valid {
		detail.MalwareType = string(advisory.MalwareType.MalwareType)
	}
	if advisory.PublishedAt.Valid {
		detail.PublishedAt = advisory.PublishedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
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
		detail.Aliases = enrichment.Aliases
	}
	return detail
}

// findingKEV resolves the exploited-catalog listing for a finding, matching
// exactly the set the gate blocks (ADR-032): through the advisory's
// identifiers when one is loaded, else the bare primary identifier — the gate
// blocks identifier-matched findings too, and a badge that depends on
// enrichment the block never needed would mark the wrong set. Best-effort: a
// failed lookup costs the badge, not the response.
func (s *Server) findingKEV(ctx context.Context, finding *store.Vulnerability, advisory *findingAdvisoryResponse) *findingKEVResponse {
	identifiers := make([]string, 0, 4)
	switch {
	case advisory != nil:
		identifiers = append(identifiers, strings.ToUpper(advisory.CanonicalID))
		for _, alias := range advisory.Aliases {
			identifiers = append(identifiers, strings.ToUpper(alias))
		}
	case isAdvisoryBackedFindingType(finding.Type):
		if id := strings.ToUpper(strings.TrimSpace(finding.PrimaryIdentifierValue)); id != "" {
			identifiers = append(identifiers, id)
		}
	}
	entries, err := s.queries.ListKEVEntriesForIdentifiers(ctx, identifiers)
	if err != nil || len(entries) == 0 {
		return nil
	}
	response := &findingKEVResponse{
		Sources: make([]string, 0, 2),
		Entries: make([]findingKEVEntryResponse, 0, len(entries)),
	}
	// Deduplicated: two CVE aliases on one catalog are still one source.
	seen := map[string]struct{}{}
	for _, entry := range entries {
		if _, dup := seen[entry.Source]; !dup {
			seen[entry.Source] = struct{}{}
			response.Sources = append(response.Sources, entry.Source)
		}
		identifier, ok := kevEntryIdentifier(entry)
		if !ok {
			continue
		}
		response.Entries = append(response.Entries, findingKEVEntryResponse{
			Source:     entry.Source,
			Identifier: identifier,
			CVEID:      entry.CveID,
		})
	}
	// The rows come 'cisa' first; its entry carries the richest facts
	// (due date, ransomware use), so the scalar fields read from it.
	first := entries[0]
	response.RansomwareUse = first.KnownRansomwareCampaignUse
	if first.DateAdded.Valid {
		response.DateAdded = first.DateAdded.Time.UTC().Format("2006-01-02")
	}
	if first.DueDate.Valid {
		response.DueDate = first.DueDate.Time.UTC().Format("2006-01-02")
	}
	return response
}

func kevEntryIdentifier(entry dbgen.KevEntry) (string, bool) {
	if entry.Source != "euvd" {
		return entry.CveID, true
	}
	identifier := strings.ToUpper(strings.TrimSpace(entry.VulnerabilityName))
	return identifier, euvdIdentifierPattern.MatchString(identifier)
}

// isAdvisoryBackedFindingType mirrors the gate's KEV scope (internal/delta's
// isAdvisoryBackedFinding): the finding types an advisory can stand behind.
func isAdvisoryBackedFindingType(findingType string) bool {
	trimmed := strings.TrimSpace(findingType)
	return strings.EqualFold(trimmed, "dependency") ||
		strings.EqualFold(trimmed, "malware") ||
		strings.EqualFold(trimmed, "container")
}

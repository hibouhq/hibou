package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/packagepolicy"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/shipped"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Stateless advisory matching (ADR-046 §2): `hibou deps scan` sends purls
// and versions, never file contents, and gets back the organisation's
// advisory sources, KEV, EPSS and malicious-package data and, for a
// repository, its triage decisions, VEX statements, not-shipped lists and
// package signals, read-only. Nothing is stored beyond an audit entry.

const advisoryMatchMaxPurls = 5000

type advisoryMatchRequest struct {
	Purls []string `json:"purls"`
	// Repo scopes VEX, the not-shipped lists and the package policy;
	// Release names the context for the audit entry.
	Repo    string `json:"repo,omitempty"`
	Release string `json:"release,omitempty"`
}

type matchedAdvisoryResponse struct {
	ID            uuid.UUID  `json:"id"`
	CanonicalID   string     `json:"canonical_id"`
	Title         string     `json:"title,omitempty"`
	Severity      string     `json:"severity"`
	CVSS          *float64   `json:"cvss,omitempty"`
	RatedBy       string     `json:"rated_by,omitempty"`
	IsMalware     bool       `json:"is_malware,omitempty"`
	MalwareType   string     `json:"malware_type,omitempty"`
	FixedVersions []string   `json:"fixed_versions,omitempty"`
	PublishedAt   *time.Time `json:"published_at,omitempty"`
	KEV           bool       `json:"kev,omitempty"`
	EPSS          *float64   `json:"epss,omitempty"`
	// VEXStatus is the repository's effective VEX verdict for the pair:
	// not_affected, affected, fixed, under_investigation, or empty.
	VEXStatus string `json:"vex_status,omitempty"`
}

type purlMatchResponse struct {
	Purl      string `json:"purl"`
	Supported bool   `json:"supported"`
	// Shipped and ShippedReason apply the repository's not-shipped lists
	// to the purl alone (no module or SBOM evidence is known locally).
	Shipped       bool                      `json:"shipped"`
	ShippedReason string                    `json:"shipped_reason,omitempty"`
	Signals       *componentSignalsResponse `json:"signals,omitempty"`
	// Decision is the package policy's verdict (allow, hold, deny) with
	// its reason, when the policy evaluator is configured.
	Decision   string                    `json:"decision,omitempty"`
	Reason     string                    `json:"reason,omitempty"`
	Advisories []matchedAdvisoryResponse `json:"advisories"`
}

type advisoryMatchResponse struct {
	Matches []purlMatchResponse `json:"matches"`
	Summary struct {
		Purls      int `json:"purls"`
		Vulnerable int `json:"vulnerable"`
		Malware    int `json:"malware"`
		KEV        int `json:"kev"`
		Holds      int `json:"holds"`
	} `json:"summary"`
}

// @Summary      Match package versions against advisories
// @Description  Stateless: receives purls and versions only and returns the organization's advisory view (ADR-046 §2). With a repository, applies its VEX statements, not-shipped lists and package policy, read-only. Persists nothing beyond an audit entry.
// @Tags         advisories
// @Accept       json
// @Produce      json
// @Param        provider  path      string                true  "Forge provider"
// @Param        slug      path      string                true  "Organization slug"
// @Param        payload   body      advisoryMatchRequest  true  "Purls to match"
// @Success      200       {object}  api.Response{data=advisoryMatchResponse}
// @Router       /orgs/{provider}/{slug}/advisories/match [post]
func (s *Server) handleMatchAdvisories(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapVulnerabilities, apitoken.AccessRead, org.Slug) {
		return
	}
	var req advisoryMatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Purls) == 0 || len(req.Purls) > advisoryMatchMaxPurls {
		api.JSONError(w, http.StatusBadRequest, "purls: between 1 and 5000 entries")
		return
	}
	if s.advisoryScanner == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "advisory matching is not configured")
		return
	}
	var repo *store.Repository
	var cfg *repoconfig.RepoConfig
	if slug := strings.TrimSpace(req.Repo); slug != "" {
		loaded, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, slug)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
			return
		}
		if loaded == nil {
			api.JSONError(w, http.StatusNotFound, "repository not found")
			return
		}
		repo = loaded
		if loadedCfg, _, err := s.loadBoundRepoConfig(r.Context(), repo); err == nil {
			cfg = loadedCfg
		}
	}

	matches, err := s.advisoryScanner.MatchPurls(r.Context(), req.Purls)
	if err != nil {
		s.log.Error().Err(err).Str("org_id", org.ID.String()).Msg("advisory match failed")
		api.JSONError(w, http.StatusInternalServerError, "failed to match advisories")
		return
	}

	// KEV and EPSS for every matched advisory, in one lookup each.
	advisoryIDs := make([]uuid.UUID, 0)
	seenAdvisory := make(map[uuid.UUID]bool)
	for _, match := range matches {
		for _, advisory := range match.Advisories {
			if !seenAdvisory[advisory.AdvisoryID] {
				seenAdvisory[advisory.AdvisoryID] = true
				advisoryIDs = append(advisoryIDs, advisory.AdvisoryID)
			}
		}
	}
	kev := make(map[uuid.UUID]bool)
	epss := make(map[uuid.UUID]float64)
	if len(advisoryIDs) > 0 {
		if listed, err := s.queries.FilterKEVAdvisoryIDs(r.Context(), advisoryIDs); err == nil {
			for _, id := range listed {
				kev[id] = true
			}
		}
		if rows, err := s.queries.ListEPSSForAdvisories(r.Context(), advisoryIDs); err == nil {
			for _, row := range rows {
				if score, parseErr := strconv.ParseFloat(row.Score, 64); parseErr == nil {
					epss[row.AdvisoryID] = score
				}
			}
		}
	}

	// Shipping lists and the package policy, repository-scoped when given.
	shipping := s.buildShippingPolicy(r.Context(), org, repo, cfg, nil)
	decisions := make(map[string]packagepolicy.Decision)
	if s.packagePolicy != nil {
		var repoID *uuid.UUID
		if repo != nil {
			repoID = &repo.ID
		}
		if evaluated, err := s.packagePolicy.Evaluate(r.Context(), packagepolicy.Request{OrgID: org.ID, RepoID: repoID, Purls: req.Purls, Policy: s.policyFor(org, cfg)}); err == nil {
			for _, decision := range evaluated {
				decisions[decision.Purl] = decision
			}
		} else {
			s.log.Warn().Err(err).Msg("package policy for advisory match")
		}
	}
	signals := s.packageSignalsFor(r.Context(), req.Purls)
	now := time.Now()

	response := advisoryMatchResponse{Matches: make([]purlMatchResponse, 0, len(matches))}
	response.Summary.Purls = len(matches)
	for _, match := range matches {
		entry := purlMatchResponse{Purl: match.Purl, Supported: match.Supported, Advisories: []matchedAdvisoryResponse{}}
		decision := shipping.policy.Decide(shipped.Candidate{Purl: match.Purl, Ecosystem: match.Ecosystem})
		entry.Shipped, entry.ShippedReason = decision.Shipped, decision.Reason
		if row, ok := signals[match.Purl]; ok {
			entry.Signals = componentSignalsFromRow(row, now)
		}
		if policyDecision, ok := decisions[match.Purl]; ok && policyDecision.Evaluated {
			entry.Decision, entry.Reason = policyDecision.Decision, policyDecision.Reason
			if policyDecision.Decision == packagepolicy.DecisionHold {
				response.Summary.Holds++
			}
		}
		for _, advisory := range match.Advisories {
			matched := matchedAdvisoryResponse{
				ID:            advisory.AdvisoryID,
				CanonicalID:   advisory.CanonicalID,
				Title:         advisory.Title,
				Severity:      advisory.Severity,
				CVSS:          advisory.CVSSScore,
				RatedBy:       advisory.RatedBy,
				IsMalware:     advisory.IsMalware,
				MalwareType:   advisory.MalwareType,
				FixedVersions: advisory.FixedVersions,
				PublishedAt:   advisory.PublishedAt,
				KEV:           kev[advisory.AdvisoryID],
			}
			if score, ok := epss[advisory.AdvisoryID]; ok {
				matched.EPSS = &score
			}
			if repo != nil {
				params := dbgen.GetEffectiveVEXStatusParams{OrgID: org.ID, AdvisoryID: advisory.AdvisoryID, RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true}}
				params.ComponentPurl.String, params.ComponentPurl.Valid = match.Purl, true
				if statement, err := s.queries.GetEffectiveVEXStatus(r.Context(), params); err == nil && statement.Status != "" {
					matched.VEXStatus = string(statement.Status)
				}
			}
			entry.Advisories = append(entry.Advisories, matched)
			if matched.IsMalware {
				response.Summary.Malware++
			}
			if matched.KEV {
				response.Summary.KEV++
			}
		}
		if len(entry.Advisories) > 0 {
			response.Summary.Vulnerable++
		}
		response.Matches = append(response.Matches, entry)
	}

	// Who asked, when, how many: the only trace the request leaves.
	context := map[string]any{"purls": len(req.Purls), "vulnerable": response.Summary.Vulnerable}
	if repo != nil {
		context["repo"] = repo.Slug
	}
	if release := strings.TrimSpace(req.Release); release != "" {
		context["release"] = release
	}
	s.writeAuditLog(r, UserFromContext(r.Context()), orgAuditID(org.ID), auditEntry{Action: audit.ActionAdvisoryMatch, ResourceType: "organization", ResourceID: org.ID.String(), Context: context})
	api.JSON(w, http.StatusOK, response)
}

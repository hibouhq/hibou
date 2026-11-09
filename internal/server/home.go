package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Home (ADR-053 §9): a person-centred dashboard across the user's
// organisations. Each tile is one query; the page holds no logic of its own.

type homeOrg struct {
	ID          uuid.UUID `json:"id"`
	Provider    string    `json:"provider"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	OpenCount   int       `json:"open_incidents"`
}

type homeApproval struct {
	Type        string    `json:"type"` // decision | delivery | waiver | merge
	OrgSlug     string    `json:"org_slug"`
	OrgProvider string    `json:"org_provider"`
	Number      int32     `json:"incident_number"`
	Title       string    `json:"incident_title"`
	Detail      string    `json:"detail"`
	ID          uuid.UUID `json:"id"`
}

// homeRepo is one of the person's repositories: the ones they open most,
// then, while they have opened few, the ones analysed most recently.
type homeRepo struct {
	ID          uuid.UUID  `json:"id"`
	OrgSlug     string     `json:"org_slug"`
	OrgProvider string     `json:"org_provider"`
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	Visited     bool       `json:"visited"`
	LastVisited *time.Time `json:"last_visited_at,omitempty"`
}

// homeRepoLimit is how many repositories Home lists.
const homeRepoLimit = 8

type homeResponse struct {
	Orgs       []homeOrg                            `json:"orgs"`
	Repos      []homeRepo                           `json:"repos"`
	NeedsYou   []dbgen.ListPendingActionsForUserRow `json:"needs_you"`
	Approvals  []homeApproval                       `json:"approvals"`
	Incidents  []dbgen.ListOpenIncidentsForOrgsRow  `json:"incidents"`
	NoisyRules []dbgen.ListNoisyIncidentRulesRow    `json:"noisy_rules"`
	Exposure   homeExposure                         `json:"exposure"`
	Recent     homeRecent                           `json:"recent"`
}

type homeExposure struct {
	Clients         []dbgen.ListExposedClientsForOrgsRow  `json:"clients"`
	UnknownReleases []dbgen.ListUnknownReleasesForOrgsRow `json:"unknown_releases"`
}

type homeRecent struct {
	Since            time.Time `json:"since"`
	FailedGates      int32     `json:"failed_gates"`
	CatalogueSignals int32     `json:"catalogue_signals"`
	SecretsFound     int32     `json:"secrets_found"`
	MalwareFound     int32     `json:"malware_found"`
}

// @Summary      Home dashboard
// @Description  Actions waiting for the user, approvals, open incidents, exposure and recent activity across the user's organisations (ADR-053 §9).
// @Tags         home
// @Produce      json
// @Param        since  query  string  false  "RFC 3339 instant of the previous visit (default: 7 days ago)"
// @Success      200  {object}  api.Response{data=server.homeResponse}
// @Security     BearerAuth
// @Router       /me/home [get]
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	ctx := r.Context()
	orgs, _, err := s.queries.ListOrganizationsByUser(ctx, user.ID, 200, 0)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list organizations")
		return
	}
	since := time.Now().UTC().Add(-7 * 24 * time.Hour)
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil && parsed.Before(time.Now()) {
			since = parsed.UTC()
		}
	}
	out := homeResponse{Orgs: []homeOrg{}, Repos: []homeRepo{}, NeedsYou: []dbgen.ListPendingActionsForUserRow{}, Approvals: []homeApproval{}, Incidents: []dbgen.ListOpenIncidentsForOrgsRow{}, NoisyRules: []dbgen.ListNoisyIncidentRulesRow{}, Recent: homeRecent{Since: since}}
	allIDs := []uuid.UUID{}
	managed := []uuid.UUID{}
	access := map[uuid.UUID]repoAccess{}
	for _, org := range orgs {
		role, _ := s.queries.GetOrgMemberRole(ctx, org.ID, user.ID)
		out.Orgs = append(out.Orgs, homeOrg{ID: org.ID, Provider: org.Provider, Slug: org.Slug, Name: org.Name, DisplayName: org.DisplayName, Role: role})
		allIDs = append(allIDs, org.ID)
		if role == "admin" || role == "release_manager" {
			managed = append(managed, org.ID)
		}
		if granted, err := s.principalRepoAccess(r, org.ID, role); err == nil {
			access[org.ID] = granted
		}
	}
	if len(allIDs) == 0 {
		api.JSON(w, http.StatusOK, out)
		return
	}
	db := s.queries.Incidents()
	out.Repos = s.homeRepos(r, user.ID, allIDs, access)
	if rows, err := db.ListPendingActionsForUser(ctx, dbgen.ListPendingActionsForUserParams{OrgIds: allIDs, UserID: uuid.NullUUID{UUID: user.ID, Valid: true}, RowLimit: 50}); err == nil {
		out.NeedsYou = rows
	}
	if rows, err := db.ListOpenIncidentsForOrgs(ctx, dbgen.ListOpenIncidentsForOrgsParams{OrgIds: allIDs, RowLimit: 100}); err == nil {
		out.Incidents = rows
		counts := map[uuid.UUID]int{}
		for _, row := range rows {
			counts[row.OrgID]++
		}
		for i := range out.Orgs {
			out.Orgs[i].OpenCount = counts[out.Orgs[i].ID]
		}
	}
	if len(managed) > 0 {
		if rows, err := db.ListProposedDecisionsForOrgs(ctx, managed); err == nil {
			for _, row := range rows {
				var proposal incidentDecision
				_ = json.Unmarshal(row.ProposedDecision, &proposal)
				if proposal.ProposedBy == user.ID.String() {
					continue
				}
				out.Approvals = append(out.Approvals, homeApproval{Type: "decision", OrgSlug: row.OrgSlug, OrgProvider: row.OrgProvider, Number: row.Number, Title: row.Title, Detail: proposal.State + ": " + proposal.Reason, ID: row.ID})
			}
		}
		if rows, err := db.ListDeliveriesAwaitingApprovalForOrgs(ctx, managed); err == nil {
			for _, row := range rows {
				if row.CreatedBy.Valid && row.CreatedBy.UUID == user.ID {
					continue
				}
				out.Approvals = append(out.Approvals, homeApproval{Type: "delivery", OrgSlug: row.OrgSlug, OrgProvider: row.OrgProvider, Number: row.Number, Title: row.Title, Detail: "notice to " + row.ClientName.String + " by " + row.Channel, ID: row.ID})
			}
		}
		if rows, err := db.ListWaiversAwaitingApprovalForOrgs(ctx, managed); err == nil {
			for _, row := range rows {
				var proposal struct {
					ProposedBy string `json:"waiver_proposed_by"`
					Reason     string `json:"waiver_reason"`
				}
				_ = json.Unmarshal(row.Evidence, &proposal)
				if proposal.ProposedBy == user.ID.String() {
					continue
				}
				out.Approvals = append(out.Approvals, homeApproval{Type: "waiver", OrgSlug: row.OrgSlug, OrgProvider: row.OrgProvider, Number: row.Number, Title: row.Title, Detail: row.Label + ": " + proposal.Reason, ID: row.ID})
			}
		}
		if rows, err := db.ListProposedMergesForOrgs(ctx, managed); err == nil {
			for _, row := range rows {
				var proposal mergeProposal
				_ = json.Unmarshal(row.ProposedMerge, &proposal)
				if proposal.ProposedBy == user.ID.String() {
					continue
				}
				out.Approvals = append(out.Approvals, homeApproval{Type: "merge", OrgSlug: row.OrgSlug, OrgProvider: row.OrgProvider, Number: row.Number, Title: row.Title, Detail: fmt.Sprintf("merge into #%d: %s", proposal.IntoNumber, proposal.Reason), ID: row.ID})
			}
		}
		if rows, err := db.ListNoisyIncidentRules(ctx, dbgen.ListNoisyIncidentRulesParams{OrgIds: managed, Threshold: 5}); err == nil {
			out.NoisyRules = rows
		}
	}
	if rows, err := db.ListExposedClientsForOrgs(ctx, allIDs); err == nil {
		out.Exposure.Clients = rows
	}
	if out.Exposure.Clients == nil {
		out.Exposure.Clients = []dbgen.ListExposedClientsForOrgsRow{}
	}
	if rows, err := db.ListUnknownReleasesForOrgs(ctx, allIDs); err == nil {
		out.Exposure.UnknownReleases = rows
	}
	if out.Exposure.UnknownReleases == nil {
		out.Exposure.UnknownReleases = []dbgen.ListUnknownReleasesForOrgsRow{}
	}
	if count, err := db.CountFailedGatesForOrgs(ctx, dbgen.CountFailedGatesForOrgsParams{OrgIds: allIDs, Since: since}); err == nil {
		out.Recent.FailedGates = count
	}
	if count, err := db.CountCatalogueSignalsForOrgs(ctx, dbgen.CountCatalogueSignalsForOrgsParams{OrgIds: allIDs, Since: since}); err == nil {
		out.Recent.CatalogueSignals = count
	}
	if rows, err := db.CountNewFindingsByTypeForOrgs(ctx, dbgen.CountNewFindingsByTypeForOrgsParams{OrgIds: allIDs, Since: since}); err == nil {
		for _, row := range rows {
			switch row.Type {
			case "secret":
				out.Recent.SecretsFound = row.Found
			case "malware":
				out.Recent.MalwareFound = row.Found
			}
		}
	}
	api.JSON(w, http.StatusOK, out)
}

// homeRepos lists the person's top repositories, then fills with the
// recently analysed ones, keeping only those the person may open.
func (s *Server) homeRepos(r *http.Request, userID uuid.UUID, orgIDs []uuid.UUID, access map[uuid.UUID]repoAccess) []homeRepo {
	ctx := r.Context()
	db := s.queries.Incidents()
	out := []homeRepo{}
	seen := map[uuid.UUID]bool{}
	allowed := func(orgID, repoID uuid.UUID) bool {
		granted, ok := access[orgID]
		return ok && granted.allows(repoID) && !seen[repoID]
	}
	// Fetch more than shown: some may be filtered out by access.
	if rows, err := db.ListTopVisitedRepos(ctx, dbgen.ListTopVisitedReposParams{UserID: userID, OrgIds: orgIDs, RowLimit: homeRepoLimit * 2}); err == nil {
		for _, row := range rows {
			if len(out) == homeRepoLimit || !allowed(row.OrgID, row.ID) {
				continue
			}
			seen[row.ID] = true
			visited := row.LastVisitedAt
			out = append(out, homeRepo{ID: row.ID, OrgSlug: row.OrgSlug, OrgProvider: row.OrgProvider, Slug: row.Slug, Name: row.Name, Visited: true, LastVisited: &visited})
		}
	}
	if len(out) < homeRepoLimit {
		if rows, err := db.ListRecentlyAnalysedRepos(ctx, dbgen.ListRecentlyAnalysedReposParams{OrgIds: orgIDs, RowLimit: homeRepoLimit * 4}); err == nil {
			for _, row := range rows {
				if len(out) == homeRepoLimit || !allowed(row.OrgID, row.ID) {
					continue
				}
				seen[row.ID] = true
				out = append(out, homeRepo{ID: row.ID, OrgSlug: row.OrgSlug, OrgProvider: row.OrgProvider, Slug: row.Slug, Name: row.Name})
			}
		}
	}
	return out
}

// recordRepoVisit notes that a person opened a repository in the UI. API
// tokens (CLI, IDE, CI) are not visits. Best-effort: it never fails the page.
func (s *Server) recordRepoVisit(r *http.Request, repoID uuid.UUID) {
	user := UserFromContext(r.Context())
	if user == nil || auth.TokenAuthFromContext(r.Context()) != nil || s.queries == nil {
		return
	}
	if err := s.queries.Incidents().RecordRepoVisit(r.Context(), dbgen.RecordRepoVisitParams{UserID: user.ID, RepoID: repoID}); err != nil {
		s.log.Debug().Err(err).Str("repo_id", repoID.String()).Msg("repo visit not recorded")
	}
}

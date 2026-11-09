package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Incident API (ADR-053 §11) under /orgs/{provider}/{slug}/incidents. Reading
// is for organisation members; every mutation needs admin or release manager
// and is audited.

type incidentSummary struct {
	dbgen.Incident
	RepoSlug  string `json:"repo_slug,omitempty"`
	RepoName  string `json:"repo_name,omitempty"`
	KindLabel string `json:"kind_label"`
}

type incidentScopeResponse struct {
	dbgen.IncidentScope
	Clients []incidentClientRef `json:"clients"`
}

type incidentClientRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Slug string    `json:"slug"`
}

type incidentDetailResponse struct {
	Incident       incidentSummary                     `json:"incident"`
	DecisionStates []string                            `json:"decision_states"`
	DecisionSteps  []string                            `json:"decision_steps,omitempty"`
	Scope          []incidentScopeResponse             `json:"scope"`
	Actions        []dbgen.IncidentAction              `json:"actions"`
	Deadlines      []dbgen.IncidentDeadline            `json:"deadlines"`
	Deliveries     []dbgen.ListIncidentDeliveriesRow   `json:"deliveries"`
	Events         []dbgen.IncidentEvent               `json:"events"`
	TrackerLinks   []dbgen.ListIncidentTrackerLinksRow `json:"tracker_links"`
	Regimes        []incident.Regime                   `json:"regimes"`
	Settings       incidentSettingsFlags               `json:"settings"`
	CanManage      bool                                `json:"can_manage"`
	Advisory       *incidentAdvisoryRef                `json:"advisory,omitempty"`
}

type incidentAdvisoryRef struct {
	ID          uuid.UUID `json:"id"`
	CanonicalID string    `json:"canonical_id"`
	Aliases     []string  `json:"aliases"`
	Title       string    `json:"title"`
	FirstParty  bool      `json:"first_party"`
	// Public: carries a public identifier, so the component's maintainer is
	// deemed aware of it (guidance §223) and no upstream notice is owed.
	Public bool `json:"public"`
}

type incidentSettingsFlags struct {
	FourEyes               bool `json:"four_eyes"`
	RequireVEXApproval     bool `json:"require_vex_approval"`
	RequireNoticeApproval  bool `json:"require_notice_approval"`
	RequireAcknowledgement bool `json:"require_acknowledgement"`
}

func (s *Server) writeIncidentError(w http.ResponseWriter, err error) {
	var input incidentInputError
	switch {
	case errors.As(err, &input):
		api.JSONError(w, http.StatusBadRequest, input.msg)
	case errors.Is(err, errIncidentConflict):
		api.JSONError(w, http.StatusConflict, "the incident's state does not allow this")
	case errors.Is(err, sql.ErrNoRows):
		api.JSONError(w, http.StatusNotFound, "not found")
	default:
		s.log.Error().Err(err).Msg("incident request failed")
		api.JSONError(w, http.StatusInternalServerError, "incident request failed")
	}
}

func (s *Server) canManageIncidents(r *http.Request, orgID uuid.UUID) bool {
	role, err := s.principalOrgRole(r, orgID)
	return err == nil && (role == "admin" || role == "release_manager")
}

// loadIncidentForRequest resolves /incidents/{number} inside the org.
func (s *Server) loadIncidentForRequest(w http.ResponseWriter, r *http.Request, mutate bool) (*store.Organization, dbgen.Incident, bool) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return nil, dbgen.Incident{}, false
	}
	if mutate && !s.requireReleaseManager(r, w, org.ID) {
		return nil, dbgen.Incident{}, false
	}
	number, err := strconv.ParseInt(chi.URLParam(r, "number"), 10, 32)
	if err != nil || number < 1 {
		api.JSONError(w, http.StatusBadRequest, "invalid incident number")
		return nil, dbgen.Incident{}, false
	}
	inc, err := s.queries.Incidents().GetIncidentByNumber(r.Context(), dbgen.GetIncidentByNumberParams{OrgID: org.ID, Number: int32(number)})
	if errors.Is(err, sql.ErrNoRows) {
		api.JSONError(w, http.StatusNotFound, "incident not found")
		return nil, inc, false
	}
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load incident")
		return nil, inc, false
	}
	if inc.RepoID.Valid {
		repo, err := s.queries.GetRepositoryByID(r.Context(), inc.RepoID.UUID)
		if err != nil || repo == nil {
			api.JSONError(w, http.StatusNotFound, "incident not found")
			return nil, inc, false
		}
	}
	return org, inc, true
}

func decodeIncidentBody(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(into); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// @Summary      List incidents
// @Tags         incidents
// @Produce      json
// @Param        provider  path   string  true   "Forge provider"
// @Param        slug      path   string  true   "Organization slug"
// @Param        state     query  string  false  "open, closed, or a state"
// @Param        kind      query  string  false  "Incident kind"
// @Param        priority  query  string  false  "P1, P2 or P3"
// @Param        repo      query  string  false  "Repository slug"
// @Success      200  {object}  api.ListResponse{data=[]server.incidentSummary}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/incidents [get]
func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	pagination := api.ParsePagination(r)
	query := r.URL.Query()
	params := dbgen.ListIncidentsByOrgParams{OrgID: org.ID, RowLimit: int32(pagination.PerPage), RowOffset: int32(pagination.Offset)} // #nosec G115 -- bounded pagination
	if value := strings.TrimSpace(query.Get("state")); value != "" {
		params.StateFilter = sql.NullString{String: value, Valid: true}
	}
	if value := strings.TrimSpace(query.Get("kind")); value != "" {
		params.KindFilter = sql.NullString{String: value, Valid: true}
	}
	if value := strings.TrimSpace(query.Get("priority")); value != "" {
		params.PriorityFilter = sql.NullString{String: value, Valid: true}
	}
	if value := strings.TrimSpace(query.Get("repo")); value != "" {
		repo, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, value)
		if err != nil || repo == nil {
			api.JSONList(w, []incidentSummary{}, pagination.Page, pagination.PerPage, 0)
			return
		}
		params.RepoFilter = uuid.NullUUID{UUID: repo.ID, Valid: true}
	}
	rows, err := s.queries.Incidents().ListIncidentsByOrg(r.Context(), params)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list incidents")
		return
	}
	total, err := s.queries.Incidents().CountIncidentsByOrg(r.Context(), dbgen.CountIncidentsByOrgParams{
		OrgID: org.ID, StateFilter: params.StateFilter, KindFilter: params.KindFilter, RepoFilter: params.RepoFilter, PriorityFilter: params.PriorityFilter,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to count incidents")
		return
	}
	out := make([]incidentSummary, 0, len(rows))
	for _, row := range rows {
		out = append(out, incidentSummary{Incident: incidentFromListRow(row), RepoSlug: row.RepoSlug.String, RepoName: row.RepoName.String, KindLabel: incident.KindLabel(row.Kind)})
	}
	api.JSONList(w, out, pagination.Page, pagination.PerPage, int(total))
}

func incidentFromListRow(row dbgen.ListIncidentsByOrgRow) dbgen.Incident {
	return dbgen.Incident{
		ID: row.ID, OrgID: row.OrgID, Number: row.Number, RepoID: row.RepoID, Kind: row.Kind, Regimes: row.Regimes,
		SubjectType: row.SubjectType, SubjectID: row.SubjectID, Title: row.Title, State: row.State, Priority: row.Priority,
		SignalSource: row.SignalSource, TriggerRule: row.TriggerRule, SignalAt: row.SignalAt, AwareAt: row.AwareAt,
		DecisionReason: row.DecisionReason, DecisionStep: row.DecisionStep, DecidedBy: row.DecidedBy, DecidedAt: row.DecidedAt,
		DecidedState: row.DecidedState, ProposedDecision: row.ProposedDecision, ProposedMerge: row.ProposedMerge, FixAvailableAt: row.FixAvailableAt,
		OwnerID: row.OwnerID, OwnerTeamID: row.OwnerTeamID, DueAt: row.DueAt, TargetSeconds: row.TargetSeconds,
		MergedInto: row.MergedInto, ClosedAt: row.ClosedAt, CreatedBy: row.CreatedBy, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

type openIncidentRequest struct {
	Kind         string   `json:"kind"`
	RepoSlug     string   `json:"repo_slug,omitempty"`
	Title        string   `json:"title"`
	Priority     string   `json:"priority,omitempty"`
	SignalSource string   `json:"signal_source"`
	Regimes      []string `json:"regimes,omitempty"`
	// VulnerabilityID names the advisory of an exploited vulnerability
	// (canonical id or alias); FindingID the finding of the other kinds.
	VulnerabilityID string `json:"vulnerability_id,omitempty"`
	FindingID       string `json:"finding_id,omitempty"`
	Note            string `json:"note,omitempty"`
	// Scope for a severe incident: releases and clients, by id.
	ReleaseIDs []string `json:"release_ids,omitempty"`
	ClientIDs  []string `json:"client_ids,omitempty"`
}

// @Summary      Open an incident
// @Description  A person opens an incident of any kind from any signal (ADR-053 §1): a customer report, a CSIRT, a researcher, internal evidence.
// @Tags         incidents
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        payload   body  server.openIncidentRequest  true  "Incident"
// @Success      201  {object}  api.Response{data=dbgen.Incident}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/incidents [post]
func (s *Server) handleOpenIncident(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok || !s.requireReleaseManager(r, w, org.ID) {
		return
	}
	var input openIncidentRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	user := UserFromContext(r.Context())
	actor := incidentActorFor(r, user)
	in, err := s.buildManualIncident(r, org, input, actor)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	created, isNew, err := s.openIncident(r.Context(), in)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	if !isNew {
		api.JSONError(w, http.StatusConflict, fmt.Sprintf("incident #%d already covers this subject", created.Number))
		return
	}
	if note := strings.TrimSpace(input.Note); note != "" {
		_ = s.addIncidentNote(r.Context(), created, actor, note)
	}
	api.JSON(w, http.StatusCreated, created)
}

func (s *Server) buildManualIncident(r *http.Request, org *store.Organization, input openIncidentRequest, actor incidentActor) (incidentOpenInput, error) {
	ctx := r.Context()
	in := incidentOpenInput{
		OrgID: org.ID, Kind: strings.TrimSpace(input.Kind), Title: strings.TrimSpace(input.Title), Priority: input.Priority,
		SignalSource: strings.TrimSpace(input.SignalSource), Regimes: input.Regimes, Actor: actor,
	}
	if !repoconfig.IncidentKindKnown(in.Kind) {
		return in, errIncidentInput("kind must be one of %s", strings.Join(incident.Kinds, ", "))
	}
	if in.SignalSource == "" {
		in.SignalSource = "internal"
	}
	if !incident.SignalSourceKnown(in.SignalSource) {
		return in, errIncidentInput("signal_source must be one of %s", strings.Join(incident.SignalSources, ", "))
	}
	settings, err := s.loadIncidentSettings(ctx, org.ID)
	if err != nil {
		return in, err
	}
	for _, regime := range in.Regimes {
		if _, ok := incident.ResolveRegime(regime, in.Kind, settings.National); !ok {
			return in, errIncidentInput("unknown regime %q", regime)
		}
	}
	var repo *store.Repository
	if slug := strings.TrimSpace(input.RepoSlug); slug != "" {
		repo, err = s.queries.GetRepositoryBySlug(ctx, org.ID, slug)
		if err != nil || repo == nil {
			return in, errIncidentInput("repository %q not found", slug)
		}
		in.RepoID = uuid.NullUUID{UUID: repo.ID, Valid: true}
	}
	switch in.Kind {
	case incident.KindExploitedVulnerability:
		if repo == nil {
			return in, errIncidentInput("an exploited vulnerability names the product's repository")
		}
		advisory, err := s.resolveVEXAdvisory(ctx, input.VulnerabilityID)
		if err != nil {
			return in, errIncidentInput("vulnerability %q not found; record a first-party advisory first if it is in your own code", input.VulnerabilityID)
		}
		in.SubjectType, in.SubjectID = incident.SubjectAdvisory, advisory.ID.String()
		if in.Title == "" {
			in.Title = fmt.Sprintf("Exploited %s in %s", advisory.CanonicalID, repo.Name)
		}
		if len(in.Regimes) == 0 {
			in.Regimes = []string{incident.RegimeCRA}
		}
	case incident.KindSecretLeak, incident.KindMalware, incident.KindPolicyBreach:
		if repo == nil {
			return in, errIncidentInput("this kind names the repository of its finding")
		}
		findingID, err := uuid.Parse(strings.TrimSpace(input.FindingID))
		if err != nil {
			return in, errIncidentInput("finding_id is required for this kind")
		}
		finding, err := s.queries.GetVulnerabilityByID(ctx, findingID)
		if err != nil || finding == nil || !s.vulnerabilityBelongsToRepo(r, repo, finding) {
			return in, errIncidentInput("finding not found in this repository")
		}
		if !incident.KindFits(in.Kind, finding.Type) {
			return in, errIncidentInput("a %s finding cannot carry a %s incident", finding.Type, in.Kind)
		}
		in.SubjectType, in.SubjectID = incident.SubjectFinding, finding.Fingerprint
		if in.Title == "" {
			in.Title = incidentTitle(in.Kind, *finding, repo)
		}
	case incident.KindSevereIncident:
		if in.Title == "" {
			return in, errIncidentInput("a security incident needs a title")
		}
		in.SubjectType = incident.SubjectNone
		if len(in.Regimes) == 0 {
			in.Regimes = []string{incident.RegimeCRA}
		}
		for _, raw := range input.ReleaseIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return in, errIncidentInput("invalid release id %q", raw)
			}
			release, err := s.queries.GetReleaseByID(ctx, id)
			if err != nil || release == nil || repo == nil || release.RepoID != repo.ID {
				return in, errIncidentInput("release %s not found in the repository", raw)
			}
			in.Scope = append(in.Scope, incident.ScopeRow{SubjectType: incident.ScopeRelease, SubjectID: id.String(), Label: release.Version, Status: incident.ScopeAffected, Reason: "named when the incident was opened", Manual: true})
		}
		for _, raw := range input.ClientIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return in, errIncidentInput("invalid client id %q", raw)
			}
			client, err := s.queries.Incidents().GetClientRow(ctx, id)
			if err != nil || client.OrgID != org.ID {
				return in, errIncidentInput("client %s not found", raw)
			}
			in.Scope = append(in.Scope, incident.ScopeRow{SubjectType: incident.ScopeClient, SubjectID: id.String(), Label: client.Name, Status: incident.ScopeAffected, Reason: "named when the incident was opened", Manual: true})
		}
	}
	return in, nil
}

// @Summary      Get an incident
// @Tags         incidents
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        number    path  int     true  "Incident number"
// @Success      200  {object}  api.Response{data=server.incidentDetailResponse}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/incidents/{number} [get]
func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	org, inc, ok := s.loadIncidentForRequest(w, r, false)
	if !ok {
		return
	}
	detail, err := s.incidentDetail(r, org, inc)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	api.JSON(w, http.StatusOK, detail)
}

func (s *Server) incidentDetail(r *http.Request, org *store.Organization, inc dbgen.Incident) (incidentDetailResponse, error) {
	ctx := r.Context()
	db := s.queries.Incidents()
	out := incidentDetailResponse{Incident: incidentSummary{Incident: inc, KindLabel: incident.KindLabel(inc.Kind)}, CanManage: s.canManageIncidents(r, org.ID)}
	positive, negative := incident.DecisionStates(inc.Regimes)
	out.DecisionStates = []string{positive, negative}
	if inc.Kind == incident.KindExploitedVulnerability {
		out.DecisionSteps = incident.DecisionSteps
	}
	var releaseClients map[string][]uuid.UUID
	if inc.RepoID.Valid {
		if repo, err := s.queries.GetRepositoryByID(ctx, inc.RepoID.UUID); err == nil && repo != nil {
			out.Incident.RepoSlug, out.Incident.RepoName = repo.Slug, repo.Name
		}
		releases, err := db.ListReleasesWithClientsByRepo(ctx, inc.RepoID.UUID)
		if err != nil {
			return out, err
		}
		releaseClients = map[string][]uuid.UUID{}
		for _, release := range releases {
			releaseClients[release.ID.String()] = release.ClientIds
		}
	}
	scope, err := db.ListIncidentScope(ctx, inc.ID)
	if err != nil {
		return out, err
	}
	clientIDs := map[uuid.UUID]bool{}
	for _, ids := range releaseClients {
		for _, id := range ids {
			clientIDs[id] = true
		}
	}
	clientRefs := map[uuid.UUID]incidentClientRef{}
	if len(clientIDs) > 0 {
		ids := make([]uuid.UUID, 0, len(clientIDs))
		for id := range clientIDs {
			ids = append(ids, id)
		}
		clients, err := db.ListClientsByIDs(ctx, ids)
		if err != nil {
			return out, err
		}
		for _, client := range clients {
			clientRefs[client.ID] = incidentClientRef{ID: client.ID, Name: client.Name, Slug: client.Slug}
		}
	}
	for _, row := range scope {
		entry := incidentScopeResponse{IncidentScope: row, Clients: []incidentClientRef{}}
		if row.SubjectType == incident.ScopeRelease {
			for _, id := range releaseClients[row.SubjectID] {
				if ref, ok := clientRefs[id]; ok {
					entry.Clients = append(entry.Clients, ref)
				}
			}
		}
		out.Scope = append(out.Scope, entry)
	}
	if out.Actions, err = db.ListIncidentActions(ctx, inc.ID); err != nil {
		return out, err
	}
	if out.Deadlines, err = db.ListIncidentDeadlines(ctx, inc.ID); err != nil {
		return out, err
	}
	if out.Deliveries, err = db.ListIncidentDeliveries(ctx, inc.ID); err != nil {
		return out, err
	}
	if out.Events, err = db.ListIncidentEvents(ctx, inc.ID); err != nil {
		return out, err
	}
	if out.TrackerLinks, err = db.ListIncidentTrackerLinks(ctx, inc.ID); err != nil {
		return out, err
	}
	settings, err := s.loadIncidentSettings(ctx, inc.OrgID)
	if err != nil {
		return out, err
	}
	out.Settings = incidentSettingsFlags{FourEyes: settings.Row.FourEyes, RequireVEXApproval: settings.Row.RequireVexApproval, RequireNoticeApproval: settings.Row.RequireNoticeApproval, RequireAcknowledgement: settings.Row.RequireAcknowledgement}
	for _, name := range inc.Regimes {
		if regime, ok := incident.ResolveRegime(name, inc.Kind, settings.National); ok {
			// The internal regime has no regulatory steps: an empty list, not
			// null, which the page reads as a list.
			if regime.Steps == nil {
				regime.Steps = []incident.StepSpec{}
			}
			out.Regimes = append(out.Regimes, regime)
		}
	}
	if inc.SubjectType == incident.SubjectAdvisory {
		if advisoryID, err := uuid.Parse(inc.SubjectID); err == nil {
			if advisories, err := s.queries.GetAdvisoriesByIDs(ctx, []uuid.UUID{advisoryID}); err == nil && len(advisories) == 1 {
				ref := &incidentAdvisoryRef{ID: advisoryID, CanonicalID: advisories[0].CanonicalID, Title: advisories[0].Title, Aliases: s.advisoryAliases(ctx, advisoryID), Public: s.advisoryIsPublic(ctx, advisoryID)}
				if inc.RepoID.Valid {
					_, fpErr := db.GetFirstPartyAdvisory(ctx, dbgen.GetFirstPartyAdvisoryParams{RepoID: inc.RepoID.UUID, AdvisoryID: advisoryID})
					ref.FirstParty = fpErr == nil
				}
				if ref.Aliases == nil {
					ref.Aliases = []string{}
				}
				out.Advisory = ref
			}
		}
	}
	if out.Scope == nil {
		out.Scope = []incidentScopeResponse{}
	}
	return out, nil
}

type updateIncidentRequest struct {
	Title       *string    `json:"title,omitempty"`
	Priority    *string    `json:"priority,omitempty"`
	OwnerID     *uuid.UUID `json:"owner_id,omitempty"`
	OwnerTeamID *uuid.UUID `json:"owner_team_id,omitempty"`
	ClearOwner  bool       `json:"clear_owner,omitempty"`
	Regimes     []string   `json:"regimes,omitempty"`
	// ExternalRef: the incident's ticket or link; empty string clears it.
	ExternalRef *string `json:"external_ref,omitempty"`
}

func (s *Server) handleUpdateIncident(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	var input updateIncidentRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	var ownerID, ownerTeamID *uuid.NullUUID
	if input.ClearOwner {
		ownerID, ownerTeamID = &uuid.NullUUID{}, &uuid.NullUUID{}
	}
	if input.OwnerID != nil {
		ownerID, ownerTeamID = &uuid.NullUUID{UUID: *input.OwnerID, Valid: true}, &uuid.NullUUID{}
	}
	if input.OwnerTeamID != nil {
		ownerID, ownerTeamID = &uuid.NullUUID{}, &uuid.NullUUID{UUID: *input.OwnerTeamID, Valid: true}
	}
	updated, err := s.updateIncidentFields(r.Context(), inc, incidentActorFor(r, UserFromContext(r.Context())), incidentFieldUpdate{Title: input.Title, Priority: input.Priority, OwnerID: ownerID, OwnerTeamID: ownerTeamID, Regimes: input.Regimes, ExternalRef: input.ExternalRef})
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Decide an incident
// @Description  The decision step (ADR-053 §2): reportable or not (or confirmed / dismissed), with its reason, T0, and the ladder step for an exploited vulnerability. Under four-eyes a decision that ends obligations is only proposed.
// @Tags         incidents
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        number    path  int     true  "Incident number"
// @Param        payload   body  server.incidentDecision  true  "Decision"
// @Success      200  {object}  api.Response{data=dbgen.Incident}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/incidents/{number}/decide [post]
func (s *Server) handleDecideIncident(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	var input incidentDecision
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	input.ProposedBy, input.ProposedAt = "", nil
	updated, proposed, err := s.decideIncident(r.Context(), inc, incidentActorFor(r, UserFromContext(r.Context())), input)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	status := http.StatusOK
	if proposed {
		status = http.StatusAccepted
	}
	api.JSON(w, status, updated)
}

func (s *Server) handleApproveIncidentDecision(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	updated, err := s.approveIncidentDecision(r.Context(), inc, incidentActorFor(r, UserFromContext(r.Context())))
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	api.JSON(w, http.StatusOK, updated)
}

type reasonRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleWithdrawIncident(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	var input reasonRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	updated, err := s.withdrawIncident(r.Context(), inc, incidentActorFor(r, UserFromContext(r.Context())), input.Reason)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	api.JSON(w, http.StatusOK, updated)
}

type mergeIncidentRequest struct {
	Into   int32  `json:"into"`
	Reason string `json:"reason"`
}

func (s *Server) handleMergeIncident(w http.ResponseWriter, r *http.Request) {
	org, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	var input mergeIncidentRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	survivor, err := s.queries.Incidents().GetIncidentByNumber(r.Context(), dbgen.GetIncidentByNumberParams{OrgID: org.ID, Number: input.Into})
	if err != nil {
		api.JSONError(w, http.StatusNotFound, "target incident not found")
		return
	}
	proposed, err := s.proposeOrMergeIncidents(r.Context(), survivor, inc, incidentActorFor(r, UserFromContext(r.Context())), input.Reason)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	if proposed {
		// Four-eyes: another person applies it.
		api.JSON(w, http.StatusAccepted, map[string]any{"proposed": true, "merged_into": survivor.Number})
		return
	}
	api.JSON(w, http.StatusOK, map[string]any{"proposed": false, "merged_into": survivor.Number})
}

type fixAvailableRequest struct {
	At   *time.Time `json:"at,omitempty"`
	Note string     `json:"note,omitempty"`
}

func (s *Server) handleIncidentFixAvailable(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	var input fixAvailableRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	at := time.Time{}
	if input.At != nil {
		at = *input.At
	}
	updated, err := s.setIncidentFixAvailable(r.Context(), inc, incidentActorFor(r, UserFromContext(r.Context())), at, input.Note)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	api.JSON(w, http.StatusOK, updated)
}

func (s *Server) handleReconcileIncident(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	updated, err := s.reconcileIncident(r.Context(), inc.ID)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	s.mergeAliasSiblings(r.Context(), updated)
	api.JSON(w, http.StatusOK, updated)
}

type noteRequest struct {
	Text string `json:"text"`
}

func (s *Server) handleIncidentNote(w http.ResponseWriter, r *http.Request) {
	// Any writing role may add a note: notes change no obligation, and
	// loadAuthorizedOrg already refuses read-only roles on a POST.
	_, inc, ok := s.loadIncidentForRequest(w, r, false)
	if !ok {
		return
	}
	var input noteRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	if err := s.addIncidentNote(r.Context(), inc, incidentActorFor(r, UserFromContext(r.Context())), input.Text); err != nil {
		s.writeIncidentError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type actionRequest struct {
	Note      string     `json:"note,omitempty"`
	Reference string     `json:"reference,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	FiledAt   *time.Time `json:"filed_at,omitempty"`
	Assignee  *uuid.UUID `json:"assignee_id,omitempty"`
	Approve   bool       `json:"approve,omitempty"`
}

func (s *Server) handleIncidentActionOp(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	actionID, err := uuid.Parse(chi.URLParam(r, "actionID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	var input actionRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	actor := incidentActorFor(r, UserFromContext(r.Context()))
	var (
		result   any
		proposed bool
	)
	switch chi.URLParam(r, "op") {
	case "complete":
		result, err = s.completeIncidentAction(r.Context(), inc, actor, actionID, input.Note, input.Reference)
	case "file":
		filedAt := time.Time{}
		if input.FiledAt != nil {
			filedAt = *input.FiledAt
		}
		result, err = s.recordIncidentFiling(r.Context(), inc, actor, actionID, input.Reference, filedAt)
	case "waive":
		result, proposed, err = s.waiveIncidentAction(r.Context(), inc, actor, actionID, input.Reason, input.Approve)
	case "reopen":
		result, err = s.reopenIncidentAction(r.Context(), inc, actor, actionID, input.Reason)
	case "assign":
		assignee := uuid.NullUUID{}
		if input.Assignee != nil {
			assignee = uuid.NullUUID{UUID: *input.Assignee, Valid: true}
		}
		result, err = s.assignIncidentAction(r.Context(), inc, actor, actionID, assignee)
	default:
		api.JSONError(w, http.StatusNotFound, "unknown action operation")
		return
	}
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	status := http.StatusOK
	if proposed {
		status = http.StatusAccepted
	}
	api.JSON(w, status, result)
}

type scopeRequest struct {
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	Label       string `json:"label,omitempty"`
	Status      string `json:"status,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Clear       bool   `json:"clear,omitempty"`
}

func (s *Server) handleIncidentScope(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	var input scopeRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	if err := s.setIncidentScopeDecision(r.Context(), inc, incidentActorFor(r, UserFromContext(r.Context())), input.SubjectType, input.SubjectID, input.Label, input.Status, input.Reason, input.Clear); err != nil {
		s.writeIncidentError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type incidentStatementRequest struct {
	ReleaseID       string `json:"release_id,omitempty"`
	VersionRange    string `json:"version_range,omitempty"`
	ComponentPURL   string `json:"component_purl,omitempty"`
	Status          string `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	Evidence        string `json:"evidence,omitempty"`
}

// handleIncidentStatement records a VEX statement for the incident's advisory
// from the scope table: the statement, not the scope row, is the record.
func (s *Server) handleIncidentStatement(w http.ResponseWriter, r *http.Request) {
	org, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	if inc.SubjectType != incident.SubjectAdvisory || !inc.RepoID.Valid {
		api.JSONError(w, http.StatusBadRequest, "statements are recorded on incidents about an advisory")
		return
	}
	advisoryID, err := uuid.Parse(inc.SubjectID)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "incident subject is not an advisory")
		return
	}
	var input incidentStatementRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	user := UserFromContext(r.Context())
	actorID := uuid.Nil
	if user != nil {
		actorID = user.ID
	}
	params, err := buildCreateVEXParams(org.ID, inc.RepoID.UUID, actorID, advisoryID, createVEXStatementRequest{
		Status: input.Status, Justification: input.Justification, ImpactStatement: input.ImpactStatement,
		ActionStatement: input.ActionStatement, ComponentPURL: input.ComponentPURL,
	})
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.applyVEXProductAxis(r.Context(), inc.RepoID.UUID, input.ReleaseID, input.VersionRange, &params); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	evidence, _ := json.Marshal(map[string]any{"incident": inc.Number, "note": strings.TrimSpace(input.Evidence)})
	params.Evidence = evidence
	s.applyVEXApprovalPolicy(r.Context(), org.ID, &params)
	statement, err := s.queries.RecordVEXStatement(r.Context(), params)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusConflict, "another statement was recorded for this scope meanwhile; reload and retry")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to record VEX statement")
		return
	}
	actor := incidentActorFor(r, user)
	s.appendIncidentEvent(r.Context(), s.queries.Incidents(), inc.ID, actor, "statement.recorded", map[string]any{
		"vex_statement_id": statement.ID, "status": statement.Status, "release_id": input.ReleaseID, "version_range": input.VersionRange, "justification": input.Justification,
	})
	s.writeVEXAuditLog(r, user, org.ID, statement.ID, audit.ActionVEXCreate, map[string]any{"repo_id": inc.RepoID.UUID, "incident": inc.Number, "status": statement.Status})
	s.publishGateRecompute(r.Context(), inc.RepoID.UUID)
	_, _ = s.reconcileIncident(r.Context(), inc.ID)
	api.JSON(w, http.StatusCreated, statement)
}

func (s *Server) handleIncidentDeliver(w http.ResponseWriter, r *http.Request) {
	org, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	var input deliverRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	deliveries, err := s.deliverIncidentNotices(r.Context(), inc, org, incidentActorFor(r, UserFromContext(r.Context())), input)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	api.JSON(w, http.StatusCreated, deliveries)
}

type approveDeliveryRequest struct {
	Evidence string `json:"evidence,omitempty"`
}

func (s *Server) handleApproveIncidentDelivery(w http.ResponseWriter, r *http.Request) {
	org, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	deliveryID, err := uuid.Parse(chi.URLParam(r, "deliveryID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid delivery id")
		return
	}
	var input approveDeliveryRequest
	if r.ContentLength > 0 && !decodeIncidentBody(w, r, &input) {
		return
	}
	delivery, err := s.approveIncidentDelivery(r.Context(), inc, org, incidentActorFor(r, UserFromContext(r.Context())), deliveryID, input.Evidence)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	api.JSON(w, http.StatusOK, delivery)
}

// @Summary      Verify a delivery's documents
// @Description  Re-renders every document of a delivery from its recorded inputs and compares with the stored bytes (ADR-053 §5).
// @Tags         incidents
// @Produce      json
// @Param        provider    path  string  true  "Forge provider"
// @Param        slug        path  string  true  "Organization slug"
// @Param        number      path  int     true  "Incident number"
// @Param        deliveryID  path  string  true  "Delivery id"
// @Success      200  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/incidents/{number}/deliveries/{deliveryID}/verify [post]
func (s *Server) handleVerifyIncidentDelivery(w http.ResponseWriter, r *http.Request) {
	org, inc, ok := s.loadIncidentForRequest(w, r, false)
	if !ok {
		return
	}
	deliveryID, err := uuid.Parse(chi.URLParam(r, "deliveryID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid delivery id")
		return
	}
	delivery, err := s.queries.Incidents().GetIncidentDelivery(r.Context(), deliveryID)
	if err != nil || delivery.IncidentID != inc.ID {
		api.JSONError(w, http.StatusNotFound, "delivery not found")
		return
	}
	var refs []documentRef
	_ = json.Unmarshal(delivery.Documents, &refs)
	results := []map[string]any{}
	allMatch := true
	for _, ref := range refs {
		result, err := s.verifyIncidentDocument(r.Context(), org.ID, ref.SHA256)
		if err != nil {
			s.writeIncidentError(w, err)
			return
		}
		if result["stored_matches_digest"] != true || result["rerendered_matches"] == false {
			allMatch = false
		}
		results = append(results, result)
	}
	api.JSON(w, http.StatusOK, map[string]any{"delivery_id": delivery.ID, "documents": results, "verified": allMatch})
}

func (s *Server) handleGetIncidentDocument(w http.ResponseWriter, r *http.Request) {
	org, inc, ok := s.loadIncidentForRequest(w, r, false)
	if !ok {
		return
	}
	sum := strings.ToLower(chi.URLParam(r, "sha256"))
	if !s.incidentReferencesDocument(r, inc.ID, sum) {
		api.JSONError(w, http.StatusNotFound, "document not found")
		return
	}
	row, body, err := s.loadIncidentDocument(r.Context(), org.ID, sum)
	if err != nil {
		api.JSONError(w, http.StatusNotFound, "document not found")
		return
	}
	w.Header().Set("Content-Type", row.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sum[:16]+"-"+row.Kind+"\"")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox")
	_, _ = w.Write(body) // #nosec G705 -- a stored document served as an attachment, nosniff and sandboxed
}

func (s *Server) incidentReferencesDocument(r *http.Request, incidentID uuid.UUID, sum string) bool {
	deliveries, err := s.queries.Incidents().ListIncidentDeliveries(r.Context(), incidentID)
	if err != nil {
		return false
	}
	for _, delivery := range deliveries {
		var refs []documentRef
		_ = json.Unmarshal(delivery.Documents, &refs)
		for _, ref := range refs {
			if ref.SHA256 == sum {
				return true
			}
		}
	}
	return false
}

// handleIncidentFilingDraft pre-fills what a filing on the authority's
// platform asks for (§4): hibou never submits, a person copies and files.
func (s *Server) handleIncidentFilingDraft(w http.ResponseWriter, r *http.Request) {
	org, inc, ok := s.loadIncidentForRequest(w, r, false)
	if !ok {
		return
	}
	draft, err := s.incidentFilingDraft(r, org, inc, strings.TrimSpace(r.URL.Query().Get("step")))
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	api.JSON(w, http.StatusOK, draft)
}

type filingDraft struct {
	Step   string            `json:"step"`
	Fields []filingDraftItem `json:"fields"`
	Text   string            `json:"text"`
}

type filingDraftItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

func (s *Server) incidentFilingDraft(r *http.Request, org *store.Organization, inc dbgen.Incident, step string) (filingDraft, error) {
	detail, err := s.incidentDetail(r, org, inc)
	if err != nil {
		return filingDraft{}, err
	}
	if step == "" {
		step = incident.StepEarlyWarning
	}
	draft := filingDraft{Step: step}
	add := func(label, value string) {
		if strings.TrimSpace(value) != "" {
			draft.Fields = append(draft.Fields, filingDraftItem{Label: label, Value: value})
		}
	}
	product := org.Name
	if detail.Incident.RepoName != "" {
		product = detail.Incident.RepoName
	}
	if inc.RepoID.Valid {
		if repo, err := s.queries.GetRepositoryByID(r.Context(), inc.RepoID.UUID); err == nil && repo != nil {
			id := s.repoProduct(r.Context(), org, repo)
			product = id.Name + " (" + id.PURL + ")"
		}
	}
	add("Manufacturer", firstNonEmptyString(org.DisplayName, org.Name))
	add("Product", product)
	if detail.Advisory != nil {
		add("Vulnerability", strings.TrimSpace(detail.Advisory.CanonicalID+" "+strings.Join(detail.Advisory.Aliases, " ")))
		add("Title", detail.Advisory.Title)
	} else {
		add("Incident", inc.Title)
	}
	if inc.AwareAt.Valid {
		add("Became aware (T0)", inc.AwareAt.Time.UTC().Format(time.RFC3339))
	}
	affected, notAffected := []string{}, []string{}
	countries := map[string]bool{}
	clientIDs := []uuid.UUID{}
	for _, row := range detail.Scope {
		switch row.Status {
		case incident.ScopeAffected, incident.ScopePending, incident.ScopeUnknown, incident.ScopeUnderInvestigation:
			affected = append(affected, row.Label)
			for _, client := range row.Clients {
				clientIDs = append(clientIDs, client.ID)
			}
		case incident.ScopeNotAffected, incident.ScopeFixed:
			notAffected = append(notAffected, row.Label+" ("+row.Status+")")
		}
	}
	if len(clientIDs) > 0 {
		if clients, err := s.queries.Incidents().ListClientsByIDs(r.Context(), clientIDs); err == nil {
			for _, client := range clients {
				var labels map[string]string
				_ = json.Unmarshal(client.Labels, &labels)
				if country := strings.TrimSpace(labels["country"]); country != "" {
					countries[strings.ToUpper(country)] = true
				}
			}
		}
	}
	add("Affected versions", strings.Join(affected, ", "))
	add("Versions not affected or fixed", strings.Join(notAffected, ", "))
	memberStates := "unknown"
	if len(countries) > 0 {
		list := make([]string, 0, len(countries))
		for country := range countries {
			list = append(list, country)
		}
		sort.Strings(list)
		memberStates = strings.Join(list, ", ")
	}
	add("Member States where the product is known to be available", memberStates)
	if inc.DecisionReason.Valid {
		add("Assessment", inc.DecisionReason.String)
	}
	switch step {
	case incident.StepNotification, incident.StepFinalReport:
		measures := []string{}
		for _, action := range detail.Actions {
			if action.State == "done" && (action.Kind == incident.ActionFixRelease || action.Kind == incident.ActionRemediation || action.Kind == incident.ActionVEX) {
				measures = append(measures, action.Label)
			}
		}
		if inc.FixAvailableAt.Valid {
			measures = append(measures, "Corrective measure available since "+inc.FixAvailableAt.Time.UTC().Format(time.RFC3339))
		}
		add("Corrective or mitigating measures", strings.Join(measures, "; "))
	}
	var b strings.Builder
	for _, field := range draft.Fields {
		fmt.Fprintf(&b, "%s: %s\n", field.Label, field.Value)
	}
	draft.Text = b.String()
	return draft, nil
}

// @Summary      Export an incident dossier
// @Description  The incident's timeline, scope, actions, clocks, deliveries and documents in one zip, with a SHA-256 manifest (ADR-053 §5).
// @Tags         incidents
// @Produce      application/zip
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        number    path  int     true  "Incident number"
// @Success      200
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/incidents/{number}/dossier [get]
func (s *Server) handleIncidentDossier(w http.ResponseWriter, r *http.Request) {
	org, inc, ok := s.loadIncidentForRequest(w, r, false)
	if !ok {
		return
	}
	detail, err := s.incidentDetail(r, org, inc)
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	var buf bytes.Buffer
	archive := zip.NewWriter(&buf)
	manifest := map[string]string{}
	add := func(name string, body []byte) error {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.Modified = time.Unix(0, 0).UTC()
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := writer.Write(body); err != nil {
			return err
		}
		digest := sha256.Sum256(body)
		manifest[name] = hex.EncodeToString(digest[:])
		return nil
	}
	incidentJSON, _ := json.MarshalIndent(detail, "", "  ")
	if err := add("incident.json", incidentJSON); err != nil {
		s.writeIncidentError(w, err)
		return
	}
	seen := map[string]bool{}
	for _, delivery := range detail.Deliveries {
		var refs []documentRef
		_ = json.Unmarshal(delivery.Documents, &refs)
		for _, ref := range refs {
			if seen[ref.SHA256] {
				continue
			}
			seen[ref.SHA256] = true
			row, body, err := s.loadIncidentDocument(r.Context(), org.ID, ref.SHA256)
			if err != nil {
				s.writeIncidentError(w, err)
				return
			}
			if err := add("documents/"+ref.SHA256+"-"+ref.Filename, body); err != nil {
				s.writeIncidentError(w, err)
				return
			}
			if err := add("documents/"+ref.SHA256+".inputs.json", row.Inputs); err != nil {
				s.writeIncidentError(w, err)
				return
			}
		}
	}
	readme := fmt.Sprintf(`Incident #%d dossier — %s%s
Exported %s from %s.

incident.json   the incident, its scope, actions, clocks, deliveries and timeline
documents/      every document delivered, under its SHA-256, with the inputs it
                was rendered from (re-render with the hibou renderer named in
                the inputs to check a document)
manifest.json   SHA-256 of every file in this archive

What this proves, and what it does not: the documents are content-addressed,
and each delivery's audit entry records their digests. The archive is not
signed: an instance key would prove integrity after export, not honesty, and
the tamper-evident, externally anchored log (ADR-041 item 6) is not in place
on this instance. The records are as trustworthy as the instance that holds
them.
`, inc.Number, inc.Title, referenceSuffix(inc.ExternalRef), time.Now().UTC().Format(time.RFC3339), firstNonEmptyString(s.cfg.BaseURL, "hibou"))
	if err := add("README.txt", []byte(readme)); err != nil {
		s.writeIncidentError(w, err)
		return
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	header := &zip.FileHeader{Name: "manifest.json", Method: zip.Deflate}
	header.Modified = time.Unix(0, 0).UTC()
	if writer, err := archive.CreateHeader(header); err == nil {
		_, _ = writer.Write(manifestJSON)
	}
	if err := archive.Close(); err != nil {
		s.writeIncidentError(w, err)
		return
	}
	user := UserFromContext(r.Context())
	s.writeSystemAuditLog(r.Context(), incidentActorFor(r, user), org.ID, audit.ActionIncidentDossier, inc.ID.String(), map[string]any{"number": inc.Number, "documents": len(seen)})
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-incident-%d.zip\"", org.Slug, inc.Number))
	_, _ = w.Write(buf.Bytes())
}

// Incident settings (ADR-053 §1, §"Before building").

type incidentSettingsRequest struct {
	OwnerID                *uuid.UUID                 `json:"owner_id"`
	OwnerTeamID            *uuid.UUID                 `json:"owner_team_id"`
	DefaultRules           *[]repoconfig.IncidentRule `json:"default_rules"`
	LockedRules            []repoconfig.IncidentRule  `json:"locked_rules"`
	InternalTargets        incident.InternalTargets   `json:"internal_targets"`
	NationalRegimes        []incident.NationalRegime  `json:"national_regimes"`
	RequireVEXApproval     bool                       `json:"require_vex_approval"`
	RequireNoticeApproval  bool                       `json:"require_notice_approval"`
	RequireAcknowledgement bool                       `json:"require_acknowledgement"`
	FourEyes               bool                       `json:"four_eyes"`
	DueSoonLeadMinutes     int32                      `json:"due_soon_lead_minutes"`
}

type incidentSettingsResponse struct {
	Settings     dbgen.IncidentSetting     `json:"settings"`
	BuiltinRules []repoconfig.IncidentRule `json:"builtin_rules"`
	Kinds        []string                  `json:"kinds"`
	Regimes      []string                  `json:"regimes"`
}

func (s *Server) handleGetIncidentSettings(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	settings, err := s.loadIncidentSettings(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load incident settings")
		return
	}
	regimes := []string{incident.RegimeCRA, incident.RegimeNIS2, incident.RegimeInternal}
	for _, national := range settings.National {
		regimes = append(regimes, "national:"+national.Code)
	}
	api.JSON(w, http.StatusOK, incidentSettingsResponse{Settings: settings.Row, BuiltinRules: incident.BuiltinRules(), Kinds: incident.Kinds, Regimes: regimes})
}

func (s *Server) handlePutIncidentSettings(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok || !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	var input incidentSettingsRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	for index, rule := range input.LockedRules {
		if err := repoconfig.ValidateIncidentRule(rule, index); err != nil {
			api.JSONError(w, http.StatusBadRequest, "locked_rules: "+err.Error())
			return
		}
	}
	defaults := []byte("null")
	if input.DefaultRules != nil {
		for index, rule := range *input.DefaultRules {
			if err := repoconfig.ValidateIncidentRule(rule, index); err != nil {
				api.JSONError(w, http.StatusBadRequest, "default_rules: "+err.Error())
				return
			}
		}
		defaults, _ = json.Marshal(*input.DefaultRules)
	}
	codes := map[string]bool{}
	for _, national := range input.NationalRegimes {
		if !repoconfig.RegimeKnown("national:"+national.Code) || codes[national.Code] {
			api.JSONError(w, http.StatusBadRequest, "national regime codes are unique lowercase identifiers")
			return
		}
		codes[national.Code] = true
		if national.URL != "" && !httpURL(national.URL) {
			api.JSONError(w, http.StatusBadRequest, "a national regime portal is an http(s) URL")
			return
		}
		if len(national.Steps) == 0 {
			api.JSONError(w, http.StatusBadRequest, "a national regime needs at least one step")
			return
		}
		for _, step := range national.Steps {
			if strings.TrimSpace(step.Name) == "" || step.Hours <= 0 || step.Hours > 24*365 {
				api.JSONError(w, http.StatusBadRequest, "a national regime step has a name and a positive number of hours")
				return
			}
		}
	}
	if input.InternalTargets.EarlyWarningHours < 0 || input.InternalTargets.EarlyWarningHours > 24 || input.InternalTargets.NotificationHours < 0 || input.InternalTargets.NotificationHours > 72 {
		api.JSONError(w, http.StatusBadRequest, "internal targets are stricter than the regulation: at most 24 h and 72 h")
		return
	}
	if input.DueSoonLeadMinutes <= 0 {
		input.DueSoonLeadMinutes = 360
	}
	locked, _ := json.Marshal(nonNilRules(input.LockedRules))
	targets, _ := json.Marshal(input.InternalTargets)
	national, _ := json.Marshal(nonNilNational(input.NationalRegimes))
	params := dbgen.UpsertIncidentSettingsParams{
		OrgID: org.ID, DefaultRules: defaults, LockedRules: locked, InternalTargets: targets, NationalRegimes: national,
		RequireVexApproval: input.RequireVEXApproval, RequireNoticeApproval: input.RequireNoticeApproval,
		RequireAcknowledgement: input.RequireAcknowledgement, FourEyes: input.FourEyes, DueSoonLeadMinutes: input.DueSoonLeadMinutes,
	}
	if input.OwnerID != nil {
		params.OwnerID = uuid.NullUUID{UUID: *input.OwnerID, Valid: true}
	}
	if input.OwnerTeamID != nil {
		params.OwnerTeamID = uuid.NullUUID{UUID: *input.OwnerTeamID, Valid: true}
	}
	if user := UserFromContext(r.Context()); user != nil {
		params.UpdatedBy = uuid.NullUUID{UUID: user.ID, Valid: true}
	}
	row, err := s.queries.Incidents().UpsertIncidentSettings(r.Context(), params)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to save incident settings")
		return
	}
	s.auditOrgConfig(r, org.ID, audit.ActionIncidentSettings, "incident_settings", org.ID.String(), map[string]any{
		"four_eyes": input.FourEyes, "require_vex_approval": input.RequireVEXApproval, "require_notice_approval": input.RequireNoticeApproval,
		"require_acknowledgement": input.RequireAcknowledgement, "locked_rules": len(input.LockedRules), "default_rules_set": input.DefaultRules != nil,
	})
	api.JSON(w, http.StatusOK, row)
}

func nonNilRules(rules []repoconfig.IncidentRule) []repoconfig.IncidentRule {
	if rules == nil {
		return []repoconfig.IncidentRule{}
	}
	return rules
}

func nonNilNational(regimes []incident.NationalRegime) []incident.NationalRegime {
	if regimes == nil {
		return []incident.NationalRegime{}
	}
	return regimes
}

// handleGetRepoIncidentRules shows the rules a repository runs, with where
// each came from (ADR-053 §1).
func (s *Server) handleGetRepoIncidentRules(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	rules, err := s.effectiveIncidentRules(r.Context(), repo.OrgID, repo.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve incident rules")
		return
	}
	cfg := s.loadPersistedRepoConfig(r.Context(), repo.ID)
	out := map[string]any{"rules": rules, "product": s.repoProduct(r.Context(), org, repo)}
	if cfg.Incidents != nil {
		out["owner"] = cfg.Incidents.Owner
	}
	api.JSON(w, http.StatusOK, out)
}

// handleListRepoIncidents lists one repository's incidents.
func (s *Server) handleListRepoIncidents(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	rows, err := s.queries.Incidents().ListIncidentsByRepo(r.Context(), dbgen.ListIncidentsByRepoParams{RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true}, Limit: 200})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list incidents")
		return
	}
	out := make([]incidentSummary, 0, len(rows))
	for _, row := range rows {
		out = append(out, incidentSummary{Incident: row, RepoSlug: repo.Slug, RepoName: repo.Name, KindLabel: incident.KindLabel(row.Kind)})
	}
	api.JSON(w, http.StatusOK, out)
}

// handleFindingIncident answers "is there an incident on this finding" for the
// finding detail (§11).
func (s *Server) handleFindingIncident(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapTriage, apitoken.AccessRead, org.Slug, repo.Slug) {
		return
	}
	vulnID, err := uuid.Parse(chi.URLParam(r, "vulnID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid vulnerability id")
		return
	}
	finding, err := s.queries.GetVulnerabilityByID(r.Context(), vulnID)
	if err != nil || finding == nil || !s.vulnerabilityBelongsToRepo(r, repo, finding) {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return
	}
	rows, err := s.queries.Incidents().ListIncidentsByRepo(r.Context(), dbgen.ListIncidentsByRepoParams{RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true}, Limit: 500})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list incidents")
		return
	}
	advisoryID := uuidString(finding.AdvisoryID)
	subjects := []dbgen.Incident{}
	for _, row := range rows {
		if (row.SubjectType == incident.SubjectFinding && row.SubjectID == finding.Fingerprint) ||
			(advisoryID != "" && row.SubjectType == incident.SubjectAdvisory && row.SubjectID == advisoryID) {
			subjects = append(subjects, row)
		}
	}
	api.JSON(w, http.StatusOK, subjects)
}

func uuidString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// referenceSuffix renders the incident's external reference for the dossier
// title line.
func referenceSuffix(ref string) string {
	if ref == "" {
		return ""
	}
	return " (" + ref + ")"
}

// httpURL reports whether raw is an absolute http(s) URL a browser can open.
func httpURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || len(raw) > 2048 {
		return false
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

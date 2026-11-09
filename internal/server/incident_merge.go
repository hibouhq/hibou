package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Merging (ADR-053 §3) folds a duplicate incident into another one: its
// timeline, deliveries and completed actions move to the survivor, which is
// then recomputed from its own subject. It cannot be undone, so a merge is
// limited to incidents about the same thing, chosen from a list rather than
// typed, and under the four-eyes setting proposed by one person and applied
// by another.

// mergeProposal is incidents.proposed_merge, on the incident to absorb.
type mergeProposal struct {
	IntoID     string    `json:"into_id"`
	IntoNumber int32     `json:"into_number"`
	Reason     string    `json:"reason"`
	ProposedBy string    `json:"proposed_by"`
	ProposedAt time.Time `json:"proposed_at"`
}

// advisoryCVEs returns an advisory's identifiers and, among them, its CVEs.
func (s *Server) advisoryCVEs(ctx context.Context, advisoryID uuid.UUID) (ids, cves []string, err error) {
	ids, err = s.queries.Incidents().ListAdvisoryIdentifiers(ctx, advisoryID)
	if err != nil {
		return nil, nil, err
	}
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-") {
			cves = append(cves, id)
		}
	}
	slices.Sort(ids)
	slices.Sort(cves)
	return ids, cves, nil
}

// sameVulnerability reports whether two advisories name one vulnerability:
// they share an identifier, and when both list CVEs the lists are the same.
// An identifier belongs to one advisory only, so the record that came second
// often lists no CVE (its CVE is the first record's alias); that still
// merges. An advisory grouping several CVEs (a Go or distribution advisory)
// shares an identifier with each of them but is none of them on its own: two
// different CVE lists never merge.
func (s *Server) sameVulnerability(ctx context.Context, a, b uuid.UUID) (bool, string, error) {
	idsA, cvesA, err := s.advisoryCVEs(ctx, a)
	if err != nil {
		return false, "", err
	}
	idsB, cvesB, err := s.advisoryCVEs(ctx, b)
	if err != nil {
		return false, "", err
	}
	shared := false
	for _, id := range idsA {
		shared = shared || slices.Contains(idsB, id)
	}
	if !shared {
		return false, "the advisories share no identifier", nil
	}
	if len(cvesA) > 0 && len(cvesB) > 0 && !slices.Equal(cvesA, cvesB) {
		return false, fmt.Sprintf("different vulnerabilities: %s vs %s", cveList(cvesA), cveList(cvesB)), nil
	}
	return true, "", nil
}

func cveList(cves []string) string {
	if len(cves) == 0 {
		return "no CVE"
	}
	return strings.Join(cves, ", ")
}

// mergeCompatibility says why merged cannot merge into survivor, or "".
func (s *Server) mergeCompatibility(ctx context.Context, survivor, merged dbgen.Incident) (string, error) {
	switch {
	case survivor.ID == merged.ID:
		return "an incident does not merge into itself", nil
	case survivor.OrgID != merged.OrgID || survivor.Kind != merged.Kind || survivor.RepoID != merged.RepoID:
		return "only incidents of the same kind on the same repository merge", nil
	case survivor.State == dbgen.IncidentStateWithdrawn || survivor.MergedInto.Valid:
		return fmt.Sprintf("#%d was withdrawn or merged", survivor.Number), nil
	case merged.State == dbgen.IncidentStateWithdrawn || merged.MergedInto.Valid:
		return fmt.Sprintf("#%d was withdrawn or merged", merged.Number), nil
	}
	// Each exploited vulnerability is its own report with its own T0.
	if survivor.Kind == incident.KindExploitedVulnerability && survivor.SubjectType == incident.SubjectAdvisory && merged.SubjectType == incident.SubjectAdvisory {
		a, errA := uuid.Parse(survivor.SubjectID)
		b, errB := uuid.Parse(merged.SubjectID)
		if errA == nil && errB == nil && a != b {
			same, why, err := s.sameVulnerability(ctx, a, b)
			if err != nil {
				return "", err
			}
			if !same {
				return why, nil
			}
		}
	}
	return "", nil
}

// proposeOrMergeIncidents merges, or under four-eyes records the proposal.
func (s *Server) proposeOrMergeIncidents(ctx context.Context, survivor, merged dbgen.Incident, actor incidentActor, reason string) (bool, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return false, errIncidentInput("merging needs its reason")
	}
	why, err := s.mergeCompatibility(ctx, survivor, merged)
	if err != nil {
		return false, err
	}
	if why != "" {
		return false, errIncidentInput("%s", why)
	}
	settings, err := s.loadIncidentSettings(ctx, merged.OrgID)
	if err != nil {
		return false, err
	}
	if !settings.Row.FourEyes || actor.Type != audit.ActorUser {
		return false, s.mergeIncidents(ctx, survivor, merged, actor, reason)
	}
	payload, _ := json.Marshal(mergeProposal{
		IntoID: survivor.ID.String(), IntoNumber: survivor.Number, Reason: reason,
		ProposedBy: actor.ID.UUID.String(), ProposedAt: time.Now().UTC(),
	})
	err = s.incidentTx(ctx, incidentLockKey(merged.ID), func(q *store.Queries) error {
		if _, err := q.Incidents().SetIncidentProposedMerge(ctx, dbgen.SetIncidentProposedMergeParams{ID: merged.ID, ProposedMerge: payload}); err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, q.Incidents(), merged.ID, actor, "merge.proposed", map[string]any{"into": survivor.Number, "reason": reason})
		return nil
	})
	if err == nil {
		s.writeSystemAuditLog(ctx, actor, merged.OrgID, audit.ActionIncidentMerge, merged.ID.String(), map[string]any{"proposed": true, "into": survivor.Number, "reason": reason})
	}
	return true, err
}

func pendingMerge(inc dbgen.Incident) (mergeProposal, bool) {
	var proposal mergeProposal
	if len(inc.ProposedMerge) == 0 || string(inc.ProposedMerge) == "null" {
		return proposal, false
	}
	if err := json.Unmarshal(inc.ProposedMerge, &proposal); err != nil || proposal.IntoID == "" {
		return proposal, false
	}
	return proposal, true
}

// approveIncidentMerge applies a proposed merge; its author cannot.
func (s *Server) approveIncidentMerge(ctx context.Context, merged dbgen.Incident, approver incidentActor) (int32, error) {
	proposal, ok := pendingMerge(merged)
	if !ok {
		return 0, errIncidentInput("no merge is waiting for approval")
	}
	if approver.Type != audit.ActorUser || approver.ID.UUID.String() == proposal.ProposedBy {
		return 0, errIncidentInput("a proposed merge is approved by someone other than its author")
	}
	intoID, err := uuid.Parse(proposal.IntoID)
	if err != nil {
		return 0, errIncidentInput("the proposal names no incident")
	}
	survivor, err := s.queries.Incidents().GetIncident(ctx, intoID)
	if err != nil {
		return 0, errIncidentInput("#%d no longer exists", proposal.IntoNumber)
	}
	// The incidents may have changed since the proposal: check again.
	why, err := s.mergeCompatibility(ctx, survivor, merged)
	if err != nil {
		return 0, err
	}
	if why != "" {
		return 0, errIncidentInput("%s", why)
	}
	reason := fmt.Sprintf("%s (proposed by %s, approved by %s)", proposal.Reason, s.userDisplay(ctx, proposal.ProposedBy), approver.Display)
	if err := s.mergeIncidents(ctx, survivor, merged, approver, reason); err != nil {
		return 0, err
	}
	return survivor.Number, nil
}

// cancelIncidentMerge drops a proposed merge: its author withdraws it, or
// another manager rejects it.
func (s *Server) cancelIncidentMerge(ctx context.Context, merged dbgen.Incident, actor incidentActor, reason string) error {
	proposal, ok := pendingMerge(merged)
	if !ok {
		return errIncidentInput("no merge is waiting for approval")
	}
	kind := "merge.rejected"
	if actor.ID.UUID.String() == proposal.ProposedBy {
		kind = "merge.cancelled"
	}
	err := s.incidentTx(ctx, incidentLockKey(merged.ID), func(q *store.Queries) error {
		if _, err := q.Incidents().SetIncidentProposedMerge(ctx, dbgen.SetIncidentProposedMergeParams{ID: merged.ID, ProposedMerge: json.RawMessage(`null`)}); err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, q.Incidents(), merged.ID, actor, kind, map[string]any{"into": proposal.IntoNumber, "reason": strings.TrimSpace(reason)})
		return nil
	})
	if err == nil {
		s.writeSystemAuditLog(ctx, actor, merged.OrgID, audit.ActionIncidentMerge, merged.ID.String(), map[string]any{"cancelled": true, "into": proposal.IntoNumber, "reason": strings.TrimSpace(reason)})
	}
	return err
}

func (s *Server) userDisplay(ctx context.Context, id string) string {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return "someone"
	}
	user, err := s.queries.GetUserByID(ctx, parsed)
	if err != nil || user == nil {
		return "someone"
	}
	return actorDisplay(user)
}

// mergeCandidate is one incident a merge could fold this one into.
type mergeCandidate struct {
	Number     int32  `json:"number"`
	Title      string `json:"title"`
	State      string `json:"state"`
	Subject    string `json:"subject"`
	Compatible bool   `json:"compatible"`
	Reason     string `json:"reason,omitempty"`
}

// @Summary      Incidents this one can merge into
// @Description  Same kind, same repository, neither withdrawn nor merged. An exploited vulnerability only merges with one naming exactly the same CVEs; the others are listed with the reason (ADR-053 §3).
// @Tags         incidents
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        number    path  int     true  "Incident number"
// @Success      200  {object}  api.Response{data=[]server.mergeCandidate}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/incidents/{number}/merge-candidates [get]
func (s *Server) handleIncidentMergeCandidates(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	ctx := r.Context()
	rows, err := s.queries.Incidents().ListMergeCandidates(ctx, dbgen.ListMergeCandidatesParams{OrgID: inc.OrgID, Kind: inc.Kind, RepoID: inc.RepoID, IncidentID: inc.ID})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list incidents")
		return
	}
	out := make([]mergeCandidate, 0, len(rows))
	for _, row := range rows {
		why, err := s.mergeCompatibility(ctx, row, inc)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to compare incidents")
			return
		}
		out = append(out, mergeCandidate{
			Number: row.Number, Title: row.Title, State: string(row.State), Subject: s.incidentSubjectLabel(ctx, row),
			Compatible: why == "", Reason: why,
		})
	}
	api.JSON(w, http.StatusOK, out)
}

// incidentSubjectLabel names what an incident is about, for the picker.
func (s *Server) incidentSubjectLabel(ctx context.Context, inc dbgen.Incident) string {
	if inc.SubjectType == incident.SubjectAdvisory {
		if id, err := uuid.Parse(inc.SubjectID); err == nil {
			if advisory, err := s.queries.GetAdvisoryByID(ctx, id); err == nil {
				return advisory.CanonicalID
			}
		}
	}
	return ""
}

// @Summary      Approve a proposed merge
// @Description  Applies the merge another person proposed under the four-eyes setting (ADR-053 §3).
// @Tags         incidents
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        number    path  int     true  "Number of the incident to absorb"
// @Success      200  {object}  api.Response{data=map[string]int}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/incidents/{number}/merge/approve [post]
func (s *Server) handleApproveIncidentMerge(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	into, err := s.approveIncidentMerge(r.Context(), inc, incidentActorFor(r, UserFromContext(r.Context())))
	if err != nil {
		s.writeIncidentError(w, err)
		return
	}
	api.JSON(w, http.StatusOK, map[string]int32{"merged_into": into})
}

// @Summary      Cancel or reject a proposed merge
// @Tags         incidents
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        number    path  int     true  "Number of the incident to absorb"
// @Success      204
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/incidents/{number}/merge/cancel [post]
func (s *Server) handleCancelIncidentMerge(w http.ResponseWriter, r *http.Request) {
	_, inc, ok := s.loadIncidentForRequest(w, r, true)
	if !ok {
		return
	}
	var input reasonRequest
	if r.ContentLength > 0 && !decodeIncidentBody(w, r, &input) {
		return
	}
	if err := s.cancelIncidentMerge(r.Context(), inc, incidentActorFor(r, UserFromContext(r.Context())), input.Reason); err != nil {
		s.writeIncidentError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

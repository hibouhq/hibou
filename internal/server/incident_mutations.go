package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Incident mutations a person makes (ADR-053 §2–§7). Each one appends to the
// timeline, writes the audit log and reconciles the incident.

// incidentInputError is a mutation refused for a reason the caller can fix.
type incidentInputError struct{ msg string }

func (e incidentInputError) Error() string { return e.msg }

func errIncidentInput(format string, args ...any) error {
	return incidentInputError{msg: fmt.Sprintf(format, args...)}
}

// errIncidentConflict marks a mutation refused because of the incident's
// state.
var errIncidentConflict = errors.New("incident state does not allow this")

type incidentDecision struct {
	State        string     `json:"state"`
	Reason       string     `json:"reason"`
	AwareAt      *time.Time `json:"aware_at,omitempty"`
	DecisionStep string     `json:"decision_step,omitempty"`
	// Justification: the VEX justification of a "cannot be exploited here"
	// step (ADR-053 §4a); ActionStatement: what users can do, for an
	// affected one. WriteStatements records the step as the VEX statement of
	// every release in scope that has none yet; releases keep their own
	// statements, and a later per-release statement supersedes this one.
	Justification   string     `json:"justification,omitempty"`
	ActionStatement string     `json:"action_statement,omitempty"`
	WriteStatements bool       `json:"write_statements,omitempty"`
	ProposedBy      string     `json:"proposed_by,omitempty"`
	ProposedAt      *time.Time `json:"proposed_at,omitempty"`
}

// decideIncident records the decision step (§2). Under the four-eyes setting a
// decision that ends obligations (not reportable, dismissed) is only proposed;
// another person applies it with approveIncidentDecision.
func (s *Server) decideIncident(ctx context.Context, inc dbgen.Incident, actor incidentActor, decision incidentDecision) (dbgen.Incident, bool, error) {
	if !incident.Open(string(inc.State)) {
		return inc, false, errIncidentConflict
	}
	decision.Reason = strings.TrimSpace(decision.Reason)
	if decision.Reason == "" {
		return inc, false, errIncidentInput("a decision needs its reason")
	}
	if !incident.ValidDecision(inc.Regimes, decision.State) {
		positive, negative := incident.DecisionStates(inc.Regimes)
		return inc, false, errIncidentInput("state must be %s or %s for this incident", positive, negative)
	}
	if inc.Kind == incident.KindExploitedVulnerability {
		valid := false
		for _, step := range incident.DecisionSteps {
			valid = valid || step == decision.DecisionStep
		}
		if !valid {
			return inc, false, errIncidentInput("decision_step must be one of %s", strings.Join(incident.DecisionSteps, ", "))
		}
		if incident.StepReportable(decision.DecisionStep) != (decision.State == incident.StateReportable) {
			return inc, false, errIncidentInput("reportable goes with the step %q, and only with it", incident.StepAttacked)
		}
		if decision.DecisionStep == incident.StepNotReachable && decision.Justification != "" && !slices.Contains(incident.NotExploitableJustifications, decision.Justification) {
			return inc, false, errIncidentInput("justification must be one of %s", strings.Join(incident.NotExploitableJustifications, ", "))
		}
	} else {
		decision.WriteStatements = false
	}
	now := time.Now().UTC()
	positive, _ := incident.DecisionStates(inc.Regimes)
	if decision.State == positive && incident.HasExternalRegime(inc.Regimes) {
		if decision.AwareAt == nil {
			decision.AwareAt = &now
		}
		if decision.AwareAt.After(now.Add(time.Minute)) {
			return inc, false, errIncidentInput("aware_at cannot be in the future")
		}
		if inc.AwareAt.Valid && decision.AwareAt.After(inc.AwareAt.Time) {
			return inc, false, errIncidentInput("aware_at can only move earlier once set")
		}
		if inc.AwareAt.Valid && !decision.AwareAt.Equal(inc.AwareAt.Time) {
			if filed, err := s.incidentHasFiling(ctx, inc.ID); err != nil || filed {
				return inc, false, errIncidentInput("aware_at is fixed once a filing is recorded")
			}
		}
	} else {
		decision.AwareAt = nil
	}

	settings, err := s.loadIncidentSettings(ctx, inc.OrgID)
	if err != nil {
		return inc, false, err
	}
	if settings.Row.FourEyes && incident.HidingDecision(decision.State) && actor.Type == audit.ActorUser {
		decision.ProposedBy, decision.ProposedAt = actor.ID.UUID.String(), &now
		payload, _ := json.Marshal(decision)
		var updated dbgen.Incident
		err := s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
			var err error
			updated, err = q.Incidents().SetIncidentProposedDecision(ctx, dbgen.SetIncidentProposedDecisionParams{ID: inc.ID, ProposedDecision: payload})
			if err != nil {
				return err
			}
			s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "decision.proposed", map[string]any{"state": decision.State, "reason": decision.Reason, "decision_step": decision.DecisionStep})
			return nil
		})
		if err == nil {
			s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentDecide, inc.ID.String(), map[string]any{"proposed": true, "state": decision.State, "reason": decision.Reason})
		}
		return updated, true, err
	}
	updated, err := s.applyIncidentDecision(ctx, inc, actor, decision, nil)
	return updated, false, err
}

func (s *Server) applyIncidentDecision(ctx context.Context, inc dbgen.Incident, actor incidentActor, decision incidentDecision, approvedBy *incidentActor) (dbgen.Incident, error) {
	var updated dbgen.Incident
	err := s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		params := dbgen.UpdateIncidentDecisionParams{
			ID: inc.ID, State: dbgen.IncidentState(decision.State), DecisionReason: nullStringValue(decision.Reason),
			DecisionStep: nullStringValue(decision.DecisionStep), DecidedBy: actor.userID(), Regimes: inc.Regimes,
		}
		if decision.AwareAt != nil {
			params.AwareAt = sql.NullTime{Time: decision.AwareAt.UTC(), Valid: true}
		}
		var err error
		updated, err = q.Incidents().UpdateIncidentDecision(ctx, params)
		if err != nil {
			return err
		}
		detail := map[string]any{"state": decision.State, "reason": decision.Reason}
		if decision.DecisionStep != "" {
			detail["decision_step"] = decision.DecisionStep
		}
		if decision.AwareAt != nil {
			detail["aware_at"] = decision.AwareAt.UTC()
		}
		if approvedBy != nil {
			detail["approved_by"] = approvedBy.Display
		}
		s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "decided", detail)
		return nil
	})
	if err != nil {
		return updated, err
	}
	auditContext := map[string]any{"state": decision.State, "reason": decision.Reason, "decision_step": decision.DecisionStep}
	if decision.AwareAt != nil {
		auditContext["aware_at"] = decision.AwareAt.UTC()
	}
	if decision.WriteStatements {
		written, err := s.writeDecisionStatements(ctx, updated, actor, decision)
		if err != nil {
			s.log.Warn().Err(err).Str("incident_id", inc.ID.String()).Msg("statements from the decision")
		}
		auditContext["statements_written"] = written
	}
	auditActor := actor
	if approvedBy != nil {
		auditActor = *approvedBy
		auditContext["proposed_by"] = actor.Display
	}
	s.writeSystemAuditLog(ctx, auditActor, inc.OrgID, audit.ActionIncidentDecide, inc.ID.String(), auditContext)
	if reconciled, err := s.reconcileIncident(ctx, inc.ID); err == nil {
		updated = reconciled
	}
	return updated, nil
}

// approveIncidentDecision applies a proposed decision; the approver must be
// someone other than the proposer.
func (s *Server) approveIncidentDecision(ctx context.Context, inc dbgen.Incident, approver incidentActor) (dbgen.Incident, error) {
	if len(inc.ProposedDecision) == 0 || string(inc.ProposedDecision) == "null" {
		return inc, errIncidentInput("no decision is waiting for approval")
	}
	var decision incidentDecision
	if err := json.Unmarshal(inc.ProposedDecision, &decision); err != nil {
		return inc, err
	}
	if approver.Type != audit.ActorUser || approver.ID.UUID.String() == decision.ProposedBy {
		return inc, errIncidentInput("a proposed decision is approved by someone other than its author")
	}
	proposer := incidentActor{Type: audit.ActorUser, Display: "proposer"}
	if id, err := uuid.Parse(decision.ProposedBy); err == nil {
		proposer.ID = uuid.NullUUID{UUID: id, Valid: true}
		if user, err := s.queries.GetUserByID(ctx, id); err == nil && user != nil {
			proposer.Display = actorDisplay(user)
		}
	}
	return s.applyIncidentDecision(ctx, inc, proposer, decision, &approver)
}

func (s *Server) incidentHasFiling(ctx context.Context, incidentID uuid.UUID) (bool, error) {
	rows, err := s.queries.Incidents().ListIncidentDeadlines(ctx, incidentID)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if row.MetAt.Valid && row.Regime != incident.RegimeInternal {
			return true, nil
		}
	}
	return false, nil
}

// filingStep maps a filing action kind to the regime and step it meets.
func filingStep(inc dbgen.Incident, kind string, national []incident.NationalRegime) (string, string, bool) {
	for _, name := range inc.Regimes {
		regime, ok := incident.ResolveRegime(name, inc.Kind, national)
		if !ok {
			continue
		}
		for _, step := range regime.Steps {
			if step.Filing == kind {
				return regime.Name, step.Step, true
			}
		}
	}
	return "", "", false
}

// recordIncidentFiling records a filing a person made on the authority's
// platform (§4): hibou never submits, it records the reference and time.
func (s *Server) recordIncidentFiling(ctx context.Context, inc dbgen.Incident, actor incidentActor, actionID uuid.UUID, reference string, filedAt time.Time) (dbgen.IncidentAction, error) {
	action, err := s.queries.Incidents().GetIncidentAction(ctx, actionID)
	if err != nil || action.IncidentID != inc.ID {
		return action, errIncidentInput("action not found on this incident")
	}
	settings, err := s.loadIncidentSettings(ctx, inc.OrgID)
	if err != nil {
		return action, err
	}
	regime, step, ok := filingStep(inc, action.Kind, settings.National)
	if !ok {
		return action, errIncidentInput("action %s is not a filing", action.Kind)
	}
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return action, errIncidentInput("a filing needs the platform's reference")
	}
	if filedAt.IsZero() {
		filedAt = time.Now().UTC()
	}
	if filedAt.After(time.Now().UTC().Add(time.Minute)) {
		return action, errIncidentInput("filed_at cannot be in the future")
	}
	var completed dbgen.IncidentAction
	err = s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		db := q.Incidents()
		if _, err := db.MeetIncidentDeadline(ctx, dbgen.MeetIncidentDeadlineParams{
			IncidentID: inc.ID, Regime: regime, Step: step, MetAt: sql.NullTime{Time: filedAt.UTC(), Valid: true}, Reference: reference,
		}); err != nil {
			return err
		}
		evidence, _ := json.Marshal(map[string]any{"reference": reference, "filed_at": filedAt.UTC(), "regime": regime, "step": step})
		var err error
		completed, err = db.CompleteIncidentAction(ctx, dbgen.CompleteIncidentActionParams{ID: action.ID, IncidentID: inc.ID, DoneBy: actor.userID(), Evidence: evidence})
		if errors.Is(err, sql.ErrNoRows) {
			return errIncidentInput("this filing is already recorded")
		}
		if err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, db, inc.ID, actor, "filing.recorded", map[string]any{"kind": action.Kind, "reference": reference, "filed_at": filedAt.UTC(), "regime": regime, "step": step})
		return nil
	})
	if err != nil {
		return completed, err
	}
	s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentFiling, inc.ID.String(), map[string]any{"kind": action.Kind, "reference": reference, "filed_at": filedAt.UTC()})
	_, _ = s.reconcileIncident(ctx, inc.ID)
	return completed, nil
}

// completeIncidentAction marks an action done by a person with evidence.
func (s *Server) completeIncidentAction(ctx context.Context, inc dbgen.Incident, actor incidentActor, actionID uuid.UUID, note, reference string) (dbgen.IncidentAction, error) {
	note, reference = strings.TrimSpace(note), strings.TrimSpace(reference)
	if note == "" && reference == "" {
		return dbgen.IncidentAction{}, errIncidentInput("completing an action needs evidence: a note or a reference")
	}
	action, err := s.queries.Incidents().GetIncidentAction(ctx, actionID)
	if err != nil || action.IncidentID != inc.ID {
		return action, errIncidentInput("action not found on this incident")
	}
	if _, _, isFiling := filingStep(inc, action.Kind, nil); isFiling {
		return action, errIncidentInput("record a filing with its platform reference instead")
	}
	var completed dbgen.IncidentAction
	err = s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		evidence, _ := json.Marshal(map[string]any{"note": note, "reference": reference})
		var err error
		completed, err = q.Incidents().CompleteIncidentAction(ctx, dbgen.CompleteIncidentActionParams{ID: action.ID, IncidentID: inc.ID, DoneBy: actor.userID(), Evidence: evidence})
		if errors.Is(err, sql.ErrNoRows) {
			return errIncidentInput("this action is not pending")
		}
		if err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "action.completed", map[string]any{"action_id": action.ID, "kind": action.Kind, "label": action.Label, "note": note, "reference": reference})
		return nil
	})
	if err != nil {
		return completed, err
	}
	s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentAction, inc.ID.String(), map[string]any{"action": "complete", "kind": action.Kind, "note": note, "reference": reference})
	_, _ = s.reconcileIncident(ctx, inc.ID)
	return completed, nil
}

// waiveIncidentAction is the sanctioned exception (§4): a reason, audited,
// and under the four-eyes setting proposed by one person, approved by
// another.
func (s *Server) waiveIncidentAction(ctx context.Context, inc dbgen.Incident, actor incidentActor, actionID uuid.UUID, reason string, approve bool) (dbgen.IncidentAction, bool, error) {
	reason = strings.TrimSpace(reason)
	action, err := s.queries.Incidents().GetIncidentAction(ctx, actionID)
	if err != nil || action.IncidentID != inc.ID {
		return action, false, errIncidentInput("action not found on this incident")
	}
	if action.State != "pending" {
		return action, false, errIncidentInput("only a pending action can be waived")
	}
	settings, err := s.loadIncidentSettings(ctx, inc.OrgID)
	if err != nil {
		return action, false, err
	}
	var proposal struct {
		ProposedBy string `json:"waiver_proposed_by"`
		Reason     string `json:"waiver_reason"`
	}
	_ = json.Unmarshal(action.Evidence, &proposal)
	if approve {
		if proposal.ProposedBy == "" {
			return action, false, errIncidentInput("no waiver is waiting for approval")
		}
		if actor.Type != audit.ActorUser || actor.ID.UUID.String() == proposal.ProposedBy {
			return action, false, errIncidentInput("a waiver is approved by someone other than its author")
		}
		reason = proposal.Reason
	} else if reason == "" {
		return action, false, errIncidentInput("a waiver needs its reason")
	}

	if settings.Row.FourEyes && !approve && actor.Type == audit.ActorUser {
		err := s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
			evidence, _ := json.Marshal(map[string]any{"waiver_proposed_by": actor.ID.UUID.String(), "waiver_reason": reason})
			if _, err := q.Incidents().ProposeIncidentActionWaiver(ctx, dbgen.ProposeIncidentActionWaiverParams{ID: action.ID, IncidentID: inc.ID, Evidence: evidence}); err != nil {
				return err
			}
			s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "waiver.proposed", map[string]any{"action_id": action.ID, "kind": action.Kind, "reason": reason})
			return nil
		})
		if err == nil {
			s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentAction, inc.ID.String(), map[string]any{"action": "propose_waiver", "kind": action.Kind, "reason": reason})
		}
		return action, true, err
	}

	var waived dbgen.IncidentAction
	err = s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		var err error
		waived, err = q.Incidents().WaiveIncidentAction(ctx, dbgen.WaiveIncidentActionParams{ID: action.ID, IncidentID: inc.ID, WaivedBy: actor.userID(), WaivedReason: nullStringValue(reason)})
		if errors.Is(err, sql.ErrNoRows) {
			return errIncidentInput("only a pending action can be waived")
		}
		if err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "action.waived", map[string]any{"action_id": action.ID, "kind": action.Kind, "label": action.Label, "reason": reason})
		return nil
	})
	if err != nil {
		return waived, false, err
	}
	s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentAction, inc.ID.String(), map[string]any{"action": "waive", "kind": action.Kind, "reason": reason})
	_, _ = s.reconcileIncident(ctx, inc.ID)
	return waived, false, nil
}

func (s *Server) reopenIncidentAction(ctx context.Context, inc dbgen.Incident, actor incidentActor, actionID uuid.UUID, reason string) (dbgen.IncidentAction, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return dbgen.IncidentAction{}, errIncidentInput("reopening an action needs its reason")
	}
	action, err := s.queries.Incidents().GetIncidentAction(ctx, actionID)
	if err != nil || action.IncidentID != inc.ID {
		return action, errIncidentInput("action not found on this incident")
	}
	var reopened dbgen.IncidentAction
	err = s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		var err error
		reopened, err = q.Incidents().ReopenIncidentAction(ctx, dbgen.ReopenIncidentActionParams{ID: action.ID, IncidentID: inc.ID})
		if err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "action.reopened", map[string]any{"action_id": action.ID, "kind": action.Kind, "label": action.Label, "reason": reason})
		return nil
	})
	if err != nil {
		return reopened, err
	}
	s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentAction, inc.ID.String(), map[string]any{"action": "reopen", "kind": action.Kind, "reason": reason})
	if inc.State == dbgen.IncidentStateClosed {
		s.reopenClosedIncident(ctx, inc, actor, "action reopened: "+action.Label)
	}
	_, _ = s.reconcileIncident(ctx, inc.ID)
	return reopened, nil
}

func (s *Server) reopenClosedIncident(ctx context.Context, inc dbgen.Incident, actor incidentActor, why string) {
	state := dbgen.IncidentStateSignal
	if inc.DecidedState.Valid {
		state = inc.DecidedState.IncidentState
	}
	_ = s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		if _, err := q.Incidents().UpdateIncidentState(ctx, dbgen.UpdateIncidentStateParams{ID: inc.ID, State: state, ClosedAt: sql.NullTime{}}); err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "reopened", map[string]any{"reason": why})
		return nil
	})
}

func (s *Server) assignIncidentAction(ctx context.Context, inc dbgen.Incident, actor incidentActor, actionID uuid.UUID, assignee uuid.NullUUID) (dbgen.IncidentAction, error) {
	if assignee.Valid {
		if role, err := s.queries.GetOrgMemberRole(ctx, inc.OrgID, assignee.UUID); err != nil || role == "" {
			return dbgen.IncidentAction{}, errIncidentInput("the assignee must be a member of the organisation")
		}
	}
	var updated dbgen.IncidentAction
	err := s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		var err error
		updated, err = q.Incidents().AssignIncidentAction(ctx, dbgen.AssignIncidentActionParams{ID: actionID, IncidentID: inc.ID, AssigneeID: assignee})
		if err != nil {
			return errIncidentInput("action not found on this incident")
		}
		s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "action.assigned", map[string]any{"action_id": actionID, "assignee_id": assignee})
		return nil
	})
	return updated, err
}

// setIncidentScopeDecision records a person's decision on a scope row: an
// exclusion with its reason, or a manual row for a severe incident. Clearing
// hands the row back to derivation.
func (s *Server) setIncidentScopeDecision(ctx context.Context, inc dbgen.Incident, actor incidentActor, subjectType, subjectID, label, status, reason string, clear bool) error {
	subjectType, subjectID, status, reason = strings.TrimSpace(subjectType), strings.TrimSpace(subjectID), strings.TrimSpace(status), strings.TrimSpace(reason)
	if subjectType == "" || subjectID == "" {
		return errIncidentInput("subject_type and subject_id are required")
	}
	if !clear {
		if reason == "" {
			return errIncidentInput("a scope decision needs its reason")
		}
		allowed := map[string]bool{incident.ScopeExcluded: true, incident.ScopeAffected: true}
		if inc.Kind == incident.KindSevereIncident {
			allowed[incident.ScopeUnknown] = true
		}
		if !allowed[status] {
			return errIncidentInput("a person sets a row to excluded (or affected); statements set the rest")
		}
	}
	err := s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		db := q.Incidents()
		if clear {
			if err := db.DeleteIncidentScopeRow(ctx, dbgen.DeleteIncidentScopeRowParams{IncidentID: inc.ID, SubjectType: subjectType, SubjectID: subjectID}); err != nil {
				return err
			}
			s.appendIncidentEvent(ctx, db, inc.ID, actor, "scope.cleared", map[string]any{"subject_type": subjectType, "subject_id": subjectID})
			return nil
		}
		if label == "" {
			label = subjectID
		}
		if err := db.UpsertIncidentScopeRow(ctx, dbgen.UpsertIncidentScopeRowParams{
			IncidentID: inc.ID, SubjectType: subjectType, SubjectID: subjectID, Label: label, Status: status, Reason: reason, Manual: true,
		}); err != nil {
			return err
		}
		if err := db.SetIncidentScopeDecision(ctx, dbgen.SetIncidentScopeDecisionParams{
			IncidentID: inc.ID, SubjectType: subjectType, SubjectID: subjectID, Status: status, Reason: reason, DecidedBy: actor.userID(),
		}); err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, db, inc.ID, actor, "scope.decided", map[string]any{"subject_type": subjectType, "subject_id": subjectID, "label": label, "status": status, "reason": reason})
		return nil
	})
	if err != nil {
		return err
	}
	s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentScope, inc.ID.String(), map[string]any{"subject_type": subjectType, "subject_id": subjectID, "status": status, "reason": reason, "cleared": clear})
	_, _ = s.reconcileIncident(ctx, inc.ID)
	return nil
}

// withdrawIncident ends an incident that should not exist (wrong advisory,
// duplicate): a terminal state distinct from closed.
func (s *Server) withdrawIncident(ctx context.Context, inc dbgen.Incident, actor incidentActor, reason string) (dbgen.Incident, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return inc, errIncidentInput("withdrawing needs its reason")
	}
	if !incident.Open(string(inc.State)) {
		return inc, errIncidentConflict
	}
	var updated dbgen.Incident
	err := s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		var err error
		updated, err = q.Incidents().UpdateIncidentState(ctx, dbgen.UpdateIncidentStateParams{ID: inc.ID, State: dbgen.IncidentStateWithdrawn, ClosedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}})
		if err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "withdrawn", map[string]any{"reason": reason})
		return nil
	})
	if err == nil {
		s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentWithdraw, inc.ID.String(), map[string]any{"reason": reason})
		s.queueTrackerSync(inc.ID)
	}
	return updated, err
}

// mergeIncidents folds one incident into another (two identifiers for one
// vulnerability, §3): the survivor absorbs history, actions and deliveries;
// nothing is deleted.
func (s *Server) mergeIncidents(ctx context.Context, survivor, merged dbgen.Incident, actor incidentActor, reason string) error {
	why, err := s.mergeCompatibility(ctx, survivor, merged)
	if err != nil {
		return err
	}
	if why != "" {
		return errIncidentInput("%s", why)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, id := range []uuid.UUID{survivor.ID, merged.ID} {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", store.AdvisoryLockID(incidentLockKey(id))); err != nil {
			return err
		}
	}
	db := s.queries.WithTx(tx).Incidents()
	if err := db.MoveIncidentChildren(ctx, dbgen.MoveIncidentChildrenParams{Survivor: survivor.ID, Merged: merged.ID}); err != nil {
		return err
	}
	if err := db.MergeIncidentInto(ctx, dbgen.MergeIncidentIntoParams{ID: merged.ID, MergedInto: uuid.NullUUID{UUID: survivor.ID, Valid: true}}); err != nil {
		return err
	}
	s.appendIncidentEvent(ctx, db, survivor.ID, actor, "merged", map[string]any{"absorbed": merged.Number, "absorbed_subject": merged.SubjectID, "reason": reason})
	s.appendIncidentEvent(ctx, db, merged.ID, actor, "merged_into", map[string]any{"into": survivor.Number, "reason": reason})
	if err := tx.Commit(); err != nil {
		return err
	}
	s.writeSystemAuditLog(ctx, actor, survivor.OrgID, audit.ActionIncidentMerge, survivor.ID.String(), map[string]any{"absorbed": merged.ID, "reason": reason})
	if survivor.State == dbgen.IncidentStateClosed {
		s.reopenClosedIncident(ctx, survivor, actor, fmt.Sprintf("merged with #%d", merged.Number))
	}
	_, _ = s.reconcileIncident(ctx, survivor.ID)
	return nil
}

// mergeAliasSiblings folds exploited-vulnerability incidents whose advisories
// share an identifier into the oldest one.
func (s *Server) mergeAliasSiblings(ctx context.Context, inc dbgen.Incident) {
	if inc.Kind != incident.KindExploitedVulnerability || !inc.RepoID.Valid || !incident.Open(string(inc.State)) {
		return
	}
	advisoryID, err := uuid.Parse(inc.SubjectID)
	if err != nil {
		return
	}
	siblings, err := s.queries.Incidents().ListAliasSiblingIncidents(ctx, dbgen.ListAliasSiblingIncidentsParams{RepoID: inc.RepoID, IncidentID: inc.ID, AdvisoryID: advisoryID})
	if err != nil || len(siblings) == 0 {
		return
	}
	survivor := inc
	all := append([]dbgen.Incident{inc}, siblings...)
	for _, candidate := range all {
		if candidate.Number < survivor.Number {
			survivor = candidate
		}
	}
	for _, candidate := range all {
		if candidate.ID == survivor.ID {
			continue
		}
		// A shared identifier is not enough: an advisory grouping several
		// CVEs shares one with each of them.
		if why, err := s.mergeCompatibility(ctx, survivor, candidate); err != nil || why != "" {
			continue
		}
		if err := s.mergeIncidents(ctx, survivor, candidate, incidentSystemActor, "the advisories name the same vulnerability"); err != nil {
			s.log.Warn().Err(err).Str("incident_id", candidate.ID.String()).Msg("merge alias sibling incident")
		}
	}
}

// setIncidentFixAvailable starts the vulnerability final-report clock (14
// days after a corrective measure is available).
func (s *Server) setIncidentFixAvailable(ctx context.Context, inc dbgen.Incident, actor incidentActor, at time.Time, note string) (dbgen.Incident, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if at.After(time.Now().UTC().Add(time.Minute)) {
		return inc, errIncidentInput("the fix cannot be available in the future")
	}
	var updated dbgen.Incident
	err := s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		var err error
		updated, err = q.Incidents().SetIncidentFixAvailable(ctx, dbgen.SetIncidentFixAvailableParams{ID: inc.ID, FixAvailableAt: sql.NullTime{Time: at.UTC(), Valid: true}})
		if err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "fix.available", map[string]any{"at": at.UTC(), "note": strings.TrimSpace(note)})
		return nil
	})
	if err != nil {
		return updated, err
	}
	s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentUpdate, inc.ID.String(), map[string]any{"fix_available_at": at.UTC()})
	if reconciled, err := s.reconcileIncident(ctx, inc.ID); err == nil {
		updated = reconciled
	}
	return updated, nil
}

// updateIncidentFields changes title, priority, owner or regimes.
// incidentFieldUpdate carries the editable fields of an incident; nil leaves
// a field as it is.
type incidentFieldUpdate struct {
	Title, Priority, ExternalRef *string
	OwnerID, OwnerTeamID         *uuid.NullUUID
	Regimes                      []string
}

func (s *Server) updateIncidentFields(ctx context.Context, inc dbgen.Incident, actor incidentActor, update incidentFieldUpdate) (dbgen.Incident, error) {
	title, priority, ownerID, ownerTeamID, regimes := update.Title, update.Priority, update.OwnerID, update.OwnerTeamID, update.Regimes
	params := dbgen.UpdateIncidentFieldsParams{ID: inc.ID, Title: inc.Title, Priority: inc.Priority, OwnerID: inc.OwnerID, OwnerTeamID: inc.OwnerTeamID, Regimes: inc.Regimes, ExternalRef: inc.ExternalRef}
	changes := map[string]any{}
	if update.ExternalRef != nil {
		params.ExternalRef, changes["external_ref"] = truncateRunes(strings.TrimSpace(*update.ExternalRef), 200), strings.TrimSpace(*update.ExternalRef)
	}
	if title != nil {
		value := strings.TrimSpace(*title)
		if value == "" {
			return inc, errIncidentInput("title cannot be empty")
		}
		params.Title, changes["title"] = truncateRunes(value, 300), value
	}
	if priority != nil {
		if !incident.ValidPriority(*priority) {
			return inc, errIncidentInput("priority must be P1, P2 or P3")
		}
		params.Priority, changes["priority"] = *priority, *priority
	}
	if ownerID != nil {
		params.OwnerID, changes["owner_id"] = *ownerID, *ownerID
	}
	if ownerTeamID != nil {
		params.OwnerTeamID, changes["owner_team_id"] = *ownerTeamID, *ownerTeamID
	}
	if regimes != nil {
		if incident.Decided(string(inc.State)) && incident.HasExternalRegime(inc.Regimes) != incident.HasExternalRegime(regimes) {
			return inc, errIncidentInput("adding or removing every external regime changes the decision vocabulary; withdraw and reopen instead")
		}
		settings, err := s.loadIncidentSettings(ctx, inc.OrgID)
		if err != nil {
			return inc, err
		}
		for _, regime := range regimes {
			if _, ok := incident.ResolveRegime(regime, inc.Kind, settings.National); !ok {
				return inc, errIncidentInput("unknown regime %q", regime)
			}
		}
		if len(regimes) == 0 {
			regimes = []string{incident.RegimeInternal}
		}
		params.Regimes, changes["regimes"] = regimes, regimes
	}
	if len(changes) == 0 {
		return inc, nil
	}
	var updated dbgen.Incident
	err := s.incidentTx(ctx, incidentLockKey(inc.ID), func(q *store.Queries) error {
		var err error
		updated, err = q.Incidents().UpdateIncidentFields(ctx, params)
		if err != nil {
			return err
		}
		s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, actor, "updated", changes)
		return nil
	})
	if err != nil {
		return updated, err
	}
	s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionIncidentUpdate, inc.ID.String(), changes)
	if reconciled, err := s.reconcileIncident(ctx, inc.ID); err == nil {
		updated = reconciled
	}
	return updated, nil
}

// addIncidentNote appends a free note to the timeline.
func (s *Server) addIncidentNote(ctx context.Context, inc dbgen.Incident, actor incidentActor, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return errIncidentInput("a note needs text")
	}
	if len([]rune(text)) > 10000 {
		return errIncidentInput("a note is at most 10000 characters")
	}
	s.appendIncidentEvent(ctx, s.queries.Incidents(), inc.ID, actor, "note", map[string]any{"text": text})
	s.queueTrackerSync(inc.ID)
	return nil
}

// writeDecisionStatements records the ladder step as the VEX statement of
// every release in scope without one (ADR-053 §4a): one decision instead of
// one entry per release. A release that already has a statement keeps it, and
// a later per-release statement supersedes the one written here.
func (s *Server) writeDecisionStatements(ctx context.Context, inc dbgen.Incident, actor incidentActor, decision incidentDecision) (int, error) {
	if inc.Kind != incident.KindExploitedVulnerability || inc.SubjectType != incident.SubjectAdvisory || !inc.RepoID.Valid {
		return 0, nil
	}
	status, justification := incident.StepStatement(decision.DecisionStep, decision.Justification)
	if status == "" {
		return 0, nil
	}
	advisoryID, err := uuid.Parse(inc.SubjectID)
	if err != nil {
		return 0, err
	}
	rows, err := s.queries.Incidents().ListIncidentScope(ctx, inc.ID)
	if err != nil {
		return 0, err
	}
	written := 0
	for _, row := range rows {
		if row.SubjectType != incident.ScopeRelease || row.VexStatementID.Valid || row.Status == incident.ScopeExcluded || row.Status == incident.ScopeNotMatched {
			continue
		}
		request := createVEXStatementRequest{Status: status, Justification: justification}
		if status == "not_affected" {
			request.ImpactStatement = decision.Reason
		} else {
			request.ActionStatement = decision.ActionStatement
		}
		params, err := buildCreateVEXParams(inc.OrgID, inc.RepoID.UUID, actor.ID.UUID, advisoryID, request)
		if err != nil {
			return written, err
		}
		if err := s.applyVEXProductAxis(ctx, inc.RepoID.UUID, row.SubjectID, "", &params); err != nil {
			return written, err
		}
		params.Evidence, _ = json.Marshal(map[string]any{"incident": inc.Number, "decision_step": decision.DecisionStep, "from_decision": true})
		s.applyVEXApprovalPolicy(ctx, inc.OrgID, &params)
		statement, err := s.queries.RecordVEXStatement(ctx, params)
		if err != nil {
			if isUniqueViolation(err) {
				continue
			}
			return written, err
		}
		written++
		s.appendIncidentEvent(ctx, s.queries.Incidents(), inc.ID, actor, "statement.recorded", map[string]any{
			"vex_statement_id": statement.ID, "status": statement.Status, "release_id": row.SubjectID, "release": row.Label, "justification": justification, "from_decision": true,
		})
		s.writeSystemAuditLog(ctx, actor, inc.OrgID, audit.ActionVEXCreate, statement.ID.String(), map[string]any{"repo_id": inc.RepoID.UUID, "incident": inc.Number, "status": statement.Status, "from_decision": true})
	}
	if written > 0 {
		s.publishGateRecompute(ctx, inc.RepoID.UUID)
	}
	return written, nil
}

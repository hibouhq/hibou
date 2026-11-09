package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The incident service (ADR-053): opening, reconciling (facts → derivation →
// persisted scope, actions and clocks), computed closure and reopening. The
// API handlers, the rule sweep, the worker and the CLI all go through it.

// incidentActor is who an incident event is attributed to.
type incidentActor struct {
	ID      uuid.NullUUID
	Type    string
	Display string
}

var incidentSystemActor = incidentActor{Type: audit.ActorSystem, Display: "hibou"}

func incidentActorFor(r *http.Request, user *store.User) incidentActor {
	actor := requestAuditActor(r, user)
	return incidentActor{ID: actor.ID, Type: actor.Type, Display: actor.Display}
}

// userID is the person behind an actor, when the actor is a user.
func (a incidentActor) userID() uuid.NullUUID {
	if a.Type == audit.ActorUser {
		return a.ID
	}
	return uuid.NullUUID{}
}

func (s *Server) appendIncidentEvent(ctx context.Context, q *dbgen.Queries, incidentID uuid.UUID, actor incidentActor, kind string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	payload, err := json.Marshal(detail)
	if err != nil {
		payload = []byte(`{}`)
	}
	if _, err := q.CreateIncidentEvent(ctx, dbgen.CreateIncidentEventParams{
		IncidentID: incidentID, ActorID: actor.ID, ActorType: actor.Type, ActorDisplay: actor.Display, Kind: kind, Detail: payload,
	}); err != nil {
		s.log.Warn().Err(err).Str("incident_id", incidentID.String()).Str("kind", kind).Msg("incident event write failed")
	}
}

// incidentTx runs fn in a transaction holding the incident's lock, so two
// replicas never reconcile or mutate one incident at once.
func (s *Server) incidentTx(ctx context.Context, lockKey string, fn func(q *store.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", store.AdvisoryLockID(lockKey)); err != nil {
		return err
	}
	if err := fn(s.queries.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

func incidentLockKey(id uuid.UUID) string { return "hibou:incident:" + id.String() }

// incidentOpenInput is what opening an incident needs.
type incidentOpenInput struct {
	OrgID        uuid.UUID
	RepoID       uuid.NullUUID
	Kind         string
	SubjectType  string
	SubjectID    string
	Title        string
	Priority     string
	SignalSource string
	TriggerRule  string
	Regimes      []string
	Target       time.Duration
	SignalAt     time.Time
	Actor        incidentActor
	Scope        []incident.ScopeRow
	Detail       map[string]any
}

// openIncident creates an incident unless its subject already has one (open,
// closed or withdrawn: a rule never opens a second incident beside an earlier
// one; scope changes reopen it instead). It reports whether it created one.
func (s *Server) openIncident(ctx context.Context, in incidentOpenInput) (dbgen.Incident, bool, error) {
	if in.SubjectType == "" {
		in.SubjectType = incident.SubjectNone
	}
	if len(in.Regimes) == 0 {
		in.Regimes = []string{incident.RegimeInternal}
	}
	if !incident.ValidPriority(in.Priority) {
		in.Priority = "P2"
	}
	if in.SignalAt.IsZero() {
		in.SignalAt = time.Now().UTC()
	}
	ownerID, ownerTeamID := s.resolveIncidentOwner(ctx, in.OrgID, in.RepoID)

	var (
		created dbgen.Incident
		isNew   bool
	)
	err := s.incidentTx(ctx, "hibou:incident-org:"+in.OrgID.String(), func(q *store.Queries) error {
		db := q.Incidents()
		if in.SubjectType != incident.SubjectNone {
			existing, err := db.FindIncidentForSubject(ctx, dbgen.FindIncidentForSubjectParams{
				OrgID: in.OrgID, RepoID: in.RepoID, Kind: in.Kind, SubjectType: in.SubjectType, SubjectID: in.SubjectID,
			})
			if err == nil {
				created = existing
				return nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		number, err := db.NextIncidentNumber(ctx, in.OrgID)
		if err != nil {
			return err
		}
		var target sql.NullInt64
		if in.Target > 0 {
			target = sql.NullInt64{Int64: int64(in.Target / time.Second), Valid: true}
		}
		created, err = db.CreateIncident(ctx, dbgen.CreateIncidentParams{
			OrgID: in.OrgID, Number: number, RepoID: in.RepoID, Kind: in.Kind, Regimes: in.Regimes,
			SubjectType: in.SubjectType, SubjectID: in.SubjectID, Title: truncateRunes(strings.TrimSpace(in.Title), 300), State: dbgen.IncidentStateSignal,
			Priority: in.Priority, SignalSource: in.SignalSource, TriggerRule: nullStringValue(in.TriggerRule),
			SignalAt: in.SignalAt, OwnerID: ownerID, OwnerTeamID: ownerTeamID, CreatedBy: in.Actor.userID(), TargetSeconds: target,
		})
		if err != nil {
			return err
		}
		isNew = true
		for _, row := range in.Scope {
			if err := db.UpsertIncidentScopeRow(ctx, scopeRowParams(created.ID, row, true)); err != nil {
				return err
			}
		}
		detail := map[string]any{"kind": in.Kind, "signal_source": in.SignalSource, "priority": in.Priority, "regimes": in.Regimes}
		if in.TriggerRule != "" {
			detail["trigger_rule"] = in.TriggerRule
		}
		for key, value := range in.Detail {
			detail[key] = value
		}
		s.appendIncidentEvent(ctx, db, created.ID, in.Actor, "opened", detail)
		return nil
	})
	if err != nil || !isNew {
		return created, false, err
	}
	s.writeSystemAuditLog(ctx, in.Actor, in.OrgID, audit.ActionIncidentOpen, created.ID.String(), map[string]any{
		"number": created.Number, "kind": created.Kind, "subject_type": created.SubjectType, "subject_id": created.SubjectID,
	})
	reconciled, err := s.reconcileIncident(ctx, created.ID)
	if err == nil {
		created = reconciled
	}
	s.publishIncidentEvent(ctx, events.IncidentOpened, created, fmt.Sprintf("Incident #%d opened: %s", created.Number, created.Title),
		fmt.Sprintf("%s, %s, signal from %s.", incident.KindLabel(created.Kind), created.Priority, created.SignalSource))
	s.queueTrackerSync(created.ID)
	return created, true, nil
}

// resolveIncidentOwner reads the repository's `incidents.owner`, then the
// organisation's owner setting.
func (s *Server) resolveIncidentOwner(ctx context.Context, orgID uuid.UUID, repoID uuid.NullUUID) (uuid.NullUUID, uuid.NullUUID) {
	if repoID.Valid {
		cfg := s.loadPersistedRepoConfig(ctx, repoID.UUID)
		if cfg.Incidents != nil {
			kind, value, _ := strings.Cut(strings.TrimSpace(cfg.Incidents.Owner), ":")
			switch kind {
			case "user":
				if id, err := s.queries.Incidents().GetOrgMemberIDByLogin(ctx, dbgen.GetOrgMemberIDByLoginParams{OrgID: orgID, Lower: value}); err == nil {
					return uuid.NullUUID{UUID: id, Valid: true}, uuid.NullUUID{}
				}
			case "team":
				if team, err := s.queries.Incidents().GetTeamBySlugInOrg(ctx, dbgen.GetTeamBySlugInOrgParams{OrgID: orgID, Slug: value}); err == nil {
					return uuid.NullUUID{}, uuid.NullUUID{UUID: team.ID, Valid: true}
				}
			}
		}
	}
	settings, err := s.loadIncidentSettings(ctx, orgID)
	if err != nil {
		return uuid.NullUUID{}, uuid.NullUUID{}
	}
	return settings.Row.OwnerID, settings.Row.OwnerTeamID
}

func scopeRowParams(incidentID uuid.UUID, row incident.ScopeRow, manual bool) dbgen.UpsertIncidentScopeRowParams {
	params := dbgen.UpsertIncidentScopeRowParams{
		IncidentID: incidentID, SubjectType: row.SubjectType, SubjectID: row.SubjectID, Label: row.Label,
		Status: row.Status, Reason: row.Reason, ComponentPurl: row.ComponentPURL,
		Reachability: nullStringValue(row.Reachability), Manual: manual || row.Manual,
	}
	if id, err := uuid.Parse(row.StatementID); err == nil {
		params.VexStatementID = uuid.NullUUID{UUID: id, Valid: true}
	}
	return params
}

func nullStringValue(value string) sql.NullString {
	value = strings.TrimSpace(value)
	return sql.NullString{String: value, Valid: value != ""}
}

// reconcileIncident recomputes an incident from current facts and persists
// the result, then closes it when nothing remains or reopens a closed one
// whose scope grew. Idempotent: running it twice changes nothing the second
// time.
func (s *Server) reconcileIncident(ctx context.Context, id uuid.UUID) (dbgen.Incident, error) {
	var (
		result  dbgen.Incident
		publish []func()
	)
	err := s.incidentTx(ctx, incidentLockKey(id), func(q *store.Queries) error {
		db := q.Incidents()
		inc, err := db.GetIncident(ctx, id)
		if err != nil {
			return err
		}
		result = inc
		if inc.MergedInto.Valid || inc.State == dbgen.IncidentStateWithdrawn {
			return nil
		}
		settings, err := s.loadIncidentSettings(ctx, inc.OrgID)
		if err != nil {
			return err
		}
		deadlineRows, err := db.ListIncidentDeadlines(ctx, inc.ID)
		if err != nil {
			return err
		}
		effectiveState := string(inc.State)
		if inc.State == dbgen.IncidentStateClosed {
			effectiveState = incident.StateSignal
			if inc.DecidedState.Valid {
				effectiveState = string(inc.DecidedState.IncidentState)
			}
		}

		deadlines, metFilings, metSteps := s.incidentDeadlines(inc, deadlineRows, settings)
		facts, err := s.gatherIncidentFacts(ctx, q, inc, effectiveState, settings)
		if err != nil {
			return err
		}
		facts.Deadlines = deadlines
		facts.MetFilings = metFilings
		derivation := incident.Derive(facts)

		if err := persistIncidentDeadlines(ctx, db, inc.ID, deadlines); err != nil {
			return err
		}
		scopeEvents, err := persistIncidentScope(ctx, db, inc.ID, derivation.Scope)
		if err != nil {
			return err
		}
		if len(scopeEvents) > 0 {
			s.appendIncidentEvent(ctx, db, inc.ID, incidentSystemActor, "scope.changed", map[string]any{"changes": scopeEvents})
		}
		newPending, err := s.persistIncidentActions(ctx, db, inc.ID, derivation.Actions)
		if err != nil {
			return err
		}
		s.proposeWithdrawalIfRejected(ctx, q, inc)

		due := incident.NextDue(deadlines, metSteps, derivation.Actions)
		dueAt := sql.NullTime{}
		if due != nil {
			dueAt = sql.NullTime{Time: *due, Valid: true}
		}
		if err := db.SetIncidentDueAt(ctx, dbgen.SetIncidentDueAtParams{ID: inc.ID, DueAt: dueAt}); err != nil {
			return err
		}

		actions, err := db.ListIncidentActions(ctx, inc.ID)
		if err != nil {
			return err
		}
		statuses := make([]incident.ActionStatus, 0, len(actions))
		for _, action := range actions {
			statuses = append(statuses, incident.ActionStatus{State: action.State, Obsolete: action.Obsolete, Optional: action.Optional})
		}

		switch {
		case inc.State == dbgen.IncidentStateClosed && len(newPending) > 0:
			reopened, err := db.UpdateIncidentState(ctx, dbgen.UpdateIncidentStateParams{ID: inc.ID, State: dbgen.IncidentState(effectiveState), ClosedAt: sql.NullTime{}})
			if err != nil {
				return err
			}
			s.appendIncidentEvent(ctx, db, inc.ID, incidentSystemActor, "reopened", map[string]any{"new_actions": newPending})
			result = reopened
			publish = append(publish, func() {
				s.publishIncidentEvent(context.WithoutCancel(ctx), events.IncidentReopened, reopened, fmt.Sprintf("Incident #%d reopened: %s", reopened.Number, reopened.Title), "New actions: "+strings.Join(newPending, "; "))
			})
		case incident.Open(string(inc.State)) && incident.ReadyToClose(string(inc.State), inc.Regimes, statuses):
			closed, err := db.UpdateIncidentState(ctx, dbgen.UpdateIncidentStateParams{ID: inc.ID, State: dbgen.IncidentStateClosed, ClosedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}})
			if err != nil {
				return err
			}
			s.appendIncidentEvent(ctx, db, inc.ID, incidentSystemActor, "closed", map[string]any{"satisfied_by": closureSummary(actions)})
			result = closed
			publish = append(publish, func() {
				s.publishIncidentEvent(context.WithoutCancel(ctx), events.IncidentClosed, closed, fmt.Sprintf("Incident #%d closed: %s", closed.Number, closed.Title), "Every required action is done or waived.")
			})
		default:
			if refreshed, err := db.GetIncident(ctx, inc.ID); err == nil {
				result = refreshed
			}
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	for _, fn := range publish {
		fn()
	}
	s.queueTrackerSync(id)
	return result, nil
}

// closureSummary lists what satisfied each action, for the closing event.
func closureSummary(actions []dbgen.IncidentAction) []map[string]any {
	out := []map[string]any{}
	for _, action := range actions {
		if action.Obsolete {
			continue
		}
		entry := map[string]any{"kind": action.Kind, "label": action.Label, "state": action.State}
		if action.State == "waived" && action.WaivedReason.Valid {
			entry["waived_reason"] = action.WaivedReason.String
		}
		if len(action.Evidence) > 0 && string(action.Evidence) != "{}" {
			entry["evidence"] = action.Evidence
		}
		out = append(out, entry)
	}
	return out
}

// incidentDeadlines computes the clocks from the incident's anchors and
// returns which filings and steps are already met.
func (s *Server) incidentDeadlines(inc dbgen.Incident, rows []dbgen.IncidentDeadline, settings incidentSettings) ([]incident.Deadline, map[string]bool, map[string]bool) {
	metSteps := map[string]bool{}
	var notificationMet *time.Time
	for _, row := range rows {
		if !row.MetAt.Valid {
			continue
		}
		metSteps[row.Regime+"/"+row.Step] = true
		if row.Step == incident.StepNotification && row.Regime != incident.RegimeInternal {
			met := row.MetAt.Time
			notificationMet = &met
		}
	}
	anchors := incident.Anchors{Signal: inc.SignalAt, NotificationMet: notificationMet}
	if inc.AwareAt.Valid {
		aware := inc.AwareAt.Time
		anchors.Aware = &aware
	}
	if inc.FixAvailableAt.Valid {
		fix := inc.FixAvailableAt.Time
		anchors.FixAvailable = &fix
	}
	target := time.Duration(0)
	if inc.TargetSeconds.Valid {
		target = time.Duration(inc.TargetSeconds.Int64) * time.Second
	}
	regimes := inc.Regimes
	if !incident.Decided(string(inc.State)) && inc.State != dbgen.IncidentStateClosed {
		// Clocks start at T0: before a decision only the internal target runs.
		regimes = []string{incident.RegimeInternal}
	}
	deadlines := incident.ComputeDeadlines(inc.Kind, regimes, anchors, settings.National, settings.InternalTargets, target)
	metFilings := map[string]bool{}
	for _, deadline := range deadlines {
		if deadline.Filing != "" && metSteps[deadline.Regime+"/"+deadline.Step] {
			metFilings[deadline.Filing] = true
		}
	}
	return deadlines, metFilings, metSteps
}

func persistIncidentDeadlines(ctx context.Context, db *dbgen.Queries, incidentID uuid.UUID, deadlines []incident.Deadline) error {
	// Rows are updated in place, not rewritten: rewriting them reset the
	// notified marker, so every reconcile re-sent the due-soon warning.
	existing, err := db.ListIncidentDeadlines(ctx, incidentID)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, deadline := range deadlines {
		if deadline.Pending {
			continue
		}
		keep[deadline.Regime+"/"+deadline.Step] = true
		if err := db.UpsertIncidentDeadline(ctx, dbgen.UpsertIncidentDeadlineParams{
			IncidentID: incidentID, Regime: deadline.Regime, Step: deadline.Step, DueAt: deadline.DueAt,
		}); err != nil {
			return err
		}
	}
	for _, row := range existing {
		if row.MetAt.Valid || keep[row.Regime+"/"+row.Step] {
			continue
		}
		if err := db.DeleteIncidentDeadline(ctx, dbgen.DeleteIncidentDeadlineParams{IncidentID: incidentID, Regime: row.Regime, Step: row.Step}); err != nil {
			return err
		}
	}
	return nil
}

// persistIncidentScope writes derived rows, drops derived rows that no longer
// derive, and keeps rows a person entered or decided. It returns the changes
// worth a timeline entry.
func persistIncidentScope(ctx context.Context, db *dbgen.Queries, incidentID uuid.UUID, rows []incident.ScopeRow) ([]string, error) {
	existing, err := db.ListIncidentScope(ctx, incidentID)
	if err != nil {
		return nil, err
	}
	before := map[string]dbgen.IncidentScope{}
	for _, row := range existing {
		before[row.SubjectType+"/"+row.SubjectID] = row
	}
	changes := []string{}
	derived := map[string]bool{}
	for _, row := range rows {
		key := row.SubjectType + "/" + row.SubjectID
		derived[key] = true
		if previous, ok := before[key]; !ok {
			changes = append(changes, fmt.Sprintf("%s %s added (%s)", row.SubjectType, row.Label, row.Status))
		} else if previous.Status != row.Status && !previous.Manual {
			changes = append(changes, fmt.Sprintf("%s %s: %s → %s", row.SubjectType, row.Label, previous.Status, row.Status))
		}
		if err := db.UpsertIncidentScopeRow(ctx, scopeRowParams(incidentID, row, false)); err != nil {
			return nil, err
		}
	}
	for key, row := range before {
		if derived[key] || row.Manual {
			continue
		}
		if err := db.DeleteIncidentScopeRow(ctx, dbgen.DeleteIncidentScopeRowParams{IncidentID: incidentID, SubjectType: row.SubjectType, SubjectID: row.SubjectID}); err != nil {
			return nil, err
		}
		changes = append(changes, fmt.Sprintf("%s %s removed", row.SubjectType, row.Label))
	}
	sort.Strings(changes)
	return changes, nil
}

// persistIncidentActions upserts derived actions, completes the ones the facts
// satisfy, reopens automatic ones the facts no longer satisfy, and marks the
// rest obsolete. It returns the labels of required actions that are pending
// and were not pending before — what reopens a closed incident.
func (s *Server) persistIncidentActions(ctx context.Context, db *dbgen.Queries, incidentID uuid.UUID, specs []incident.ActionSpec) ([]string, error) {
	existing, err := db.ListIncidentActions(ctx, incidentID)
	if err != nil {
		return nil, err
	}
	before := map[string]dbgen.IncidentAction{}
	for _, action := range existing {
		before[action.Kind+"|"+action.SubjectType+"|"+action.SubjectID] = action
	}
	keep := make([]uuid.UUID, 0, len(specs))
	newPending := []string{}
	for _, spec := range specs {
		dueAt := sql.NullTime{}
		if spec.DueAt != nil {
			dueAt = sql.NullTime{Time: *spec.DueAt, Valid: true}
		}
		row, err := db.UpsertIncidentAction(ctx, dbgen.UpsertIncidentActionParams{
			IncidentID: incidentID, Kind: spec.Kind, SubjectType: spec.SubjectType, SubjectID: spec.SubjectID,
			Label: spec.Label, Automatic: spec.Automatic, Optional: spec.Optional, DueAt: dueAt,
		})
		if err != nil {
			return nil, err
		}
		keep = append(keep, row.ID)
		previous, existed := before[spec.Kind+"|"+spec.SubjectType+"|"+spec.SubjectID]
		switch {
		case spec.Satisfied && row.State == "pending":
			evidence, _ := json.Marshal(spec.Evidence)
			if len(spec.Evidence) == 0 {
				evidence = []byte(`{"source":"derived"}`)
			}
			if _, err := db.CompleteIncidentAction(ctx, dbgen.CompleteIncidentActionParams{ID: row.ID, IncidentID: incidentID, Evidence: evidence}); err != nil {
				return nil, err
			}
			s.appendIncidentEvent(ctx, db, incidentID, incidentSystemActor, "action.completed", map[string]any{"action_id": row.ID, "kind": row.Kind, "label": row.Label, "evidence": json.RawMessage(evidence)})
		case !spec.Satisfied && spec.Automatic && row.State == "done" && !row.DoneBy.Valid:
			if _, err := db.ReopenIncidentAction(ctx, dbgen.ReopenIncidentActionParams{ID: row.ID, IncidentID: incidentID}); err != nil {
				return nil, err
			}
			s.appendIncidentEvent(ctx, db, incidentID, incidentSystemActor, "action.reopened", map[string]any{"action_id": row.ID, "kind": row.Kind, "label": row.Label})
			if !spec.Optional {
				newPending = append(newPending, row.Label)
			}
		case !spec.Satisfied && row.State == "pending" && !spec.Optional && (!existed || previous.Obsolete):
			newPending = append(newPending, row.Label)
		}
	}
	if err := db.MarkIncidentActionsObsolete(ctx, dbgen.MarkIncidentActionsObsoleteParams{IncidentID: incidentID, KeepIds: keep}); err != nil {
		return nil, err
	}
	return newPending, nil
}

// gatherIncidentFacts reads what derivation needs for one incident.
func (s *Server) gatherIncidentFacts(ctx context.Context, q *store.Queries, inc dbgen.Incident, state string, settings incidentSettings) (incident.Facts, error) {
	db := q.Incidents()
	facts := incident.Facts{
		Kind: inc.Kind, State: state, Regimes: inc.Regimes,
		Settings: incident.Settings{RequireVEXApproval: settings.Row.RequireVexApproval, RequireAcknowledgement: settings.Row.RequireAcknowledgement},
	}
	if inc.DecisionStep.Valid {
		facts.DecisionStep = inc.DecisionStep.String
	}
	scopeRows, err := db.ListIncidentScope(ctx, inc.ID)
	if err != nil {
		return facts, err
	}
	facts.ManualScope = map[string]incident.ScopeRow{}
	for _, row := range scopeRows {
		if !row.Manual {
			continue
		}
		facts.ManualScope[row.SubjectType+"/"+row.SubjectID] = incident.ScopeRow{
			SubjectType: row.SubjectType, SubjectID: row.SubjectID, Label: row.Label, Status: row.Status, Reason: row.Reason,
			ComponentPURL: row.ComponentPurl, Manual: true,
		}
	}
	deliveries, err := db.ListIncidentDeliveries(ctx, inc.ID)
	if err != nil {
		return facts, err
	}
	for _, delivery := range deliveries {
		if delivery.ClientID.Valid {
			facts.Deliveries = append(facts.Deliveries, incident.DeliveryFact{ClientID: delivery.ClientID.UUID.String(), Status: delivery.Status})
		}
	}

	var releases []dbgen.ListReleasesWithClientsByRepoRow
	if inc.RepoID.Valid {
		releases, err = db.ListReleasesWithClientsByRepo(ctx, inc.RepoID.UUID)
		if err != nil {
			return facts, err
		}
	}

	switch inc.Kind {
	case incident.KindExploitedVulnerability:
		if err := s.gatherExploitedFacts(ctx, q, inc, releases, &facts); err != nil {
			return facts, err
		}
	case incident.KindSevereIncident:
		facts.Releases = releaseFacts(releases, nil)
	case incident.KindSecretLeak, incident.KindMalware, incident.KindPolicyBreach:
		if err := s.gatherFindingFacts(ctx, q, inc, releases, &facts); err != nil {
			return facts, err
		}
	}

	clientIDs := map[uuid.UUID]bool{}
	for _, release := range facts.Releases {
		for _, id := range release.ClientIDs {
			if parsed, err := uuid.Parse(id); err == nil {
				clientIDs[parsed] = true
			}
		}
	}
	for _, row := range facts.ManualScope {
		if row.SubjectType == incident.ScopeClient {
			if parsed, err := uuid.Parse(row.SubjectID); err == nil {
				clientIDs[parsed] = true
			}
		}
	}
	if len(clientIDs) > 0 {
		ids := make([]uuid.UUID, 0, len(clientIDs))
		for id := range clientIDs {
			ids = append(ids, id)
		}
		clients, err := db.ListClientsByIDs(ctx, ids)
		if err != nil {
			return facts, err
		}
		facts.ClientNames = map[string]string{}
		for _, client := range clients {
			facts.ClientNames[client.ID.String()] = client.Name
		}
	}
	return facts, nil
}

func releaseFacts(rows []dbgen.ListReleasesWithClientsByRepoRow, match func(row dbgen.ListReleasesWithClientsByRepoRow) (bool, string, string)) []incident.ReleaseFact {
	out := make([]incident.ReleaseFact, 0, len(rows))
	for _, row := range rows {
		fact := incident.ReleaseFact{ID: row.ID.String(), Version: row.Version, HasSnapshot: row.SnapshotID.Valid, CreatedAt: row.CreatedAt}
		for _, id := range row.ClientIds {
			fact.ClientIDs = append(fact.ClientIDs, id.String())
		}
		if match != nil {
			fact.Matched, fact.ComponentPURL, fact.Reachability = match(row)
		}
		out = append(out, fact)
	}
	return out
}

func (s *Server) gatherExploitedFacts(ctx context.Context, q *store.Queries, inc dbgen.Incident, releases []dbgen.ListReleasesWithClientsByRepoRow, facts *incident.Facts) error {
	db := q.Incidents()
	advisoryID, err := uuid.Parse(inc.SubjectID)
	if err != nil || !inc.RepoID.Valid {
		facts.Releases = releaseFacts(releases, nil)
		return nil
	}
	firstParty, fpErr := db.GetFirstPartyAdvisory(ctx, dbgen.GetFirstPartyAdvisoryParams{RepoID: inc.RepoID.UUID, AdvisoryID: advisoryID})
	isFirstParty := fpErr == nil
	facts.ComponentAdvisory = !isFirstParty
	facts.AdvisoryPublic = s.advisoryIsPublic(ctx, advisoryID)

	if isFirstParty {
		versRange, err := incident.ParseVers(firstParty.AffectedRange)
		facts.Releases = releaseFacts(releases, func(row dbgen.ListReleasesWithClientsByRepoRow) (bool, string, string) {
			return err == nil && versRange.Contains(row.Version), "", ""
		})
	} else {
		snapshotIDs := []uuid.UUID{}
		for _, row := range releases {
			if row.SnapshotID.Valid {
				snapshotIDs = append(snapshotIDs, row.SnapshotID.UUID)
			}
		}
		type match struct{ purl, reachability string }
		matches := map[uuid.UUID]match{}
		if len(snapshotIDs) > 0 {
			rows, err := db.ListAdvisoryMatchesInSnapshots(ctx, dbgen.ListAdvisoryMatchesInSnapshotsParams{SnapshotIds: snapshotIDs, AdvisoryID: uuid.NullUUID{UUID: advisoryID, Valid: true}})
			if err != nil {
				return err
			}
			for _, row := range rows {
				current := matches[row.SnapshotID]
				// A reachable verdict anywhere in the release wins over unreachable.
				if current.purl == "" || row.Reachability == "reachable" {
					matches[row.SnapshotID] = match{purl: row.ComponentPurl, reachability: row.Reachability}
				}
			}
		}
		facts.Releases = releaseFacts(releases, func(row dbgen.ListReleasesWithClientsByRepoRow) (bool, string, string) {
			if !row.SnapshotID.Valid {
				return false, "", ""
			}
			found, ok := matches[row.SnapshotID.UUID]
			return ok, found.purl, found.reachability
		})
	}

	statements, err := q.ListVEXStatementsForAdvisoryRepo(ctx, inc.OrgID, advisoryID, inc.RepoID.UUID)
	if err != nil {
		return err
	}
	for _, statement := range statements {
		fact := incident.StatementFact{
			ID: statement.ID.String(), Status: string(statement.Status), Approved: statement.ApprovedBy.Valid,
			Repo: statement.RepoID.Valid, CreatedAt: statement.CreatedAt,
		}
		if statement.Justification.Valid {
			fact.Justification = string(statement.Justification.VexJustification)
		}
		if statement.ReleaseID.Valid {
			fact.ReleaseID = statement.ReleaseID.UUID.String()
		}
		if statement.VersionRange.Valid {
			fact.VersionRange = statement.VersionRange.String
		}
		if statement.ComponentPurl.Valid {
			fact.ComponentPURL = statement.ComponentPurl.String
		}
		facts.Statements = append(facts.Statements, fact)
	}
	return nil
}

func (s *Server) gatherFindingFacts(ctx context.Context, q *store.Queries, inc dbgen.Incident, releases []dbgen.ListReleasesWithClientsByRepoRow, facts *incident.Facts) error {
	if !inc.RepoID.Valid || inc.SubjectID == "" {
		return nil
	}
	db := q.Incidents()
	fingerprint := inc.SubjectID
	refs, err := db.ListLatestSnapshotsForRepoRefs(ctx, inc.RepoID.UUID)
	if err != nil {
		return err
	}
	snapshotIDs := make([]uuid.UUID, 0, len(refs))
	for _, ref := range refs {
		snapshotIDs = append(snapshotIDs, ref.SnapshotID)
	}
	for _, row := range releases {
		if row.SnapshotID.Valid {
			snapshotIDs = append(snapshotIDs, row.SnapshotID.UUID)
		}
	}
	present := map[uuid.UUID]bool{}
	if len(snapshotIDs) > 0 {
		hits, err := db.ListFingerprintPresenceInSnapshots(ctx, dbgen.ListFingerprintPresenceInSnapshotsParams{SnapshotIds: snapshotIDs, Fingerprint: fingerprint})
		if err != nil {
			return err
		}
		for _, id := range hits {
			present[id] = true
		}
	}
	for _, ref := range refs {
		if ref.RefType == "pull_request" && !present[ref.SnapshotID] {
			// Pull requests where it never appeared are noise in the scope.
			continue
		}
		facts.Refs = append(facts.Refs, incident.RefFact{Name: ref.RefName, Present: present[ref.SnapshotID]})
	}
	if inc.Kind == incident.KindMalware {
		facts.Releases = releaseFacts(releases, func(row dbgen.ListReleasesWithClientsByRepoRow) (bool, string, string) {
			return row.SnapshotID.Valid && present[row.SnapshotID.UUID], "", ""
		})
	}

	finding := &incident.FindingFact{}
	if latest, err := q.GetLatestVulnerabilityByFingerprint(ctx, inc.RepoID.UUID, fingerprint); err == nil && latest != nil {
		finding.Status = latest.Status
		if latest.Type == "secret" {
			finding.ValidatorDead = secretValidatorDead(latest.Metadata)
			finding.Revoked = latest.Status == "resolved"
		}
	}
	if acceptance, err := q.GetActiveFindingAcceptance(ctx, inc.RepoID.UUID, fingerprint); err == nil && acceptance != nil {
		finding.Accepted = true
	}
	if attestation, err := db.GetLatestSecretAttestation(ctx, dbgen.GetLatestSecretAttestationParams{RepoID: inc.RepoID.UUID, Fingerprint: fingerprint}); err == nil {
		finding.Revoked = finding.Revoked || attestation.Revoked
		finding.Rotated = attestation.Rotation != ""
		finding.ExposureDone = attestation.Exposure != ""
		finding.OwnerExternal = attestation.OwnerExternal
	}
	facts.Finding = finding
	return nil
}

// secretValidatorDead reads a validator verdict out of a secret finding's
// metadata: the credential was checked against its service and is dead.
// Transient verdicts (unknown, errors, rate limits) never count.
func secretValidatorDead(metadata json.RawMessage) bool {
	if len(metadata) == 0 {
		return false
	}
	var raw map[string]any
	if json.Unmarshal(metadata, &raw) != nil {
		return false
	}
	var walk func(map[string]any) bool
	walk = func(values map[string]any) bool {
		for key, value := range values {
			switch typed := value.(type) {
			case string:
				normalized := strings.ToLower(strings.ReplaceAll(key, "_", ""))
				if normalized == "validationstatus" || normalized == "validation" {
					status := strings.ToLower(strings.TrimSpace(typed))
					if status == "invalid" || status == "revoked" {
						return true
					}
				}
			case map[string]any:
				if walk(typed) {
					return true
				}
			}
		}
		return false
	}
	return walk(raw)
}

func (s *Server) publishIncidentEvent(ctx context.Context, eventType events.Type, inc dbgen.Incident, title, message string) {
	if s.bus == nil {
		return
	}
	severity := "high"
	switch inc.Priority {
	case "P1":
		severity = "critical"
	case "P3":
		severity = "medium"
	}
	if eventType == events.IncidentClosed {
		severity = "info"
	}
	payload := map[string]any{
		"org_id":      inc.OrgID.String(),
		"incident_id": inc.ID.String(),
		"number":      inc.Number,
		"kind":        inc.Kind,
		"title":       title,
		"message":     message,
		"severity":    severity,
		"link":        s.incidentLink(ctx, inc),
	}
	if inc.RepoID.Valid {
		payload["repo_id"] = inc.RepoID.UUID.String()
	}
	s.bus.Publish(ctx, events.Event{Type: eventType, Payload: payload, Timestamp: time.Now().UTC()})
}

func (s *Server) incidentLink(ctx context.Context, inc dbgen.Incident) string {
	org, err := s.queries.GetOrganizationByID(ctx, inc.OrgID)
	if err != nil || org == nil {
		return ""
	}
	return fmt.Sprintf("/orgs/%s/%s/incidents/%d", org.Provider, org.Slug, inc.Number)
}

// writeSystemAuditLog records an incident mutation that may run outside a
// request (rules, the worker).
func (s *Server) writeSystemAuditLog(ctx context.Context, actor incidentActor, orgID uuid.UUID, action, resourceID string, context map[string]any) {
	body, err := json.Marshal(context)
	if err != nil {
		body = []byte(`{}`)
	}
	actorType := actor.Type
	if actorType == "" {
		actorType = audit.ActorSystem
	}
	if _, err := s.queries.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorID: actor.ID, ActorType: actorType, ActorDisplay: actor.Display, Action: action,
		ResourceType: "incident", ResourceID: resourceID, OrgID: orgAuditID(orgID), Context: body,
	}); err != nil {
		s.log.Warn().Err(err).Str("action", action).Msg("audit log write failed; the action itself succeeded")
	}
}

// incidentWork is the in-process reconcile queue: triggers (statements,
// deployments, catalogue movements) enqueue incident ids, a worker drains
// them. Reconciling is idempotent and locked per incident, so a lost entry is
// repaired by the periodic sweep and a duplicate costs one recomputation.
type incidentWork struct {
	mu      sync.Mutex
	pending map[uuid.UUID]struct{}
	tracker map[uuid.UUID]struct{}
	signal  chan struct{}
}

var incidentQueueOnce sync.Map // *Server → *incidentWork

func (s *Server) incidentQueue() *incidentWork {
	if value, ok := incidentQueueOnce.Load(s); ok {
		return value.(*incidentWork)
	}
	work := &incidentWork{pending: map[uuid.UUID]struct{}{}, tracker: map[uuid.UUID]struct{}{}, signal: make(chan struct{}, 1)}
	actual, _ := incidentQueueOnce.LoadOrStore(s, work)
	return actual.(*incidentWork)
}

func (w *incidentWork) push(target map[uuid.UUID]struct{}, ids ...uuid.UUID) {
	w.mu.Lock()
	for _, id := range ids {
		target[id] = struct{}{}
	}
	w.mu.Unlock()
	select {
	case w.signal <- struct{}{}:
	default:
	}
}

func (w *incidentWork) drain() ([]uuid.UUID, []uuid.UUID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	reconcile := make([]uuid.UUID, 0, len(w.pending))
	for id := range w.pending {
		reconcile = append(reconcile, id)
	}
	tracker := make([]uuid.UUID, 0, len(w.tracker))
	for id := range w.tracker {
		tracker = append(tracker, id)
	}
	w.pending = map[uuid.UUID]struct{}{}
	w.tracker = map[uuid.UUID]struct{}{}
	return reconcile, tracker
}

func (s *Server) queueIncidentReconcile(ids ...uuid.UUID) {
	if len(ids) == 0 {
		return
	}
	work := s.incidentQueue()
	work.push(work.pending, ids...)
}

func (s *Server) queueTrackerSync(ids ...uuid.UUID) {
	work := s.incidentQueue()
	work.push(work.tracker, ids...)
}

// queueIncidentReconcileForAdvisory enqueues the incidents about an advisory:
// a statement changed, so scopes and vex actions may move.
func (s *Server) queueIncidentReconcileForAdvisory(ctx context.Context, orgID, advisoryID uuid.UUID) {
	if s.queries == nil {
		return
	}
	rows, err := s.queries.Incidents().ListOpenIncidentsBySubject(ctx, dbgen.ListOpenIncidentsBySubjectParams{
		OrgID: orgID, SubjectType: incident.SubjectAdvisory, SubjectIds: []string{advisoryID.String()},
	})
	if err != nil {
		return
	}
	for _, row := range rows {
		s.queueIncidentReconcile(row.ID)
	}
}

// queueIncidentReconcileForRepo enqueues a repository's open incidents and its
// closed exploited-vulnerability incidents, which a new release or deployment
// can reopen.
func (s *Server) queueIncidentReconcileForRepo(ctx context.Context, repoID uuid.UUID) {
	if s.queries == nil {
		return
	}
	db := s.queries.Incidents()
	open, err := db.ListOpenIncidentIDsForRepo(ctx, uuid.NullUUID{UUID: repoID, Valid: true})
	if err == nil {
		s.queueIncidentReconcile(open...)
	}
	closed, err := db.ListReopenableIncidentIDsForRepo(ctx, uuid.NullUUID{UUID: repoID, Valid: true})
	if err == nil {
		s.queueIncidentReconcile(closed...)
	}
}

// runIncidentWorker drains the reconcile and tracker queues.
func (s *Server) runIncidentWorker(ctx context.Context) {
	work := s.incidentQueue()
	for {
		select {
		case <-ctx.Done():
			return
		case <-work.signal:
		}
		reconcile, tracker := work.drain()
		for _, id := range reconcile {
			runCtx, cancel := context.WithTimeout(ctx, time.Minute)
			reconciled, err := s.reconcileIncident(runCtx, id)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				s.log.Warn().Err(err).Str("incident_id", id.String()).Msg("incident reconcile failed")
			}
			if err == nil {
				// Two identifiers for one vulnerability fold into one incident (§3).
				s.mergeAliasSiblings(runCtx, reconciled)
			}
			cancel()
		}
		for _, id := range tracker {
			runCtx, cancel := context.WithTimeout(ctx, time.Minute)
			s.syncIncidentTrackers(runCtx, id)
			cancel()
		}
	}
}

// proposeWithdrawalIfRejected records, once, that the advisory an incident is
// about was withdrawn or rejected upstream (§3): a person decides whether to
// withdraw the incident, since what was already sent stays valid as sent.
func (s *Server) proposeWithdrawalIfRejected(ctx context.Context, q *store.Queries, inc dbgen.Incident) {
	if inc.SubjectType != incident.SubjectAdvisory || !incident.Open(string(inc.State)) {
		return
	}
	advisoryID, err := uuid.Parse(inc.SubjectID)
	if err != nil {
		return
	}
	advisories, err := q.GetAdvisoriesByIDs(ctx, []uuid.UUID{advisoryID})
	if err != nil || len(advisories) != 1 || !advisories[0].WithdrawnAt.Valid {
		return
	}
	events, err := q.Incidents().ListIncidentEvents(ctx, inc.ID)
	if err != nil {
		return
	}
	for _, event := range events {
		if event.Kind == "withdrawal.proposed" {
			return
		}
	}
	s.appendIncidentEvent(ctx, q.Incidents(), inc.ID, incidentSystemActor, "withdrawal.proposed", map[string]any{
		"reason":       "the advisory was withdrawn upstream; withdraw the incident if it no longer applies",
		"withdrawn_at": advisories[0].WithdrawnAt.Time,
	})
}

// advisoryIsPublic: the advisory has a public identifier (CVE, GHSA, an
// ecosystem database id), so its maintainer is deemed aware of it (guidance
// C(2026) 5252 §223).
func (s *Server) advisoryIsPublic(ctx context.Context, advisoryID uuid.UUID) bool {
	ids := s.advisoryAliases(ctx, advisoryID)
	if advisory, err := s.queries.GetAdvisoryByID(ctx, advisoryID); err == nil {
		ids = append(ids, advisory.CanonicalID)
	}
	for _, id := range ids {
		upper := strings.ToUpper(id)
		for _, prefix := range []string{"CVE-", "GHSA-", "GO-", "PYSEC-", "RUSTSEC-", "OSV-", "EUVD-"} {
			if strings.HasPrefix(upper, prefix) {
				return true
			}
		}
	}
	return false
}

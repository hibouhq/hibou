package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// A finding's timeline has two sources that must stay distinguishable: what the
// scanners observed (derived from the snapshot series) and what a human or a
// token decided (the audit log). Both are capped so one long-lived finding on a
// busy repository cannot return an unbounded response.
const (
	maxFindingScanEvents     = 100
	maxFindingActivityEvents = 100
	maxFindingAdvisoryEvents = 100
)

// findingActivityActions is the closed set of audit actions this endpoint may
// surface. It exists because the endpoint is NOT the org audit log: that one is
// admin-only precisely because its entries carry member changes, token
// provenance and settings diffs. Here anyone who can read the repository's
// findings can read the history of ONE finding, so only actions that are about
// a finding are eligible — and the query additionally binds org, repository and
// fingerprint, so an entry from another repo or another finding cannot appear
// even if it carried one of these actions.
var findingActivityActions = []string{
	audit.ActionFindingAcceptance,
	audit.ActionFindingCreate,
	audit.ActionFindingCWEs,
	audit.ActionFindingDispute,
	audit.ActionSecretRevoked,
	// ADR-034 §4: decisions on manual and agent findings.
	audit.ActionFindingReassert,
	audit.ActionFindingRetract,
	audit.ActionFindingResolve,
	// Triage copied to a re-keyed fingerprint (ADR-034, D15).
	audit.ActionFindingRekeyed,
}

// findingActivityContextKeys is the allowlist projected out of an audit entry's
// context. Everything else is dropped, including the ADR-020 token provenance
// (token_id, token_owner_id, acting_user_id) and the request's IP and user
// agent, which the org-wide log shows to admins only. Adding a key here widens
// what a plain member can read — do it deliberately.
var findingActivityContextKeys = []string{
	"status",
	"cwes",
	"reason",
	"reason_kind",
	"labels",
	"expires_at",
	"vex_justification",
	"comment",
	"severity",
	"origin",
}

// findingHistoryEvent is one entry of the merged timeline. Source separates the
// two origins; Kind is the display verb.
type findingHistoryEvent struct {
	// Source is "scan" (observed by a scanner) or "activity" (decided by a
	// human or a token).
	Source string    `json:"source"`
	Kind   string    `json:"kind"`
	At     time.Time `json:"at"`

	// Scan events: where the change was observed.
	RefName   string `json:"ref_name,omitempty"`
	RefType   string `json:"ref_type,omitempty"`
	CommitSHA string `json:"commit_sha,omitempty"`
	Severity  string `json:"severity,omitempty"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`

	// Activity events: who did what. Detail is also set on a scan-observed
	// suppression, carrying the in-source justification as its comment.
	Action       string         `json:"action,omitempty"`
	ActorType    string         `json:"actor_type,omitempty"`
	ActorDisplay string         `json:"actor_display,omitempty"`
	Detail       map[string]any `json:"detail,omitempty"`
}

type findingHistoryResponse struct {
	Events []findingHistoryEvent `json:"events"`
	// Truncated says a cap was hit, so the UI never implies the timeline is
	// complete when it is not.
	Truncated bool `json:"truncated"`
}

// @Summary      Finding history
// @Description  The timeline of one finding: every scan-observed state change (detected, resolved, reintroduced) merged with the triage decisions recorded against its fingerprint. Readable by anyone who can read the repository's findings — unlike the organization audit log, which is admin-only; entries are restricted to finding actions on this repository and this fingerprint, and their context is projected to triage fields.
// @Tags         vulnerabilities
// @Produce      json
// @Param        provider     path  string  true  "Forge provider"
// @Param        slug         path  string  true  "Organization slug"
// @Param        repoSlug     path  string  true  "Repository slug"
// @Param        fingerprint  path  string  true  "Finding fingerprint"
// @Success      200  {object}  api.Response{data=server.findingHistoryResponse}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/findings/{fingerprint}/history [get]
func (s *Server) handleGetFindingHistory(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	fingerprint := pathFingerprint(r)
	if fingerprint == "" {
		api.JSONError(w, http.StatusBadRequest, "fingerprint is required")
		return
	}

	// The fingerprint must exist on this repository. Without this the endpoint
	// would answer "no events" for a foreign fingerprint the caller has no
	// business asking about, and 404 for one that never existed — a difference
	// worth not leaking.
	finding, err := s.queries.GetLatestVulnerabilityByFingerprint(r.Context(), repo.ID, fingerprint)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding")
		return
	}
	if finding == nil {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return
	}

	response := findingHistoryResponse{Events: []findingHistoryEvent{}}

	// The creation point is the one date a reader always wants, so it is read
	// separately and anchored to the bottom of the timeline: capping the
	// transition list must never be able to cut off "when did this appear".
	first, err := s.queries.GetFindingFirstObservation(r.Context(), repo.ID, fingerprint)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding history")
		return
	}

	transitions, err := s.queries.ListFindingTransitions(r.Context(), repo.ID, fingerprint, maxFindingScanEvents+1)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding history")
		return
	}
	if len(transitions) > maxFindingScanEvents {
		transitions = transitions[:maxFindingScanEvents]
		response.Truncated = true
	}
	anchored := false
	for _, transition := range transitions {
		event := scanHistoryEvent(transition)
		// The oldest detection on the ref the finding was born on IS the
		// creation point; promote it instead of repeating it underneath.
		if !anchored && first != nil && event.Kind == "detected" && event.RefName == first.RefName && event.CommitSHA == first.CommitSHA {
			event.Kind = "first_detected"
			event.At = first.ObservedAt
			anchored = true
		}
		response.Events = append(response.Events, event)
	}
	if first != nil && !anchored {
		anchor := scanHistoryEvent(*first)
		anchor.Kind = "first_detected"
		anchor.From = ""
		response.Events = append(response.Events, anchor)
	}

	// ADR-034: a resolution has no row in the snapshot that resolved it, so
	// the scan series alone cannot show it; finding_resolutions holds the
	// evidence ("Resolved in e4f5a6b", "No longer reported by gosec 2.29").
	resolutions, err := s.queries.ListFindingResolutions(r.Context(), repo.ID, fingerprint, maxFindingScanEvents+1)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding history")
		return
	}
	if len(resolutions) > maxFindingScanEvents {
		resolutions = resolutions[:maxFindingScanEvents]
		response.Truncated = true
	}
	for _, resolution := range resolutions {
		response.Events = append(response.Events, resolutionHistoryEvent(resolution))
	}

	entries, err := s.queries.ListFindingActivity(r.Context(), org.ID, repo.ID, fingerprint, findingActivityActions, maxFindingActivityEvents+1)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding history")
		return
	}
	if len(entries) > maxFindingActivityEvents {
		entries = entries[:maxFindingActivityEvents]
		response.Truncated = true
	}
	for _, entry := range entries {
		response.Events = append(response.Events, activityHistoryEvent(entry))
	}

	identifiers, err := s.findingKEVIdentifiers(r.Context(), finding)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding history")
		return
	}
	advisoryEvents, err := s.queries.ListKEVAdvisoryEventsForCVEs(r.Context(), identifiers, maxFindingAdvisoryEvents+1)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding history")
		return
	}
	if len(advisoryEvents) > maxFindingAdvisoryEvents {
		advisoryEvents = advisoryEvents[:maxFindingAdvisoryEvents]
		response.Truncated = true
	}
	listed := make(map[string]struct{}, len(advisoryEvents))
	seen := make(map[string]struct{}, len(advisoryEvents))
	for _, entry := range advisoryEvents {
		event := advisoryHistoryEvent(entry)
		source, _ := event.Detail["source"].(string)
		key := event.Kind + "\x00" + source + "\x00" + entry.CveID + "\x00" + event.At.UTC().Format(time.RFC3339Nano)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		response.Events = append(response.Events, event)
		if event.Kind == string(store.EventKEVListed) {
			if source != "" {
				listed[source+"\x00"+entry.CveID] = struct{}{}
			}
		}
	}
	for _, entry := range advisoryEvents {
		if entry.Kind != string(store.EventKEVDelisted) {
			continue
		}
		event := advisoryHistoryEvent(entry)
		source, _ := event.Detail["source"].(string)
		dateAdded, _ := event.Detail["date_added"].(string)
		occurred, err := time.Parse("2006-01-02", dateAdded)
		if source == "" || err != nil {
			continue
		}
		key := source + "\x00" + entry.CveID
		if _, ok := listed[key]; ok {
			continue
		}
		listed[key] = struct{}{}
		response.Events = append(response.Events, findingHistoryEvent{
			Source: "advisory",
			Kind:   string(store.EventKEVListed),
			At:     occurred,
			Detail: map[string]any{"source": source},
		})
	}
	anchors, err := s.queries.ListKEVEntriesForIdentifiersLimited(r.Context(), identifiers, maxFindingAdvisoryEvents+1)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding history")
		return
	}
	if len(anchors) > maxFindingAdvisoryEvents {
		anchors = anchors[:maxFindingAdvisoryEvents]
		response.Truncated = true
	}
	for _, anchor := range anchors {
		if !anchor.DateAdded.Valid {
			continue
		}
		if _, ok := listed[anchor.Source+"\x00"+anchor.CveID]; ok {
			continue
		}
		response.Events = append(response.Events, findingHistoryEvent{
			Source: "advisory",
			Kind:   string(store.EventKEVListed),
			At:     anchor.DateAdded.Time,
			Detail: map[string]any{"source": anchor.Source},
		})
	}

	// Newest first, with activity ahead of the scan that observed its effect
	// when both land in the same instant.
	sort.SliceStable(response.Events, func(i, j int) bool {
		if response.Events[i].At.Equal(response.Events[j].At) {
			return response.Events[i].Source == "activity" && response.Events[j].Source != "activity"
		}
		return response.Events[i].At.After(response.Events[j].At)
	})

	api.JSON(w, http.StatusOK, response)
}

func (s *Server) findingKEVIdentifiers(ctx context.Context, finding *store.Vulnerability) ([]string, error) {
	if finding.AdvisoryID == nil {
		switch finding.Type {
		case "dependency", "container", "malware":
			if identifier := strings.ToUpper(strings.TrimSpace(finding.PrimaryIdentifierValue)); identifier != "" {
				return []string{identifier}, nil
			}
		}
		return nil, nil
	}
	advisory, err := s.queries.GetAdvisoryByID(ctx, *finding.AdvisoryID)
	if err != nil {
		return nil, err
	}
	aliases, err := s.queries.ListAliasesByAdvisoryIDs(ctx, []uuid.UUID{*finding.AdvisoryID})
	if err != nil {
		return nil, err
	}
	identifiers := make([]string, 0, len(aliases)+1)
	seen := make(map[string]struct{}, len(aliases)+1)
	for _, identifier := range append([]string{advisory.CanonicalID}, advisoryAliases(aliases)...) {
		identifier = strings.ToUpper(strings.TrimSpace(identifier))
		if identifier == "" {
			continue
		}
		if _, ok := seen[identifier]; ok {
			continue
		}
		seen[identifier] = struct{}{}
		identifiers = append(identifiers, identifier)
	}
	return identifiers, nil
}

func advisoryAliases(aliases []dbgen.AdvisoryAlias) []string {
	identifiers := make([]string, len(aliases))
	for index, alias := range aliases {
		identifiers[index] = alias.Alias
	}
	return identifiers
}

func scanHistoryEvent(transition store.FindingTransition) findingHistoryEvent {
	event := findingHistoryEvent{
		Source:    "scan",
		Kind:      scanEventKind(transition.PreviousStatus, transition.Status),
		At:        transition.ObservedAt,
		RefName:   transition.RefName,
		RefType:   transition.RefType,
		CommitSHA: transition.CommitSHA,
		Severity:  transition.Severity,
		From:      transition.PreviousStatus,
		To:        transition.Status,
	}
	// A row whose status did not change was selected for its reachability
	// verdict (the query's second arm): the call-graph analysis proved the
	// vulnerable symbol unreachable, or revealed it reachable again. From/To
	// carry the verdicts for these events, not the status.
	// A carried row (ADR-034): the producer did not re-check the finding on
	// this commit, or re-checked and reported it again after a gap.
	if transition.PreviousStatus == transition.Status && transition.PreviousPresence != "" && transition.Presence != transition.PreviousPresence {
		if transition.Presence == store.PresenceReported {
			event.Kind = "rechecked"
		} else {
			event.Kind = "not_rechecked"
			if transition.PresenceReason != "" {
				event.Detail = map[string]any{"reason": transition.PresenceReason, "reason_text": presence.ReasonText(transition.PresenceReason)}
			}
		}
		event.From = transition.PreviousPresence
		event.To = transition.Presence
		return event
	}
	if transition.PreviousStatus == transition.Status && transition.Reachability != "" {
		if transition.Reachability == "not_reachable" {
			event.Kind = "became_unreachable"
		} else {
			event.Kind = "became_reachable"
		}
		event.From = transition.PreviousReachability
		event.To = transition.Reachability
	}
	// A developer who suppresses in code (`#nosec G115 -- reason`) has written
	// the triage comment already; the scanner extracted it (SARIF
	// suppressions[].justification) and the ingest kept it. Surface it the way
	// a human decision's comment is surfaced, so the timeline reads the same
	// whether the call was made in the UI or in the source.
	if justification := strings.TrimSpace(transition.SuppressionJustification); justification != "" {
		event.Detail = map[string]any{"comment": justification}
	}
	return event
}

// resolutionHistoryEvent renders a recorded resolution (ADR-034 §3). Kind
// "resolved" for a fix or a removed file; "no_longer_reported" when the
// finding only stopped being reported (scanner change, repeated absence).
func resolutionHistoryEvent(resolution store.FindingResolution) findingHistoryEvent {
	kind := "resolved"
	if resolution.Reason == presence.ResolvedNoLongerReported || resolution.Reason == presence.ResolvedProducerChanged || resolution.Reason == presence.ResolvedProducerRetired {
		kind = "no_longer_reported"
	}
	detail := map[string]any{"reason": resolution.Reason, "producer": resolution.Producer}
	if resolution.ProducerVersion != "" {
		detail["producer_version"] = resolution.ProducerVersion
	}
	return findingHistoryEvent{
		Source:    "scan",
		Kind:      kind,
		At:        resolution.CreatedAt,
		RefName:   resolution.RefName,
		RefType:   resolution.RefType,
		CommitSHA: resolution.CommitSHA,
		To:        "resolved",
		Detail:    detail,
	}
}

// scanEventKind names the transition the way a reader thinks about it: the
// first sighting on a ref is "detected", a return after a fix is
// "reintroduced", and everything else is described by its destination.
func scanEventKind(previous, current string) string {
	switch {
	case previous == "":
		return "detected"
	case current == "resolved":
		return "resolved"
	case previous == "resolved":
		return "reintroduced"
	case current == "suppressed":
		return "suppressed"
	default:
		return "status_change"
	}
}

func activityHistoryEvent(entry store.FindingActivityEntry) findingHistoryEvent {
	detail := projectFindingActivityContext(entry.Context)
	status, _ := detail["status"].(string)
	return findingHistoryEvent{
		Source:       "activity",
		Kind:         activityEventKind(entry.Action, status),
		At:           entry.CreatedAt,
		Action:       entry.Action,
		ActorType:    entry.ActorType,
		ActorDisplay: entry.ActorDisplay,
		Detail:       detail,
	}
}

func advisoryHistoryEvent(entry dbgen.AdvisoryEvent) findingHistoryEvent {
	detail := map[string]any{}
	var stored map[string]any
	if json.Unmarshal(entry.Detail, &stored) == nil {
		if source, ok := stored["source"].(string); ok && strings.TrimSpace(source) != "" {
			detail["source"] = source
		}
	}
	if len(detail) == 0 {
		detail = nil
	}
	return findingHistoryEvent{
		Source: "advisory",
		Kind:   entry.Kind,
		At:     entry.OccurredAt,
		Detail: detail,
	}
}

// activityEventKind collapses (action, status) into one verb. The acceptance
// endpoint records its decision in the status field — "open" is a reopen — so
// the timeline reads as decisions rather than as endpoint names.
func activityEventKind(action, status string) string {
	switch action {
	case audit.ActionFindingCreate:
		return "reported"
	case audit.ActionSecretRevoked:
		return "revoked"
	case audit.ActionFindingCWEs:
		return "reclassified"
	case audit.ActionFindingReassert:
		return "reasserted"
	case audit.ActionFindingRetract:
		return "retracted"
	case audit.ActionFindingResolve:
		return "resolved_by_decision"
	case audit.ActionFindingRekeyed:
		return "rekeyed"
	case audit.ActionFindingDispute:
		if status == "undisputed" {
			return "dispute_withdrawn"
		}
		return "disputed"
	case audit.ActionFindingAcceptance:
		switch status {
		case "open":
			return "reopened"
		case "false_positive":
			return "false_positive"
		case "risk_accepted", "accepted":
			return "accepted"
		default:
			return "triaged"
		}
	default:
		return "triaged"
	}
}

// projectFindingActivityContext copies the allowlisted keys out of an audit
// entry's context and drops everything else. A malformed context yields no
// detail rather than an error: the event itself is still worth showing.
func projectFindingActivityContext(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var context map[string]any
	if err := json.Unmarshal(raw, &context); err != nil {
		return nil
	}
	detail := make(map[string]any, len(findingActivityContextKeys))
	for _, key := range findingActivityContextKeys {
		value, ok := context[key]
		if !ok || value == nil {
			continue
		}
		if text, isString := value.(string); isString && strings.TrimSpace(text) == "" {
			continue
		}
		detail[key] = value
	}
	if len(detail) == 0 {
		return nil
	}
	return detail
}

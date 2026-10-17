package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/cvetriage"
	"github.com/hibouhq/hibou/internal/provider/depsdev"
	"github.com/hibouhq/hibou/internal/store"
)

// Advisory activity: what moved since you last looked.
//
// The per-advisory timeline answers "what happened to this one". This answers
// the question somebody watching a queue actually has, and it has to carry both
// origins — a CVE triaged in July and revised by its CNA in August must show
// both, in order, or nobody can tell a corrected typo from a widened range.
//
// Roughly three quarters of what the feed carries is revision rather than
// arrival, so upstream activity is the common case here, not the exception.

type activityEvent struct {
	CVEID      string          `json:"cve_id"`
	Kind       string          `json:"kind"`
	External   bool            `json:"external"`
	OccurredAt string          `json:"occurred_at"`
	ObservedAt string          `json:"observed_at"`
	Detail     json.RawMessage `json:"detail"`
}

type activityResponse struct {
	Events []activityEvent `json:"events"`
	Health *FeedHealth     `json:"health"`
	// Without this an empty stream is ambiguous: nothing changed, or the corpus
	// is months stale.
	Corpus *corpusState `json:"corpus"`
	// KEV is the exploited-catalog sync state, one entry per source (ADR-032):
	// when each catalog last synced, how many entries it carries, and what has
	// been failing since when. Same reason health is here at all — "no
	// exploited findings" and "catalogs never synced" must not look alike.
	KEV *KEVHealth `json:"kev,omitempty"`
	// DepsDev is the package-signals sync state (ADR-048 §6): a live
	// provider has no catalog date, but it has a last pass, what it looked
	// up and what failed, and that is what tells "no signals" from "never
	// synced". Absent when the provider is switched off.
	DepsDev *depsdev.Health `json:"depsdev,omitempty"`
}

type corpusState struct {
	Commit string `json:"commit"`
	// The commit's own date, not when the seed ran.
	CommittedAt string `json:"committed_at,omitempty"`
}

func (s *Server) handleAdvisoryEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthenticated(w, r) {
		return
	}
	limit := int32(50)
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			limit = int32(parsed) // #nosec G109 G115 -- bounded to 1..200 above
		}
	}
	rows, err := s.queries.ListRecentAdvisoryEvents(r.Context(), limit)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load advisory activity")
		return
	}
	events := make([]activityEvent, 0, len(rows))
	for _, row := range rows {
		kind := store.AdvisoryEventKind(row.Kind)
		events = append(events, activityEvent{
			CVEID:      row.CveID,
			Kind:       row.Kind,
			External:   kind.External(),
			OccurredAt: row.OccurredAt.UTC().Format("2006-01-02T15:04:05Z"),
			ObservedAt: row.ObservedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Detail:     row.Detail,
		})
	}

	response := activityResponse{Events: events}
	// Health is best-effort: a stream without it is still readable, and failing
	// the whole request because a summary is missing would be the wrong trade.
	if raw, healthErr := s.queries.GetInstanceSettingValue(r.Context(), feedHealthKey); healthErr == nil && len(raw) > 0 {
		var health FeedHealth
		if json.Unmarshal(raw, &health) == nil {
			response.Health = &health
		}
	}
	// Skipped when the sync is disabled: the stored record describes a loop
	// that no longer runs, and a permanent "failing"/"stale" card for a
	// deliberately disabled feature is noise, not health.
	if s.cfg.KEV.Enabled {
		if raw, kevErr := s.queries.GetInstanceSettingValue(r.Context(), kevHealthKey); kevErr == nil && len(raw) > 0 {
			var kevHealth KEVHealth
			if json.Unmarshal(raw, &kevHealth) == nil {
				response.KEV = &kevHealth
			}
		}
	}
	if s.cfg.DepsDev.Enabled {
		if raw, depsErr := s.queries.GetInstanceSettingValue(r.Context(), depsdev.HealthSettingKey); depsErr == nil && len(raw) > 0 {
			var health depsdev.Health
			if json.Unmarshal(raw, &health) == nil {
				response.DepsDev = &health
			}
		}
	}
	if raw, seedErr := s.queries.GetInstanceSettingValue(r.Context(), cvetriage.FeedSeedSettingKey); seedErr == nil && len(raw) > 0 {
		var seed cvetriage.FeedSeed
		if json.Unmarshal(raw, &seed) == nil && seed.Commit != "" {
			state := corpusState{Commit: seed.Commit}
			if !seed.CommittedAt.IsZero() {
				state.CommittedAt = seed.CommittedAt.UTC().Format("2006-01-02T15:04:05Z")
			}
			response.Corpus = &state
		}
	}
	api.JSON(w, http.StatusOK, response)
}

// handleAdvisoryTimeline returns one advisory's history.
//
// Separate from the finding's own timeline on purpose. A finding's history is
// what happened to it here — detected, accepted, fixed. This is what happened to
// the advisory anywhere, including upstream activity nobody here caused, which
// is the half that explains why a finding's facts changed underneath it.
func (s *Server) handleAdvisoryTimeline(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuthenticated(w, r) {
		return
	}
	cveID := chi.URLParam(r, "advisoryID")
	if !cvefeed.ValidCVEID(cveID) {
		api.JSONError(w, http.StatusBadRequest, "invalid CVE id")
		return
	}
	rows, err := s.queries.ListAdvisoryEventsForCVE(r.Context(), cveID, 50)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load advisory history")
		return
	}
	events := make([]activityEvent, 0, len(rows))
	for _, row := range rows {
		kind := store.AdvisoryEventKind(row.Kind)
		events = append(events, activityEvent{
			CVEID:      row.CveID,
			Kind:       row.Kind,
			External:   kind.External(),
			OccurredAt: row.OccurredAt.UTC().Format("2006-01-02T15:04:05Z"),
			ObservedAt: row.ObservedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Detail:     row.Detail,
		})
	}
	api.JSON(w, http.StatusOK, events)
}

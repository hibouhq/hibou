package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AdvisoryEventKind names one thing that happened to an advisory.
//
// The set deliberately spans both origins. A timeline that showed only what
// people here did would answer half the question: a CVE triaged in July and
// revised by its CNA in August has to show both, in order, or nobody can tell a
// typo fix from a widened range. Most of what the feed carries is revision —
// roughly three quarters of each batch — so upstream events are the common case,
// not the exception.
type AdvisoryEventKind string

const (
	// Upstream, nothing to do with us.
	EventPublished  AdvisoryEventKind = "published"
	EventCNARevised AdvisoryEventKind = "cna_revised"
	EventEnriched   AdvisoryEventKind = "enriched"
	EventWithdrawn  AdvisoryEventKind = "withdrawn"
	EventUpstreamed AdvisoryEventKind = "coordinates_upstreamed"
	// A catalog (CISA KEV / ENISA EUVD) listed or withdrew the CVE as
	// actively exploited (ADR-032) — the Art. 14 "becoming aware" trigger.
	EventKEVListed   AdvisoryEventKind = "kev_listed"
	EventKEVDelisted AdvisoryEventKind = "kev_delisted"

	// Ours.
	EventAuthored   AdvisoryEventKind = "coordinates_authored"
	EventSuperseded AdvisoryEventKind = "superseded"
	EventDiverged   AdvisoryEventKind = "diverged"
	EventRevoked    AdvisoryEventKind = "mapping_revoked"
)

// External reports whether an event happened upstream rather than here. The
// distinction drives presentation, and it is also why this timeline is not the
// audit log: an audit entry always has an actor, these often have none.
func (k AdvisoryEventKind) External() bool {
	switch k {
	case EventPublished, EventCNARevised, EventEnriched, EventWithdrawn, EventUpstreamed,
		EventKEVListed, EventKEVDelisted:
		return true
	}
	return false
}

// AdvisoryEvent is one timeline entry.
type AdvisoryEvent struct {
	AdvisoryID *uuid.UUID
	CVEID      string
	Kind       AdvisoryEventKind
	// When it happened, on the clock of whoever it happened to: upstream's
	// dateUpdated for a revision, ours for a decision made here.
	OccurredAt time.Time
	ActorID    *uuid.UUID
	Detail     json.RawMessage
}

// RangeChange is the payload of a cna_revised event.
//
// Recording that something changed is not enough to act on — a triager needs to
// see WHAT moved to tell a corrected typo from a range that now covers versions
// they run. Storing the before/after of the changed fields is cheap; retaining
// whole prior records is not, and the raw record is re-fetchable anyway.
type RangeChange struct {
	Product string `json:"product"`
	Before  string `json:"before"`
	After   string `json:"after"`
}

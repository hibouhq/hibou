// Package events provides a process-local event bus for in-process fan-out inside one hibou replica.
// Durable authoritative state must be persisted in PostgreSQL.
// Cross-replica fan-out, such as live WebSocket delivery, must use a shared transport such as PostgreSQL
// LISTEN/NOTIFY as described in ADR-015.
// Publish and Subscribe are process-local only: handlers run in goroutines only in the same process that
// publishes, and the bus provides no persistence.
package events

import (
	"context"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type Type string

const (
	ScanRequested Type = "scan.requested"
	ScanCompleted Type = "scan.completed"
	ScanFailed    Type = "scan.failed"
	ScanStale     Type = "scan.stale"
	// VulnerabilitiesFound is the per-scan batch: every vulnerability row a
	// scan inserted, in one event. Payload: snapshot_id, identifiers []string
	// (human-facing CVE/GHSA ids), findings []{identifier, severity,
	// component}. The notify layer dedups identifiers per repo, so only
	// genuinely never-notified findings ring the bell — and only once.
	VulnerabilitiesFound Type = "vulnerabilities.found"
	// MalwareDetected is the malicious-package slice of a scan's new findings,
	// split out of VulnerabilitiesFound so it can carry critical urgency on its
	// own channel: a dedicated bell notification and unconditional external
	// dispatch. Same payload shape as VulnerabilitiesFound.
	MalwareDetected     Type = "malware.detected"
	SecretScanCompleted Type = "secret.scan.completed"
	SecretScanFailed    Type = "secret.scan.failed"
	SecretDiscovered    Type = "secret.discovered"
	GatePassed          Type = "gate.passed"
	GateFailed          Type = "gate.failed"
	// GateRecomputeRequested asks the forge gatePublisher to re-evaluate and re-post
	// the PR gate check without a CI re-run. Payload: one of "ref_id" (single PR
	// ref), "repo_id" (all open PRs in the repo), or "org_id" (all open PRs in the
	// org). Published by gate-affecting changes: VEX/false-positive dismissal,
	// manual override, advisory re-evaluation.
	GateRecomputeRequested Type = "gate.recompute_requested"
	RetentionWarnAt        Type = "retention.warn_at"
	RetentionEviction      Type = "retention.eviction_started"
	RetentionProtected     Type = "retention.protected_exceeds_budget"
	NotificationNew        Type = "notification.new"
	TokenExpiring          Type = "token.expiring" // #nosec G101 -- event name, not a credential
	// TriageQueued is a watched product's advisory arriving with nobody yet
	// having said which packages it affects. Payload: org_id, cve_id, label,
	// severity, pending (queue depth).
	//
	// Digest rather than per-record on purpose: the feed carries ~1,300 records
	// a day, and even a well-targeted subscription bursts. A channel that cries
	// wolf gets muted, and a muted channel is the same as no queue at all.
	TriageQueued Type = "triage.queued"
	// AdvisoryDiverged is upstream publishing coordinates that disagree with a
	// mapping authored here. Neither side is retired automatically — that is
	// the point of the event. Payload: org_id, cve_id, ours, theirs.
	AdvisoryDiverged Type = "advisory.diverged"
	// LocalGrantSuspended is a capability parked because the forge narrowed
	// someone's standing. Payload: user_id, org_id, role, reason.
	//
	// It notifies rather than merely logging because the grant is now inert:
	// somebody who could triage yesterday cannot today, and if nobody is told,
	// the first symptom is a queue quietly going unworked.
	LocalGrantSuspended Type = "rbac.local_grant.suspended"
	// ForgeAdminDeparted is the forge saying an org's only admin left. The
	// membership is kept (an org nobody administers cannot be repaired from
	// inside Hibou), so an operator must appoint another admin. Payload:
	// org_id, user_id.
	ForgeAdminDeparted Type = "rbac.forge_admin.departed"
)

type Event struct {
	Type      Type
	Payload   any
	Timestamp time.Time
}

type Handler func(ctx context.Context, event Event)

// Bus fans events out to handlers registered in the current process only.
type Bus struct {
	mu       sync.RWMutex
	handlers map[Type][]Handler
	log      zerolog.Logger
}

func New(log zerolog.Logger) *Bus {
	return &Bus{
		handlers: make(map[Type][]Handler),
		log:      log.With().Str("component", "events.bus").Logger(),
	}
}

func (b *Bus) Publish(ctx context.Context, evt Event) {
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}

	b.mu.RLock()
	handlers := append([]Handler(nil), b.handlers[evt.Type]...)
	b.mu.RUnlock()

	for _, handler := range handlers {
		go func(handler Handler) {
			defer func() {
				if recovered := recover(); recovered != nil {
					b.log.Error().
						Any("panic", recovered).
						Str("event_type", string(evt.Type)).
						Bytes("stack", debug.Stack()).
						Msg("event handler panicked")
				}
			}()
			handler(ctx, evt)
		}(handler)
	}
}

func (b *Bus) Subscribe(eventType Type, handler Handler) {
	if handler == nil {
		return
	}

	b.mu.Lock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
	b.mu.Unlock()
}

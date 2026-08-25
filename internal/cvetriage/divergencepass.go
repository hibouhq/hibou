package cvetriage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// DivergenceStore is what a divergence pass needs from the database.
type DivergenceStore interface {
	ListMappedCVEsForDivergenceCheck(ctx context.Context, limit int32) ([]dbgen.ListMappedCVEsForDivergenceCheckRow, error)
	RecordAdvisoryEvent(ctx context.Context, event store.AdvisoryEvent) error
}

// DivergenceResult counts one pass.
type DivergenceResult struct {
	Checked    int
	Superseded int
	Diverged   int
	// NoUpstream is the ordinary case and is counted so that a pass which found
	// nothing is distinguishable from a pass that never ran.
	NoUpstream int
	// Failed counts errored lookups. Treating an unreachable upstream as
	// "upstream names nothing" would diverge every mapping on a network blip.
	Failed int
}

// divergenceBatch caps one pass; lookups are per-CVE network calls. The query is
// oldest-decision-first, so a truncated pass still covers the likeliest drift.
const divergenceBatch = 200

// CheckDivergence compares authored coordinates against what upstream now
// publishes (ADR-028 §10).
//
// Never rewrites a mapping: both outcomes are events, because a person's
// decision should not change without them seeing it.
func CheckDivergence(ctx context.Context, divergenceStore DivergenceStore, upstream UpstreamCoordinates) (DivergenceResult, error) {
	result := DivergenceResult{}
	if upstream == nil {
		// No upstream configured is not a failure; there is simply nothing to
		// compare against.
		return result, nil
	}

	mapped, err := divergenceStore.ListMappedCVEsForDivergenceCheck(ctx, divergenceBatch)
	if err != nil {
		return result, fmt.Errorf("list mapped CVEs: %w", err)
	}

	for _, row := range mapped {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		var ours []Package
		if err := json.Unmarshal(row.Packages, &ours); err != nil {
			result.Failed++
			continue
		}

		theirs, lookupErr := upstream.PackagesFor(ctx, row.CveID)
		if lookupErr != nil {
			// Deliberately not an event: an unreachable upstream must not read
			// as "upstream names nothing", which would diverge every mapping.
			result.Failed++
			continue
		}
		result.Checked++

		comparison := CompareCoordinates(ours, theirs)
		comparison.CVEID = row.CveID
		switch comparison.Verdict {
		case VerdictNoUpstream:
			result.NoUpstream++
			continue
		case VerdictAgrees:
			// Recording agreement every pass would bury the two verdicts that
			// need reading.
			continue
		case VerdictSuperseded:
			result.Superseded++
		case VerdictDiverged:
			result.Diverged++
		}

		detail, marshalErr := json.Marshal(comparison)
		if marshalErr != nil {
			result.Failed++
			continue
		}
		kind := store.EventSuperseded
		if comparison.Verdict == VerdictDiverged {
			kind = store.EventDiverged
		}
		if err := divergenceStore.RecordAdvisoryEvent(ctx, store.AdvisoryEvent{
			CVEID:      row.CveID,
			Kind:       kind,
			OccurredAt: time.Now().UTC(),
			Detail:     detail,
		}); err != nil {
			return result, fmt.Errorf("record %s event for %s: %w", kind, row.CveID, err)
		}
	}
	return result, nil
}

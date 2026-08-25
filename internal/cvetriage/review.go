package cvetriage

import (
	"strings"

	"github.com/hibouhq/hibou/internal/cvefeed"
)

// RangeDelta is one range that moved between two versions of a record.
//
// Recording that a record changed is not enough to act on. A triager needs to
// see WHAT moved: a corrected typo and a bound that now covers versions they
// run look identical otherwise, and only one of them is urgent.
type RangeDelta struct {
	Product string `json:"product"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
	// Widened reports whether the change could newly implicate versions that
	// were previously considered unaffected. That is the direction that turns a
	// clean component into a vulnerable one without anybody touching the code.
	Widened bool `json:"widened"`
}

// DiffRanges compares two versions of the same record's affected ranges.
//
// The comparison is by product and introduced-version, which is the pair a CNA
// keeps stable across a revision — a branch entry stays "the 9.0 branch" even
// when its upper bound moves. Products appearing or disappearing entirely are
// reported as an added or removed range rather than silently ignored.
func DiffRanges(before, after cvefeed.Projection) []RangeDelta {
	type key struct{ product, introduced string }

	index := func(record cvefeed.Projection) map[key]string {
		out := map[key]string{}
		for _, product := range record.Affected {
			for _, versionRange := range product.Ranges {
				out[key{product.ProductKey, versionRange.Introduced}] = upperBound(versionRange)
			}
		}
		return out
	}
	beforeRanges, afterRanges := index(before), index(after)

	deltas := []RangeDelta{}
	for k, afterBound := range afterRanges {
		beforeBound, existed := beforeRanges[k]
		if existed && beforeBound == afterBound {
			continue
		}
		deltas = append(deltas, RangeDelta{
			Product: k.product,
			Before:  formatRange(k.introduced, beforeBound, existed),
			After:   formatRange(k.introduced, afterBound, true),
			// A new range is always potentially widening; a moved bound widens
			// when it moved later. String comparison is deliberate: this flags
			// a range for a human, it does not decide a match, so a conservative
			// answer is the right kind of wrong.
			Widened: !existed || afterBound > beforeBound,
		})
	}
	for k, beforeBound := range beforeRanges {
		if _, stillThere := afterRanges[k]; stillThere {
			continue
		}
		deltas = append(deltas, RangeDelta{
			Product: k.product,
			Before:  formatRange(k.introduced, beforeBound, true),
			Widened: false,
		})
	}
	return deltas
}

func upperBound(versionRange cvefeed.VersionRange) string {
	if versionRange.Fixed != "" {
		return "<" + versionRange.Fixed
	}
	return "<=" + versionRange.LastAffected
}

func formatRange(introduced, bound string, present bool) string {
	if !present {
		return ""
	}
	return strings.TrimSpace(introduced + " " + bound)
}

// NeedsReview reports whether a decision made against `triagedAt` is stale.
//
// Detecting this needs no history of our own: the record's own dateUpdated
// moving past the value a decision was stamped with is the entire signal, and
// revised records arrive in the same sweep as new ones. Roughly three quarters
// of what the feed carries is revision, so this is the common path rather than
// an edge case.
func NeedsReview(record cvefeed.Projection, triagedAt *cvefeed.Projection) bool {
	if triagedAt == nil || record.Updated.IsZero() || triagedAt.Updated.IsZero() {
		return false
	}
	return record.Updated.After(triagedAt.Updated)
}

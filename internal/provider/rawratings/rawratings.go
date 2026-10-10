// Package rawratings rebuilds an advisory source's ratings from the raw record
// stored with it, using the provider's own mapping (ADR-038 §8). The startup
// backfill and the seed data go through it, so stored ratings always come
// from the same code that maps a live provider response.
package rawratings

import (
	"encoding/json"
	"strconv"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/provider/osv"
	"github.com/hibouhq/hibou/internal/provider/trivy"
)

// FromRaw maps a stored record. Authored sources (triage, manual) carry no
// ratings of their own and yield none.
func FromRaw(provider string, raw json.RawMessage) ([]advisory.Rating, error) {
	switch provider {
	case "osv":
		return osv.RatingsFromRaw(raw)
	case "trivy":
		return trivy.RatingsFromRaw(raw)
	case advisory.CVEProvider:
		var stored map[string]string
		if err := json.Unmarshal(raw, &stored); err != nil {
			return nil, err
		}
		var score *float64
		if value, err := strconv.ParseFloat(stored["score"], 64); err == nil {
			score = &value
		}
		return advisory.CVERatings(stored["source"], stored["vector"], score, stored["severity"]), nil
	}
	return nil, nil
}

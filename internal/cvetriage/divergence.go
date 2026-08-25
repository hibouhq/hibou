package cvetriage

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Divergence compares coordinates we authored against what upstream later
// published for the same CVE (ADR-028 §10).
//
// Asymmetric on purpose: broader upstream is adopted, narrower is a question.
// Adopting narrower would retire findings a person chose to raise.
type Divergence struct {
	CVEID string
	// Verdict is what the comparison concluded.
	Verdict DivergenceVerdict
	// Ours and Upstream are normalised package keys, sorted, for the event
	// payload a reviewer reads.
	Ours     []string
	Upstream []string
	// Missing is what upstream names and we do not — the packages adopting
	// would add. Extra is what we name and upstream does not: the packages
	// adopting would drop, which is the half that needs a person.
	Missing []string
	Extra   []string
}

// DivergenceVerdict is the conclusion drawn from one comparison.
type DivergenceVerdict string

const (
	// VerdictAgrees means upstream named exactly what we did. Nothing to record:
	// an event per unchanged mapping per pass would bury the ones that matter.
	VerdictAgrees DivergenceVerdict = "agrees"
	// VerdictSuperseded means upstream is broader — it covers everything we
	// named and more. Safe to adopt: nothing we flagged stops being flagged.
	VerdictSuperseded DivergenceVerdict = "superseded"
	// VerdictDiverged means upstream drops or replaces something we named.
	// Kept, and asked about.
	VerdictDiverged DivergenceVerdict = "diverged"
	// VerdictNoUpstream means upstream still publishes no coordinates for this
	// CVE, which is the ordinary case and the reason the feature exists.
	VerdictNoUpstream DivergenceVerdict = "no_upstream"
)

// UpstreamCoordinates looks up the packages an upstream database now names for
// a CVE. Empty means it names none, which is not an error.
type UpstreamCoordinates interface {
	PackagesFor(ctx context.Context, cveID string) ([]Package, error)
}

// CompareCoordinates decides what upstream's coordinates mean for ours.
func CompareCoordinates(ours, upstream []Package) Divergence {
	ourKeys := packageKeySet(ours)
	upstreamKeys := packageKeySet(upstream)

	result := Divergence{
		Ours:     sortedKeys(ourKeys),
		Upstream: sortedKeys(upstreamKeys),
	}
	if len(upstreamKeys) == 0 {
		result.Verdict = VerdictNoUpstream
		return result
	}
	for key := range upstreamKeys {
		if _, held := ourKeys[key]; !held {
			result.Missing = append(result.Missing, key)
		}
	}
	for key := range ourKeys {
		if _, held := upstreamKeys[key]; !held {
			result.Extra = append(result.Extra, key)
		}
	}
	sort.Strings(result.Missing)
	sort.Strings(result.Extra)

	switch {
	case len(result.Extra) > 0:
		// Upstream drops something we named. Narrower in any respect is a
		// question, even when it is also broader elsewhere: the packages it
		// drops are findings that would disappear.
		result.Verdict = VerdictDiverged
	case len(result.Missing) > 0:
		result.Verdict = VerdictSuperseded
	default:
		result.Verdict = VerdictAgrees
	}
	return result
}

// packageKeySet normalises to ecosystem+name, casefolded, so "Maven" and "maven"
// are the same coordinate and a comparison does not diverge on spelling.
func packageKeySet(packages []Package) map[string]struct{} {
	out := map[string]struct{}{}
	for _, pkg := range packages {
		ecosystem := strings.ToLower(strings.TrimSpace(pkg.Ecosystem))
		name := strings.ToLower(strings.TrimSpace(pkg.Name))
		if ecosystem == "" || name == "" {
			continue
		}
		out[ecosystem+":"+name] = struct{}{}
	}
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// Summary is the one-line explanation a reviewer sees on the event.
func (d Divergence) Summary() string {
	switch d.Verdict {
	case VerdictSuperseded:
		return "upstream adds " + strings.Join(d.Missing, ", ")
	case VerdictDiverged:
		if len(d.Missing) > 0 {
			return fmt.Sprintf("upstream drops %s and adds %s",
				strings.Join(d.Extra, ", "), strings.Join(d.Missing, ", "))
		}
		return "upstream drops " + strings.Join(d.Extra, ", ")
	case VerdictAgrees:
		return "upstream names the same packages"
	default:
		return "upstream publishes no package coordinates"
	}
}

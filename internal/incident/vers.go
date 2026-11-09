package incident

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hibouhq/hibou/internal/versioncmp"
)

// VersRange is a parsed vers range ("vers:generic/>=4.0|<4.3"): the version
// axis of a VEX statement and of a first-party advisory (ADR-053 §4a).
type VersRange struct {
	Scheme      string
	All         bool
	Constraints []VersConstraint
}

// VersConstraint is one comparator and version.
type VersConstraint struct {
	Op      string
	Version string
}

// ParseVers parses a vers range.
func ParseVers(raw string) (VersRange, error) {
	trimmed := strings.TrimSpace(raw)
	rest, ok := strings.CutPrefix(trimmed, "vers:")
	if !ok {
		return VersRange{}, fmt.Errorf("vers range must start with vers: (got %q)", raw)
	}
	scheme, constraints, ok := strings.Cut(rest, "/")
	if !ok || scheme == "" || constraints == "" {
		return VersRange{}, fmt.Errorf("vers range needs a scheme and constraints (got %q)", raw)
	}
	out := VersRange{Scheme: strings.ToLower(scheme)}
	if strings.TrimSpace(constraints) == "*" {
		out.All = true
		return out, nil
	}
	for _, part := range strings.Split(constraints, "|") {
		part = strings.TrimSpace(part)
		if part == "" {
			return VersRange{}, fmt.Errorf("vers range %q has an empty constraint", raw)
		}
		op := "="
		for _, candidate := range []string{">=", "<=", "!=", ">", "<", "="} {
			if strings.HasPrefix(part, candidate) {
				op = candidate
				part = strings.TrimSpace(strings.TrimPrefix(part, candidate))
				break
			}
		}
		if part == "" {
			return VersRange{}, fmt.Errorf("vers range %q has a comparator without a version", raw)
		}
		out.Constraints = append(out.Constraints, VersConstraint{Op: op, Version: part})
	}
	comparator := versComparator(out.Scheme)
	sort.SliceStable(out.Constraints, func(i, j int) bool {
		return comparator.Compare(out.Constraints[i].Version, out.Constraints[j].Version) < 0
	})
	return out, nil
}

func versComparator(scheme string) versioncmp.Comparator {
	if comparator, ok := versioncmp.Get(scheme); ok {
		return comparator
	}
	return &versioncmp.Semver{}
}

// Contains reports whether version is in the range, following the vers
// specification's containment algorithm.
func (r VersRange) Contains(version string) bool {
	if r.All {
		return true
	}
	comparator := versComparator(r.Scheme)
	version = strings.TrimSpace(version)
	remaining := []VersConstraint{}
	for _, constraint := range r.Constraints {
		cmp := comparator.Compare(version, constraint.Version)
		switch constraint.Op {
		case "=":
			if cmp == 0 {
				return true
			}
			continue
		case "!=":
			if cmp == 0 {
				return false
			}
			continue
		}
		if cmp == 0 && (constraint.Op == ">=" || constraint.Op == "<=") {
			return true
		}
		remaining = append(remaining, constraint)
	}
	if len(remaining) == 0 {
		return false
	}
	first, last := remaining[0], remaining[len(remaining)-1]
	if (first.Op == "<" || first.Op == "<=") && comparator.Compare(version, first.Version) < 0 {
		return true
	}
	if (last.Op == ">" || last.Op == ">=") && comparator.Compare(version, last.Version) > 0 {
		return true
	}
	for i := 0; i+1 < len(remaining); i++ {
		lower, upper := remaining[i], remaining[i+1]
		if (lower.Op == ">" || lower.Op == ">=") && (upper.Op == "<" || upper.Op == "<=") &&
			comparator.Compare(version, lower.Version) > 0 && comparator.Compare(version, upper.Version) < 0 {
			return true
		}
	}
	return false
}

// ReleaseLine groups versions for the fix_release action: the version with
// its last dot-separated segment dropped (4.2.1 → 4.2), so a fix on 4.2.3
// satisfies every affected 4.2.x.
func ReleaseLine(version string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if index := strings.IndexAny(trimmed, "-+"); index >= 0 {
		trimmed = trimmed[:index]
	}
	if index := strings.LastIndex(trimmed, "."); index > 0 {
		return trimmed[:index]
	}
	return trimmed
}

package advisory

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type CVSSVersion string

const (
	CVSSVersionV2  CVSSVersion = "v2"
	CVSSVersionV30 CVSSVersion = "v3.0"
	CVSSVersionV31 CVSSVersion = "v3.1"
	CVSSVersionV40 CVSSVersion = "v4.0"
)

type Advisory struct {
	ID          uuid.UUID
	CanonicalID string
	Title       string
	Description string
	Severity    Severity
	CVSSScore   *float64
	CVSSVersion *CVSSVersion
	CVSSVector  string
	CWEIDs      []string
	IsMalware   bool
	MalwareType *string
	PublishedAt *time.Time
	WithdrawnAt *time.Time
	Aliases     []string
	Sources     []Source
	Ranges      []AffectedRange
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Source struct {
	ID          uuid.UUID
	AdvisoryID  uuid.UUID
	Provider    string
	ProviderID  string
	Severity    *Severity
	CVSSScore   *float64
	CVSSVersion *CVSSVersion
	CVSSVector  string
	RawData     json.RawMessage
	FetchedAt   time.Time
}

type AffectedRange struct {
	ID           uuid.UUID
	AdvisoryID   uuid.UUID
	Ecosystem    string
	PackageName  string
	Introduced   string
	Fixed        string
	LastAffected string
	Source       string
}

func NormalizeSeverity(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func MergeSeverity(sources []Source) (Severity, *float64, string) {
	if len(sources) == 0 {
		return SeverityInfo, nil, ""
	}

	if preferred, ok := bestSource(sources, func(source Source) bool {
		return strings.EqualFold(source.Provider, "nvd") && sourceHasSignal(source)
	}); ok {
		severity, score := severityFromSource(preferred)
		return severity, score, preferred.CVSSVector
	}

	if best, ok := bestSource(sources, sourceHasSignal); ok {
		severity, score := severityFromSource(best)
		return severity, score, best.CVSSVector
	}

	return SeverityInfo, nil, ""
}

func bestSource(sources []Source, include func(Source) bool) (Source, bool) {
	var best Source
	bestSet := false
	for _, source := range sources {
		if !include(source) {
			continue
		}
		if !bestSet || compareSources(source, best) > 0 {
			best = source
			bestSet = true
		}
	}
	return best, bestSet
}

func sourceHasSignal(source Source) bool {
	return source.CVSSScore != nil || source.Severity != nil
}

func severityFromSource(source Source) (Severity, *float64) {
	if source.CVSSScore != nil {
		return NormalizeSeverity(*source.CVSSScore), source.CVSSScore
	}
	if source.Severity != nil {
		return *source.Severity, nil
	}
	return SeverityInfo, nil
}

func compareSources(left, right Source) int {
	if cmp := compareOptionalScore(left.CVSSScore, right.CVSSScore); cmp != 0 {
		return cmp
	}

	leftSeverity, _ := severityFromSource(left)
	rightSeverity, _ := severityFromSource(right)
	if cmp := compareSeverityRank(leftSeverity, rightSeverity); cmp != 0 {
		return cmp
	}

	if left.CVSSVector != "" && right.CVSSVector == "" {
		return 1
	}
	if left.CVSSVector == "" && right.CVSSVector != "" {
		return -1
	}

	return strings.Compare(strings.ToLower(right.Provider), strings.ToLower(left.Provider))
}

func compareOptionalScore(left, right *float64) int {
	if left != nil && right == nil {
		return 1
	}
	if left == nil && right != nil {
		return -1
	}
	if left == nil && right == nil {
		return 0
	}
	if *left > *right {
		return 1
	}
	if *left < *right {
		return -1
	}
	return 0
}

func compareSeverityRank(left, right Severity) int {
	leftRank := severityRank(left)
	rightRank := severityRank(right)
	if leftRank > rightRank {
		return 1
	}
	if leftRank < rightRank {
		return -1
	}
	return 0
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}
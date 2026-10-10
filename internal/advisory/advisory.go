package advisory

import (
	"encoding/json"
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
	// SeverityUnknown: no source rates it (ADR-038 §3). Not "informational":
	// an unrated CVE may be critical.
	SeverityUnknown Severity = "unknown"
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
	RatedBy     string
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
	ID         uuid.UUID
	AdvisoryID uuid.UUID
	Provider   string
	ProviderID string
	Ratings    []Rating
	RawData    json.RawMessage
	FetchedAt  time.Time
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
	// Release scopes distro ranges (apk/deb/rpm) to one distribution release
	// ("3.18" for Alpine 3.18, "12" for Debian bookworm). Empty for language
	// ecosystems, whose versions are release-independent.
	Release string
	// VulnerableSymbols are the advisory's declared vulnerable functions,
	// qualified by import path (Go/OSV imports[].symbols). Empty when the
	// advisory does not say — never guessed.
	VulnerableSymbols []string
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

// severityRank orders severities; unknown sits between medium and low
// (ADR-038 §3).
func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 6
	case SeverityHigh:
		return 5
	case SeverityMedium:
		return 4
	case SeverityUnknown:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

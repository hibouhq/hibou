// Package scanpolicy resolves which scanners run on a repository (ADR-035
// §5): org requirements first (a repo cannot loosen them without an
// approved, unexpired exception), then the repo's own choices (which may add
// coverage), then the org default (every applicable, non-preview scanner).
// Operator availability is applied later by the planner. One function, so
// the API, the UI and the plan cannot disagree.
package scanpolicy

import (
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/applicability"
	"github.com/hibouhq/hibou/internal/scancatalog"
)

// Repo setting modes.
const (
	ModeInherit  = "inherit"
	ModeEnabled  = "enabled"
	ModeDisabled = "disabled"
)

// Decision states.
const (
	StateRequired    = "required"
	StateEnabled     = "enabled"
	StateRecommended = "recommended"
	StateDisabled    = "disabled"
	StateOff         = "off" // applicable pre-release, not opted in
	StateNotApplied  = "not_applicable"
)

// Requirement is an org requirement: a capability for a language.
type Requirement struct {
	ID            uuid.UUID `json:"id"`
	Language      string    `json:"language"`
	Capability    string    `json:"capability"`
	ScannerIDs    []string  `json:"scanner_ids"`
	FreshnessDays int       `json:"freshness_days"`
	Enforcement   string    `json:"enforcement"`
}

// Exception waives a requirement for a repository scope.
type Exception struct {
	ID            uuid.UUID `json:"id"`
	RequirementID uuid.UUID `json:"requirement_id"`
	Scope         string    `json:"scope"`
	Status        string    `json:"status"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Active reports an approved exception that has not expired.
func (e Exception) Active(now time.Time) bool {
	return e.Status == "approved" && now.Before(e.ExpiresAt)
}

// Decision is the effective state of one scanner on the repository, with
// where it came from.
type Decision struct {
	ScannerID string `json:"scanner_id"`
	State     string `json:"state"`
	// Source: org-requirement, repo, org-default.
	Source string `json:"source"`
	// RepoMode is the repo's own setting, shown even when overridden.
	RepoMode     string      `json:"repo_mode"`
	Requirements []uuid.UUID `json:"requirements,omitempty"`
	Exempted     []uuid.UUID `json:"exempted,omitempty"`
	Applicable   bool        `json:"applicable"`
	Preview      bool        `json:"preview,omitempty"`
	Reason       string      `json:"reason"`
}

// Runs reports whether the scanner is part of the plan.
func (d Decision) Runs() bool {
	return d.State == StateRequired || d.State == StateEnabled || d.State == StateRecommended
}

// Input is what resolution reads.
type Input struct {
	Catalog       *scancatalog.Catalog
	Applicability applicability.Result
	Settings      map[string]string // scanner id -> repo mode
	Requirements  []Requirement
	Exceptions    []Exception
	Now           time.Time
}

// Resolve returns one decision per catalog scanner that is applicable or
// has a repo setting, sorted by scanner id.
func Resolve(input Input) []Decision {
	applicable := map[string]applicability.ScannerScope{}
	for _, scope := range input.Applicability.Applicable {
		applicable[scope.ScannerID] = scope
	}
	exempted := map[uuid.UUID]bool{}
	for _, exception := range input.Exceptions {
		if exception.Active(input.Now) && (exception.Scope == "" || exception.Scope == ".") {
			exempted[exception.RequirementID] = true
		}
	}

	// Which scanners each requirement makes required.
	requiredBy := map[string][]uuid.UUID{}
	exemptedFor := map[string][]uuid.UUID{}
	for _, requirement := range input.Requirements {
		if input.Applicability.Languages[requirement.Language] == 0 {
			continue // the repo has no code in that language
		}
		candidates := candidatesFor(input.Catalog, requirement)
		if len(candidates) == 0 {
			continue
		}
		chosen := chooseCandidates(candidates, input.Settings)
		for _, id := range chosen {
			if exempted[requirement.ID] {
				exemptedFor[id] = append(exemptedFor[id], requirement.ID)
				continue
			}
			requiredBy[id] = append(requiredBy[id], requirement.ID)
		}
	}

	ids := map[string]bool{}
	for id := range applicable {
		ids[id] = true
	}
	for id := range input.Settings {
		ids[id] = true
	}
	for id := range requiredBy {
		ids[id] = true
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		if _, ok := input.Catalog.Scanner(id); ok {
			sorted = append(sorted, id)
		}
	}
	sort.Strings(sorted)

	decisions := make([]Decision, 0, len(sorted))
	for _, id := range sorted {
		scanner, _ := input.Catalog.Scanner(id)
		_, isApplicable := applicable[id]
		mode := input.Settings[id]
		if mode == "" {
			mode = ModeInherit
		}
		decision := Decision{ScannerID: id, RepoMode: mode, Applicable: isApplicable, Preview: scanner.Prerelease, Exempted: exemptedFor[id]}
		switch {
		case len(requiredBy[id]) > 0:
			decision.State, decision.Source, decision.Requirements = StateRequired, "org-requirement", requiredBy[id]
			decision.Reason = "required by the organization"
			if mode == ModeDisabled {
				decision.Reason += "; the repository's \"disabled\" does not apply without an approved exception"
			}
		case !isApplicable:
			decision.State, decision.Source, decision.Reason = StateNotApplied, "repo", "nothing in the repository it can analyse"
		case mode == ModeEnabled:
			decision.State, decision.Source, decision.Reason = StateEnabled, "repo", "enabled for this repository"
		case mode == ModeDisabled:
			decision.State, decision.Source, decision.Reason = StateDisabled, "repo", "disabled for this repository"
		case scanner.Prerelease:
			decision.State, decision.Source, decision.Reason = StateOff, "org-default", "pre-release: enable it explicitly"
		default:
			decision.State, decision.Source, decision.Reason = StateRecommended, "org-default", "applies to this repository"
		}
		if len(decision.Exempted) > 0 && decision.State != StateRequired {
			decision.Reason += "; requirement waived by an approved exception"
		}
		decisions = append(decisions, decision)
	}
	return decisions
}

// candidatesFor lists the catalog scanners that provide the requirement's
// capability for its language, restricted to the approved list when set.
// Pre-releases qualify only when the org approved them by name.
func candidatesFor(catalog *scancatalog.Catalog, requirement Requirement) []string {
	approved := map[string]bool{}
	for _, id := range requirement.ScannerIDs {
		approved[id] = true
	}
	out := []string{}
	for i := range catalog.Scanners {
		scanner := &catalog.Scanners[i]
		if len(approved) > 0 && !approved[scanner.ID] {
			continue
		}
		if scanner.Prerelease && !approved[scanner.ID] {
			continue
		}
		for _, capability := range scanner.Capabilities {
			if capability.Language == requirement.Language && capability.Capability == requirement.Capability {
				out = append(out, scanner.ID)
				break
			}
		}
	}
	return out
}

// chooseCandidates: the candidates the repo enabled satisfy the requirement;
// otherwise the first candidate (catalog order) is required.
func chooseCandidates(candidates []string, settings map[string]string) []string {
	enabled := []string{}
	for _, id := range candidates {
		if settings[id] == ModeEnabled {
			enabled = append(enabled, id)
		}
	}
	if len(enabled) > 0 {
		return enabled
	}
	return candidates[:1]
}

// Enabled lists the scanners the plan runs.
func Enabled(decisions []Decision) []string {
	out := make([]string, 0, len(decisions))
	for _, decision := range decisions {
		if decision.Runs() {
			out = append(out, decision.ScannerID)
		}
	}
	return out
}

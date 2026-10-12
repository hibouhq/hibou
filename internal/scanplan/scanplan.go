// Package scanplan turns a repository's applicability, the scanner catalog
// and the effective policy into a reproducible scan plan (ADR-035 §4,
// ADR-036 §3–4): which scanner jobs run, on which scope, from which verified
// artifact, after which prerequisites, and why. It is pure; the server stores
// the plan and CI executes it.
package scanplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hibouhq/hibou/internal/applicability"
	"github.com/hibouhq/hibou/internal/scancatalog"
)

// Modes (ADR-036 §4).
const (
	// ModeBaseline: no compatible baseline, or something material changed.
	ModeBaseline = "baseline"
	// ModeFull: whole applicable scope, because no adapter supports
	// validated incremental analysis yet.
	ModeFull = "full"
	// ModeSweep: scheduled refresh of every eligible scope.
	ModeSweep = "sweep"
)

// Job statuses.
const (
	JobReady   = "ready"
	JobBlocked = "blocked"
)

// Input is everything a plan depends on; its digest identifies the plan.
type Input struct {
	CommitSHA     string
	BaseCommitSHA string
	RequestedMode string
	Runner        Runner
	Applicability applicability.Result
	// DetectionRevision and CatalogRevision pin what the plan was built from.
	DetectionRevision string
	CatalogRevision   string
	// Enabled restricts the plan to these scanner ids; nil means the org
	// defaults (every applicable, non-preview scanner).
	Enabled []string
	// Previous is the last stored plan of the repo, for mode selection.
	Previous *Plan
}

// Runner is the CI platform the artifacts must run on.
type Runner struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Libc string `json:"libc,omitempty"`
}

// Job is one scanner execution.
type Job struct {
	ID        string `json:"id"`
	ScannerID string `json:"scanner_id"`
	Status    string `json:"status"`
	// BlockedReason names the exact setup blocker (ADR-035 §5).
	BlockedReason string `json:"blocked_reason,omitempty"`
	// Targets are the module roots the job analyses ("." = repository).
	Targets    []string `json:"targets"`
	Exclusions []string `json:"exclusions"`
	// Scope is "full" when Targets cover the repository, else "partial".
	Scope         string                   `json:"scope"`
	Capabilities  []scancatalog.Capability `json:"capabilities"`
	Artifact      *scancatalog.Location    `json:"artifact,omitempty"`
	Ruleset       string                   `json:"ruleset,omitempty"`
	Prerequisites []string                 `json:"prerequisites"`
	Command       []string                 `json:"command"`
	Resources     scancatalog.Resources    `json:"resources"`
	Rationale     string                   `json:"rationale"`
}

// Plan is the stored, reproducible plan.
type Plan struct {
	Digest            string `json:"digest"`
	Mode              string `json:"mode"`
	ModeReason        string `json:"mode_reason"`
	CommitSHA         string `json:"commit_sha"`
	BaseCommitSHA     string `json:"base_commit_sha,omitempty"`
	Runner            Runner `json:"runner"`
	DetectionRevision string `json:"detection_revision"`
	CatalogRevision   string `json:"catalog_revision"`
	// ApplicabilityStatus "truncated"/"unknown" means the plan may miss
	// scopes: coverage built on it is not complete.
	ApplicabilityStatus string `json:"applicability_status"`
	Jobs                []Job  `json:"jobs"`
}

// Build makes the plan. Operator availability (the distribution policy)
// constrains execution; enabled scanners constrain selection.
func Build(input Input, catalog *scancatalog.Catalog, distribution scancatalog.DistributionConfig) Plan {
	plan := Plan{
		CommitSHA:           input.CommitSHA,
		BaseCommitSHA:       input.BaseCommitSHA,
		Runner:              input.Runner,
		DetectionRevision:   input.DetectionRevision,
		CatalogRevision:     input.CatalogRevision,
		ApplicabilityStatus: input.Applicability.Status,
		Jobs:                []Job{},
	}
	plan.Mode, plan.ModeReason = selectMode(input)

	enabled := map[string]bool{}
	for _, id := range input.Enabled {
		enabled[id] = true
	}
	exclusions := make([]string, 0, len(input.Applicability.Exclusions))
	for _, exclusion := range input.Applicability.Exclusions {
		exclusions = append(exclusions, exclusion.Path)
	}
	for _, scope := range input.Applicability.Applicable {
		if input.Enabled == nil && scope.Preview {
			continue // pre-releases are opt-in
		}
		if input.Enabled != nil && !enabled[scope.ScannerID] {
			continue
		}
		scanner, ok := catalog.Scanner(scope.ScannerID)
		if !ok {
			continue
		}
		job := Job{
			ID:            jobID(scanner.ID, scope.Modules),
			ScannerID:     scanner.ID,
			Status:        JobReady,
			Targets:       append([]string(nil), scope.Modules...),
			Exclusions:    exclusions,
			Scope:         "partial",
			Capabilities:  scope.Capabilities,
			Prerequisites: append([]string(nil), scanner.Stages.Requires...),
			Command:       append([]string(nil), scanner.Command.Args...),
			Resources:     scanner.Resources,
			Rationale:     scope.Reason,
		}
		if len(job.Targets) == 0 || contains(job.Targets, ".") {
			job.Targets = []string{"."}
			job.Scope = "full"
		}
		job.Status, job.BlockedReason, job.Artifact = resolveArtifact(scanner, input.Runner, distribution)
		if job.Status == JobReady {
			if ruleset, reason := selectRuleset(catalog, scanner); reason != "" {
				job.Status, job.BlockedReason = JobBlocked, reason
			} else {
				job.Ruleset = ruleset
			}
		}
		plan.Jobs = append(plan.Jobs, job)
	}
	sort.Slice(plan.Jobs, func(i, j int) bool { return plan.Jobs[i].ID < plan.Jobs[j].ID })
	plan.Digest = digest(plan)
	return plan
}

// selectMode applies ADR-036 §4. No adapter has validated incremental
// support yet, so a PR or push never gets change-impact: it scans the whole
// applicable scope.
func selectMode(input Input) (string, string) {
	if input.RequestedMode == ModeSweep {
		return ModeSweep, "full sweep requested"
	}
	previous := input.Previous
	switch {
	case previous == nil:
		return ModeBaseline, "no earlier plan for this repository"
	case previous.CatalogRevision != input.CatalogRevision:
		return ModeBaseline, "scanner catalog changed since the last plan"
	case previous.DetectionRevision != input.DetectionRevision:
		return ModeBaseline, "detection recipes changed since the last plan"
	}
	return ModeFull, "full applicable scope: no scanner here supports validated incremental analysis"
}

func resolveArtifact(scanner *scancatalog.Scanner, runner Runner, distribution scancatalog.DistributionConfig) (string, string, *scancatalog.Location) {
	var chosen *scancatalog.Distribution
	for i := range scanner.Distributions {
		d := &scanner.Distributions[i]
		if d.Kind == scancatalog.KindMaven {
			// A Maven adapter runs in the build's own JDK: the plugin is
			// the artifact, whatever the runner's platform.
			chosen = d
			break
		}
	}
	if chosen == nil {
		binary, ok := scanner.BinaryFor(runner.OS, runner.Arch, runner.Libc)
		if !ok {
			return JobBlocked, fmt.Sprintf("no verified %s build for %s/%s", scanner.Name, runner.OS, runner.Arch), nil
		}
		chosen = binary
	}
	location, err := distribution.Resolve(scanner, chosen)
	if err != nil {
		return JobBlocked, err.Error(), nil
	}
	return JobReady, "", &location
}

// selectRuleset returns the scanner's first selectable ruleset, or why none
// is. A scanner whose rules ship inside it (SpotBugs) needs none.
func selectRuleset(catalog *scancatalog.Catalog, scanner *scancatalog.Scanner) (string, string) {
	if len(scanner.Rulesets) == 0 {
		return "", ""
	}
	pending := make([]string, 0, len(scanner.Rulesets))
	for _, id := range scanner.Rulesets {
		ruleset, ok := catalog.Ruleset(id)
		if !ok {
			continue
		}
		if ruleset.Selectable() {
			return ruleset.ID, ""
		}
		pending = append(pending, fmt.Sprintf("%s (%s)", ruleset.ID, ruleset.Status))
	}
	return "", "no approved ruleset: " + strings.Join(pending, ", ")
}

func jobID(scannerID string, modules []string) string {
	sorted := append([]string(nil), modules...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(scannerID + "\x00" + strings.Join(sorted, "\x00")))
	return scannerID + "-" + hex.EncodeToString(sum[:])[:10]
}

// digest identifies the plan's content: the same inputs give the same digest.
func digest(plan Plan) string {
	plan.Digest = ""
	encoded, _ := json.Marshal(plan)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

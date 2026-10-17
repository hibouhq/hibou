package delta

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/cooldown"
	"github.com/hibouhq/hibou/internal/packagepolicy"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Dependency delta and cooldown gate (ADR-045 §4.1.2, ADR-048 §3).
//
// The gate judges only what the PR introduces: versions in the head
// snapshot that the base does not have. Each one is asked of the package
// policy: a cooldown hold, a malicious deny, or warnings. A version that
// fixes a finding the PR resolves is never held, so the cooldown cannot
// fight remediation.

// CooldownGate is the `dependencies.cooldown` section resolved for a PR.
type CooldownGate struct {
	// WindowMode: auto, off, or duration; WindowDuration applies to the
	// latter. Empty means the instance default.
	WindowMode     string
	WindowDuration time.Duration
	// Enforcement: inherit (the gate's), advisory (notes only), blocking
	// (reasons, which fail the gate).
	Enforcement string
	// InstallConfig: require (a missing install-time cooldown fails the
	// gate), warn (a note), off. Empty means warn (ADR-048 §3.1).
	InstallConfig string
}

// Dependency change kinds.
const (
	DependencyAdded   = "added"
	DependencyUpdated = "updated"
	DependencyRemoved = "removed"
)

// DependencyChange is one component the PR adds, updates or removes.
type DependencyChange struct {
	Change          string `json:"change"`
	Purl            string `json:"purl"`
	Name            string `json:"name"`
	Ecosystem       string `json:"ecosystem"`
	Version         string `json:"version"`
	PreviousVersion string `json:"previous_version,omitempty"`
	// Decision, Until, Reason and Warnings come from the package policy for
	// added and updated versions.
	Decision string     `json:"decision,omitempty"`
	Until    *time.Time `json:"until,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	Warnings []string   `json:"warnings,omitempty"`
	// Exempt says why a hold was lifted: the version fixes a finding this PR
	// resolves, or an acceptance exists.
	Exempt string `json:"exempt,omitempty"`
}

// DependencyDelta is what the PR changes in the inventory.
type DependencyDelta struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Removed int `json:"removed"`
	// Holds and Denies count changes the policy refused.
	Holds   int                `json:"holds"`
	Denies  int                `json:"denies"`
	Changes []DependencyChange `json:"changes"`
	// Evaluated is false when no base inventory exists to compare against,
	// or no policy evaluator is configured.
	Evaluated bool   `json:"evaluated"`
	Note      string `json:"note,omitempty"`
	// InstallGaps lists modules whose package manager has no install-time
	// cooldown, or one shorter than the policy, and an updater that waits
	// less than the install does (ADR-048 §3.1).
	InstallGaps []string `json:"install_gaps,omitempty"`
}

// extractionRunStore reads the head's extraction run, which carries each
// module's install-time settings.
type extractionRunStore interface {
	GetDepExtractionRunBySnapshot(ctx context.Context, snapshotID uuid.UUID) (*store.DepExtractionRun, error)
}

// evaluateInstallConfig verifies the install-time cooldown (ADR-048 §3.1):
// the gate holds a merge, only the package manager's own setting keeps a
// fresh version off a build. A module without the setting is a coverage
// gap: a reason under install_config: require, a note under warn.
func (s *Service) evaluateInstallConfig(ctx context.Context, cfg *GateConfig) (gaps, reasons, notes []string) {
	if cfg == nil || cfg.HeadSnapshotID == uuid.Nil {
		return nil, nil, nil
	}
	mode := "warn"
	if cfg.Cooldown != nil && strings.TrimSpace(cfg.Cooldown.InstallConfig) != "" {
		mode = strings.ToLower(strings.TrimSpace(cfg.Cooldown.InstallConfig))
	}
	if mode == "off" {
		return nil, nil, nil
	}
	runs, ok := s.store.(extractionRunStore)
	if !ok {
		return nil, nil, nil
	}
	run, err := runs.GetDepExtractionRunBySnapshot(ctx, cfg.HeadSnapshotID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", cfg.HeadSnapshotID.String()).Msg("load extraction run for install config")
		return nil, nil, nil
	}
	if run == nil {
		return nil, nil, nil
	}
	var required time.Duration
	if cfg.Cooldown != nil && cfg.Cooldown.WindowMode == cooldown.WindowDuration {
		required = cfg.Cooldown.WindowDuration
	}
	var minInstall time.Duration
	for _, module := range run.Modules {
		where := "`" + module.Path + "/`"
		if module.Path == "." || module.Path == "" {
			where = "the root module"
		}
		for _, setting := range module.InstallConfig {
			window := time.Duration(setting.WindowSeconds) * time.Second
			switch {
			case !setting.Present:
				line := fmt.Sprintf("%s has no install-time cooldown for %s: set `%s` in `%s`", where, setting.Tool, setting.Setting, setting.Path)
				if setting.Note != "" {
					line += " (" + setting.Note + ")"
				}
				gaps = append(gaps, line)
			case required > 0 && window > 0 && window < required:
				gaps = append(gaps, fmt.Sprintf("%s: %s waits %s before installing a new version, the policy window is %s (`%s` in `%s`)", where, setting.Tool, humanWindow(window), humanWindow(required), setting.Setting, setting.Path))
			}
			if setting.Present && window > 0 && (minInstall == 0 || window < minInstall) {
				minInstall = window
			}
		}
	}
	var updaterNotes []string
	for _, updater := range run.Updaters {
		window := time.Duration(updater.WindowSeconds) * time.Second
		if updater.Present && minInstall > 0 && window < minInstall {
			updaterNotes = append(updaterNotes, fmt.Sprintf("%s waits %s before proposing a version, the install waits %s: its pull requests will be held (`%s`)", updater.Tool, humanWindow(window), humanWindow(minInstall), updater.Path))
		}
	}
	if mode == "require" {
		reasons = append(reasons, gaps...)
	} else {
		notes = append(notes, gaps...)
	}
	notes = append(notes, updaterNotes...)
	gaps = append(gaps, updaterNotes...)
	return gaps, reasons, notes
}

func humanWindow(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
	return d.String()
}

// SetPackagePolicy enables the dependency delta and cooldown gate.
func (s *Service) SetPackagePolicy(evaluate func(ctx context.Context, req packagepolicy.Request) ([]packagepolicy.Decision, error), defaultPolicy packagepolicy.Policy) {
	if s == nil {
		return
	}
	s.packagePolicy = evaluate
	s.defaultPolicy = defaultPolicy
}

// evaluateDependencyDelta computes the inventory delta between base and
// head and asks the policy about every introduced version. Reasons fail
// the gate; notes do not.
func (s *Service) evaluateDependencyDelta(ctx context.Context, repoID, orgID uuid.UUID, cfg *GateConfig, delta *DeltaResult) (*DependencyDelta, []string, []string) {
	if s.packagePolicy == nil || cfg == nil || cfg.HeadSnapshotID == uuid.Nil {
		return nil, nil, nil
	}
	lister, ok := s.store.(componentLister)
	if !ok {
		return nil, nil, nil
	}
	head, err := lister.ListComponentsBySnapshot(ctx, cfg.HeadSnapshotID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", cfg.HeadSnapshotID.String()).Msg("list head components for dependency delta")
		return nil, nil, nil
	}
	if cfg.BaseSnapshotID == uuid.Nil {
		return &DependencyDelta{Note: "no base inventory to compare against: dependency changes not evaluated"}, nil, nil
	}
	base, err := lister.ListComponentsBySnapshot(ctx, cfg.BaseSnapshotID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", cfg.BaseSnapshotID.String()).Msg("list base components for dependency delta")
		return nil, nil, nil
	}
	if len(base) == 0 {
		return &DependencyDelta{Note: "the target branch has no inventory yet: dependency changes not evaluated"}, nil, nil
	}

	result := diffComponents(base, head)
	result.Evaluated = true
	if len(result.Changes) == 0 {
		return result, nil, nil
	}

	policy := s.defaultPolicy
	if cfg.Cooldown != nil && cfg.Cooldown.WindowMode != "" {
		policy.WindowMode = cfg.Cooldown.WindowMode
		policy.WindowDuration = cfg.Cooldown.WindowDuration
	}
	policy.PrivateNamespaces = append(append([]string{}, policy.PrivateNamespaces...), cfg.PrivateNamespaces...)
	enforcement := "inherit"
	if cfg.Cooldown != nil && strings.TrimSpace(cfg.Cooldown.Enforcement) != "" {
		enforcement = strings.ToLower(strings.TrimSpace(cfg.Cooldown.Enforcement))
	}

	// Versions that fix a finding this PR resolves are never held.
	fixes := make(map[string]string) // ecosystem|name -> advisory id
	for _, vuln := range delta.Resolved {
		if vuln.ComponentName == nil {
			continue
		}
		key := componentKey(derefString(vuln.Ecosystem), *vuln.ComponentName)
		if _, seen := fixes[key]; !seen {
			fixes[key] = vuln.PrimaryIdentifierValue
		}
	}

	purls := make([]string, 0, len(result.Changes))
	indexByPurl := make(map[string]int, len(result.Changes))
	for i, change := range result.Changes {
		if change.Change == DependencyRemoved {
			continue
		}
		indexByPurl[change.Purl] = i
		purls = append(purls, change.Purl)
	}
	decisions, err := s.packagePolicy(ctx, packagepolicy.Request{OrgID: orgID, RepoID: &repoID, Purls: purls, Policy: policy})
	if err != nil {
		s.log.Warn().Err(err).Str("repo_id", repoID.String()).Msg("package policy for dependency delta")
		result.Note = "package policy unavailable: cooldown not evaluated"
		return result, nil, nil
	}
	var reasons, notes []string
	for _, decision := range decisions {
		i, ok := indexByPurl[decision.Purl]
		if !ok {
			continue
		}
		change := &result.Changes[i]
		change.Decision = decision.Decision
		change.Until = decision.Until
		change.Reason = decision.Reason
		change.Warnings = decision.Warnings
		if decision.Accepted {
			change.Exempt = decision.Reason
		}
		if decision.Decision == packagepolicy.DecisionHold {
			if advisory, fixes := fixes[componentKey(change.Ecosystem, change.Name)]; fixes {
				change.Decision = packagepolicy.DecisionAllow
				change.Exempt = "allowed: fixes " + advisory
				change.Until = nil
				continue
			}
			result.Holds++
			line := fmt.Sprintf("Cooldown: %s %s (%s) is %s", change.Name, change.Version, change.Change, decision.Reason)
			if enforcement == "advisory" {
				notes = append(notes, line)
			} else {
				reasons = append(reasons, line)
			}
		}
		if decision.Decision == packagepolicy.DecisionDeny {
			result.Denies++
			reasons = append(reasons, fmt.Sprintf("Dependency: %s %s is %s", change.Name, change.Version, decision.Reason))
		}
	}
	return result, reasons, notes
}

func componentKey(ecosystem, name string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "|" + strings.ToLower(strings.TrimSpace(name))
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// diffComponents lists what head has that base does not, what it dropped,
// and pairs version changes of the same package.
func diffComponents(base, head []dbgen.Component) *DependencyDelta {
	basePurls := make(map[string]struct{}, len(base))
	baseByName := make(map[string][]dbgen.Component, len(base))
	for _, c := range base {
		basePurls[c.Purl] = struct{}{}
		key := componentKey(c.Ecosystem, c.Name)
		baseByName[key] = append(baseByName[key], c)
	}
	headPurls := make(map[string]struct{}, len(head))
	headByName := make(map[string]struct{}, len(head))
	result := &DependencyDelta{Changes: []DependencyChange{}}
	for _, c := range head {
		headPurls[c.Purl] = struct{}{}
		headByName[componentKey(c.Ecosystem, c.Name)] = struct{}{}
		if _, inBase := basePurls[c.Purl]; inBase {
			continue
		}
		change := DependencyChange{Change: DependencyAdded, Purl: c.Purl, Name: c.Name, Ecosystem: c.Ecosystem, Version: c.Version}
		if previous := baseByName[componentKey(c.Ecosystem, c.Name)]; len(previous) > 0 {
			change.Change = DependencyUpdated
			change.PreviousVersion = previous[0].Version
			result.Updated++
		} else {
			result.Added++
		}
		result.Changes = append(result.Changes, change)
	}
	for _, c := range base {
		if _, inHead := headPurls[c.Purl]; inHead {
			continue
		}
		if _, stillThere := headByName[componentKey(c.Ecosystem, c.Name)]; stillThere {
			continue // an update, already listed from the head side
		}
		result.Removed++
		result.Changes = append(result.Changes, DependencyChange{Change: DependencyRemoved, Purl: c.Purl, Name: c.Name, Ecosystem: c.Ecosystem, Version: c.Version})
	}
	sort.SliceStable(result.Changes, func(i, j int) bool {
		if result.Changes[i].Change != result.Changes[j].Change {
			return changeRank(result.Changes[i].Change) < changeRank(result.Changes[j].Change)
		}
		return result.Changes[i].Name < result.Changes[j].Name
	})
	return result
}

func changeRank(change string) int {
	switch change {
	case DependencyAdded:
		return 0
	case DependencyUpdated:
		return 1
	default:
		return 2
	}
}

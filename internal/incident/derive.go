package incident

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Scope statuses (ADR-053 §3).
const (
	ScopePending            = "pending"
	ScopeAffected           = "affected"
	ScopeNotAffected        = "not_affected"
	ScopeFixed              = "fixed"
	ScopeUnderInvestigation = "under_investigation"
	ScopeUnknown            = "unknown"
	ScopeExcluded           = "excluded"
	ScopeNotMatched         = "not_matched"
	ScopePresent            = "present"
	ScopeAbsent             = "absent"
)

// Scope subject types.
const (
	ScopeRelease = "release"
	ScopeRef     = "ref"
	ScopeClient  = "client"
)

// Action kinds that are not regime filings.
const (
	ActionVEX              = "vex"
	ActionClientNotice     = "client_notice"
	ActionFixRelease       = "fix_release"
	ActionUpstreamNotice   = "upstream_notice"
	ActionRemediation      = "remediation"
	ActionRevoke           = "revoke"
	ActionRotate           = "rotate"
	ActionAssessExposure   = "assess_exposure"
	ActionRemove           = "remove"
	ActionNotifyOwner      = "notify_owner"
	ActionRemovePackage    = "remove_package"
	ActionRotateCISecrets  = "rotate_ci_secrets"
	ActionReportRegistry   = "report_registry"
	ActionRemediateFinding = "remediate"
)

// StatementFact is a current VEX statement that may apply to a release.
type StatementFact struct {
	ID            string
	Status        string
	Justification string
	Approved      bool
	ReleaseID     string
	VersionRange  string
	ComponentPURL string
	// Repo is true for a repository-scoped statement, false for org-wide.
	Repo      bool
	CreatedAt time.Time
}

// ReleaseFact is a release of the incident's repository, with what the
// exposure join knows about it.
type ReleaseFact struct {
	ID          string
	Version     string
	HasSnapshot bool
	CreatedAt   time.Time
	ClientIDs   []string
	// Matched: the advisory (or the package) is in this release's inventory.
	Matched       bool
	ComponentPURL string
	Reachability  string
}

// RefFact is the presence of a finding on the latest snapshot of one ref.
type RefFact struct {
	Name    string
	Present bool
}

// FindingFact is the state of the finding a finding-subject incident wraps.
type FindingFact struct {
	Status        string // detected | resolved | suppressed
	Accepted      bool
	Revoked       bool // attested revoked
	ValidatorDead bool // validator confirmed the credential dead
	Rotated       bool // attestation recorded rotation (or not needed)
	ExposureDone  bool // attestation confirmed the exposure assessment
	OwnerExternal bool // the credential belongs to someone else
}

// DeliveryFact is one delivery to a client.
type DeliveryFact struct {
	ClientID string
	Status   string // pending_approval | sent | failed | acknowledged
}

// Settings are the organisation switches derivation reads.
type Settings struct {
	RequireVEXApproval     bool
	RequireAcknowledgement bool
}

// Facts is everything derivation reads. The caller gathers it; Derive is pure.
type Facts struct {
	Kind         string
	State        string
	Regimes      []string
	DecisionStep string
	// ComponentAdvisory: the subject is a third-party component's advisory,
	// so an upstream notice applies (Art. 13(6)); false for first-party.
	ComponentAdvisory bool
	// AdvisoryPublic: the advisory carries a public identifier (CVE, GHSA),
	// so the maintainer already knows and the upstream report is not
	// required (guidance C(2026) 5252 §223); the action stays, optional.
	AdvisoryPublic bool
	Releases       []ReleaseFact
	Statements     []StatementFact
	Refs           []RefFact
	Finding        *FindingFact
	// ManualScope are rows a person entered or decided, keyed by
	// subject_type + "/" + subject_id.
	ManualScope map[string]ScopeRow
	Deliveries  []DeliveryFact
	Deadlines   []Deadline
	// MetFilings: filing action kinds already recorded.
	MetFilings map[string]bool
	Settings   Settings
	// ClientNames labels client actions; unknown ids fall back to the id.
	ClientNames map[string]string
}

// ScopeRow is one derived scope row.
type ScopeRow struct {
	SubjectType   string
	SubjectID     string
	Label         string
	Status        string
	Reason        string
	ComponentPURL string
	StatementID   string
	Reachability  string
	Manual        bool
	ClientIDs     []string
}

// ActionSpec is one derived action.
type ActionSpec struct {
	Kind        string
	SubjectType string
	SubjectID   string
	Label       string
	Automatic   bool
	Optional    bool
	DueAt       *time.Time
	// Satisfied: the facts already show the action done; Evidence says how.
	Satisfied bool
	Evidence  map[string]any
}

// Derivation is what an incident's facts imply.
type Derivation struct {
	Scope   []ScopeRow
	Actions []ActionSpec
}

// Derive computes scope and actions from facts (ADR-053 §3, §4).
func Derive(f Facts) Derivation {
	if !Open(f.State) {
		return Derivation{}
	}
	switch f.Kind {
	case KindExploitedVulnerability:
		return deriveExploited(f)
	case KindSevereIncident:
		return deriveSevere(f)
	case KindSecretLeak:
		return deriveSecret(f)
	case KindMalware:
		return deriveMalware(f)
	case KindPolicyBreach:
		return derivePolicy(f)
	}
	return Derivation{}
}

func manualRow(f Facts, subjectType, subjectID string) (ScopeRow, bool) {
	if f.ManualScope == nil {
		return ScopeRow{}, false
	}
	row, ok := f.ManualScope[subjectType+"/"+subjectID]
	return row, ok && row.Manual
}

// StatementFor is statementFor for callers outside the package (document
// rendering).
func StatementFor(statements []StatementFact, release ReleaseFact) *StatementFact {
	return statementFor(statements, release)
}

// statementFor picks the statement that speaks for a release: one naming the
// release, then a version range containing it, then the component in the
// repository, then the repository, then the organisation; the newest within a
// tier.
func statementFor(statements []StatementFact, release ReleaseFact) *StatementFact {
	best, bestTier := (*StatementFact)(nil), 99
	for i := range statements {
		statement := &statements[i]
		tier := 99
		switch {
		case statement.ReleaseID != "":
			if statement.ReleaseID == release.ID {
				tier = 0
			}
		case statement.VersionRange != "":
			if r, err := ParseVers(statement.VersionRange); err == nil && r.Contains(release.Version) {
				tier = 1
			}
		case statement.ComponentPURL != "":
			if statement.Repo && release.ComponentPURL != "" && statement.ComponentPURL == release.ComponentPURL {
				tier = 2
			}
		case statement.Repo:
			tier = 3
		default:
			tier = 4
		}
		if tier < bestTier || (tier == bestTier && best != nil && statement.CreatedAt.After(best.CreatedAt)) {
			best, bestTier = statement, tier
		}
	}
	if bestTier == 99 {
		return nil
	}
	return best
}

func statementSatisfies(statement *StatementFact, settings Settings) bool {
	if statement == nil || statement.Status == ScopeUnderInvestigation {
		return false
	}
	return statement.Approved || !settings.RequireVEXApproval
}

// needsNotice: a client on a release in this status must be told.
func needsNotice(status string) bool {
	switch status {
	case ScopeAffected, ScopePending, ScopeUnknown, ScopeUnderInvestigation:
		return true
	}
	return false
}

func deriveExploited(f Facts) Derivation {
	var out Derivation
	releases := append([]ReleaseFact(nil), f.Releases...)
	sort.SliceStable(releases, func(i, j int) bool { return releases[i].CreatedAt.Before(releases[j].CreatedAt) })

	rows := make([]ScopeRow, 0, len(releases))
	statements := map[string]*StatementFact{}
	for _, release := range releases {
		row := ScopeRow{SubjectType: ScopeRelease, SubjectID: release.ID, Label: release.Version, ComponentPURL: release.ComponentPURL, Reachability: release.Reachability, ClientIDs: release.ClientIDs}
		statement := statementFor(f.Statements, release)
		statements[release.ID] = statement
		switch {
		case release.Matched:
			row.Status = ScopePending
			if statement != nil {
				row.Status, row.StatementID = statement.Status, statement.ID
				row.Reason = statement.Justification
			}
		case !release.HasSnapshot && len(release.ClientIDs) > 0:
			row.Status, row.Reason = ScopeUnknown, "no inventory for this release; produce one from the tag or record a statement"
			if statement != nil {
				row.Status, row.StatementID, row.Reason = statement.Status, statement.ID, firstNonEmpty(statement.Justification, "status assumed by statement")
			}
		case len(release.ClientIDs) > 0:
			row.Status, row.Reason = ScopeNotMatched, "the advisory is not matched in this release's inventory"
		default:
			continue
		}
		if manual, ok := manualRow(f, ScopeRelease, release.ID); ok {
			row.Status, row.Reason, row.Manual = manual.Status, manual.Reason, true
		}
		rows = append(rows, row)
	}
	out.Scope = rows

	notificationDue := deadlineFor(f.Deadlines, StepNotification)
	reportable := f.State == StateReportable
	for _, row := range rows {
		switch row.Status {
		case ScopeExcluded, ScopeNotMatched:
			continue
		}
		statement := statements[row.SubjectID]
		action := ActionSpec{
			Kind: ActionVEX, SubjectType: ScopeRelease, SubjectID: row.SubjectID,
			Label: "VEX statement for " + row.Label, Automatic: true,
		}
		if statementSatisfies(statement, f.Settings) {
			action.Satisfied = true
			action.Evidence = map[string]any{"vex_statement_id": statement.ID, "status": statement.Status}
		}
		out.Actions = append(out.Actions, action)
	}

	if reportable {
		out.Actions = append(out.Actions, filingActions(f)...)
		out.Actions = append(out.Actions, clientNotices(f, rows, notificationDue)...)
	} else if f.State == StateNotReportable && f.DecisionStep == StepReachableNoAttack {
		// Exploitable here, not exploited here: Art. 14(8) does not apply,
		// but the affected releases' clients are worth warning (ADR-053,
		// ladder step 3) — offered, never owed.
		for _, action := range clientNotices(f, rows, nil) {
			action.Optional = true
			action.Label += " (voluntary)"
			out.Actions = append(out.Actions, action)
		}
	}
	out.Actions = append(out.Actions, fixReleaseActions(rows, releases)...)
	// Art. 13(6): a vulnerability identified in a component is reported to
	// its maintainer, unless they already know — a public identifier (CVE,
	// GHSA, …) means they do (guidance §223), so a public advisory derives no
	// upstream notice at all.
	if f.State == StateNotReportable && f.ComponentAdvisory && !f.AdvisoryPublic && (f.DecisionStep == StepNotReachable || f.DecisionStep == StepReachableNoAttack) {
		seen := map[string]bool{}
		for _, row := range rows {
			if row.ComponentPURL == "" || seen[row.ComponentPURL] {
				continue
			}
			seen[row.ComponentPURL] = true
			out.Actions = append(out.Actions, ActionSpec{
				Kind: ActionUpstreamNotice, SubjectType: "component", SubjectID: row.ComponentPURL,
				Label: "Report upstream to the maintainer of " + row.ComponentPURL + " (Art. 13(6))",
			})
		}
	}
	return out
}

func deadlineFor(deadlines []Deadline, step string) *time.Time {
	var out *time.Time
	for _, deadline := range deadlines {
		if deadline.Pending || deadline.Step != step || (deadline.Regime == RegimeInternal && step != StepResolve) {
			continue
		}
		due := deadline.DueAt
		out = earliest(out, &due)
	}
	return out
}

func filingActions(f Facts) []ActionSpec {
	out := []ActionSpec{}
	for _, deadline := range f.Deadlines {
		if deadline.Filing == "" {
			continue
		}
		action := ActionSpec{
			Kind: deadline.Filing, SubjectType: "regime", SubjectID: deadline.Regime,
			Label: deadline.Label + " (" + deadline.Regime + ")", Satisfied: f.MetFilings[deadline.Filing],
		}
		if !deadline.Pending {
			due := deadline.DueAt
			action.DueAt = &due
		}
		out = append(out, action)
	}
	return out
}

func clientNotices(f Facts, rows []ScopeRow, due *time.Time) []ActionSpec {
	clients := map[string]bool{}
	for _, row := range rows {
		if row.SubjectType == ScopeClient && needsNotice(row.Status) {
			clients[row.SubjectID] = true
			continue
		}
		if !needsNotice(row.Status) {
			continue
		}
		for _, id := range row.ClientIDs {
			clients[id] = true
		}
	}
	ids := make([]string, 0, len(clients))
	for id := range clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []ActionSpec{}
	for _, id := range ids {
		action := ActionSpec{
			Kind: ActionClientNotice, SubjectType: ScopeClient, SubjectID: id,
			Label: "Inform " + firstNonEmpty(f.ClientNames[id], id), Automatic: true, DueAt: due,
		}
		for _, delivery := range f.Deliveries {
			if delivery.ClientID != id {
				continue
			}
			if delivery.Status == "acknowledged" || (delivery.Status == "sent" && !f.Settings.RequireAcknowledgement) {
				action.Satisfied = true
				action.Evidence = map[string]any{"delivery_status": delivery.Status}
				break
			}
		}
		out = append(out, action)
	}
	return out
}

// fixReleaseActions: one per release line with an affected release, done when
// a later release of the same line is fixed or no longer carries the
// vulnerability.
func fixReleaseActions(rows []ScopeRow, releases []ReleaseFact) []ActionSpec {
	created := map[string]time.Time{}
	for _, release := range releases {
		created[release.ID] = release.CreatedAt
	}
	type line struct {
		latestAffected time.Time
		versions       []string
	}
	lines := map[string]*line{}
	order := []string{}
	for _, row := range rows {
		if row.Status != ScopeAffected {
			continue
		}
		name := ReleaseLine(row.Label)
		entry, ok := lines[name]
		if !ok {
			entry = &line{}
			lines[name] = entry
			order = append(order, name)
		}
		entry.versions = append(entry.versions, row.Label)
		if created[row.SubjectID].After(entry.latestAffected) {
			entry.latestAffected = created[row.SubjectID]
		}
	}
	out := []ActionSpec{}
	for _, name := range order {
		entry := lines[name]
		action := ActionSpec{
			Kind: ActionFixRelease, SubjectType: "release_line", SubjectID: name,
			Label: fmt.Sprintf("Ship a fix for %s.x (affected: %s)", name, strings.Join(entry.versions, ", ")), Automatic: true,
		}
		for _, release := range releases {
			if ReleaseLine(release.Version) != name || !release.CreatedAt.After(entry.latestAffected) {
				continue
			}
			fixed := release.HasSnapshot && !release.Matched
			for _, row := range rows {
				if row.SubjectID == release.ID && (row.Status == ScopeFixed || row.Status == ScopeNotMatched) {
					fixed = true
				}
			}
			if fixed {
				action.Satisfied = true
				action.Evidence = map[string]any{"release_id": release.ID, "version": release.Version}
				break
			}
		}
		out = append(out, action)
	}
	return out
}

func deriveSevere(f Facts) Derivation {
	var out Derivation
	for _, row := range f.ManualScope {
		out.Scope = append(out.Scope, row)
	}
	sort.SliceStable(out.Scope, func(i, j int) bool {
		if out.Scope[i].SubjectType != out.Scope[j].SubjectType {
			return out.Scope[i].SubjectType < out.Scope[j].SubjectType
		}
		return out.Scope[i].Label < out.Scope[j].Label
	})
	// Clients of releases in scope come from the exposure join.
	rows := append([]ScopeRow(nil), out.Scope...)
	for i := range rows {
		if rows[i].SubjectType != ScopeRelease {
			continue
		}
		for _, release := range f.Releases {
			if release.ID == rows[i].SubjectID {
				rows[i].ClientIDs = release.ClientIDs
			}
		}
	}
	if f.State == StateReportable {
		out.Actions = append(out.Actions, filingActions(f)...)
		out.Actions = append(out.Actions, clientNotices(f, rows, deadlineFor(f.Deadlines, StepNotification))...)
	}
	if f.State != StateDismissed {
		out.Actions = append(out.Actions, ActionSpec{Kind: ActionRemediation, SubjectType: "incident", SubjectID: "", Label: "Contain and remediate; attach the evidence"})
	}
	return out
}

func refRows(f Facts) ([]ScopeRow, bool) {
	rows := []ScopeRow{}
	anyPresent := false
	for _, ref := range f.Refs {
		status := ScopeAbsent
		if ref.Present {
			status, anyPresent = ScopePresent, true
		}
		rows = append(rows, ScopeRow{SubjectType: ScopeRef, SubjectID: ref.Name, Label: ref.Name, Status: status})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Label < rows[j].Label })
	return rows, anyPresent
}

func deriveSecret(f Facts) Derivation {
	var out Derivation
	rows, anyPresent := refRows(f)
	out.Scope = rows
	if f.State == StateDismissed {
		return out
	}
	finding := FindingFact{}
	if f.Finding != nil {
		finding = *f.Finding
	}
	revoke := ActionSpec{Kind: ActionRevoke, SubjectType: "finding", Label: "Revoke the credential at its provider"}
	switch {
	case finding.ValidatorDead:
		revoke.Satisfied, revoke.Evidence = true, map[string]any{"validator": "credential confirmed dead"}
	case finding.Revoked:
		revoke.Satisfied, revoke.Evidence = true, map[string]any{"attestation": "revocation attested"}
	}
	out.Actions = append(out.Actions,
		revoke,
		ActionSpec{Kind: ActionRotate, SubjectType: "finding", Label: "Deploy a new credential, or record why none is needed", Satisfied: finding.Rotated},
		ActionSpec{Kind: ActionAssessExposure, SubjectType: "finding", Label: "Assess the exposure (visibility, forks, time in history)", Satisfied: finding.ExposureDone},
		ActionSpec{Kind: ActionRemove, SubjectType: "finding", Label: "Remove the secret from every branch", Automatic: true, Optional: true, Satisfied: !anyPresent && len(rows) > 0},
	)
	if finding.OwnerExternal {
		out.Actions = append(out.Actions, ActionSpec{Kind: ActionNotifyOwner, SubjectType: "finding", Label: "Tell the credential's owner"})
	}
	return out
}

func deriveMalware(f Facts) Derivation {
	var out Derivation
	rows, anyPresent := refRows(f)
	shipped := []ScopeRow{}
	for _, release := range f.Releases {
		if !release.Matched {
			continue
		}
		shipped = append(shipped, ScopeRow{SubjectType: ScopeRelease, SubjectID: release.ID, Label: release.Version, Status: ScopeAffected, Reason: "the package shipped in this release", ClientIDs: release.ClientIDs, ComponentPURL: release.ComponentPURL})
	}
	out.Scope = append(rows, shipped...)
	if f.State == StateDismissed {
		return out
	}
	out.Actions = append(out.Actions,
		ActionSpec{Kind: ActionRemovePackage, SubjectType: "finding", Label: "Remove the package from every branch", Automatic: true, Satisfied: !anyPresent && len(rows) > 0},
		ActionSpec{Kind: ActionRotateCISecrets, SubjectType: "finding", Label: "Rotate the CI secrets the package could read"},
		ActionSpec{Kind: ActionReportRegistry, SubjectType: "finding", Label: "Report the package to its registry"},
	)
	if len(shipped) > 0 {
		out.Actions = append(out.Actions, clientNotices(f, shipped, nil)...)
	}
	if f.State == StateReportable {
		out.Actions = append(out.Actions, filingActions(f)...)
	}
	return out
}

func derivePolicy(f Facts) Derivation {
	var out Derivation
	rows, anyPresent := refRows(f)
	out.Scope = rows
	if f.State == StateDismissed {
		return out
	}
	action := ActionSpec{Kind: ActionRemediateFinding, SubjectType: "finding", Label: "Fix the finding, or record an approved exception", Automatic: true, DueAt: deadlineFor(f.Deadlines, StepResolve)}
	switch {
	case f.Finding != nil && f.Finding.Status == "resolved":
		action.Satisfied, action.Evidence = true, map[string]any{"finding": "resolved"}
	case f.Finding != nil && f.Finding.Accepted:
		action.Satisfied, action.Evidence = true, map[string]any{"finding": "exception approved"}
	case len(rows) > 0 && !anyPresent:
		action.Satisfied, action.Evidence = true, map[string]any{"finding": "no longer present"}
	}
	out.Actions = append(out.Actions, action)
	if f.State == StateReportable {
		out.Actions = append(out.Actions, filingActions(f)...)
	}
	return out
}

// ActionStatus is a persisted action, for closure.
type ActionStatus struct {
	State    string
	Obsolete bool
	Optional bool
}

// ReadyToClose implements the computed closure of ADR-053 §7: an open
// incident closes when every current, required action is done or waived,
// and — for incidents under an external regime — once a person decided.
// An incident without any required action closes only after a decision, so
// a fresh signal never closes itself.
func ReadyToClose(state string, regimes []string, actions []ActionStatus) bool {
	if !Open(state) {
		return false
	}
	if HasExternalRegime(regimes) && !Decided(state) {
		return false
	}
	required := 0
	for _, action := range actions {
		if action.Obsolete || action.Optional {
			continue
		}
		required++
		if action.State != "done" && action.State != "waived" {
			return false
		}
	}
	return required > 0 || Decided(state)
}

// NextDue is the earliest due date among pending actions and unmet deadlines,
// for sorting and countdowns.
func NextDue(deadlines []Deadline, met map[string]bool, actions []ActionSpec) *time.Time {
	var out *time.Time
	for _, deadline := range deadlines {
		if deadline.Pending || met[deadline.Regime+"/"+deadline.Step] {
			continue
		}
		due := deadline.DueAt
		out = earliest(out, &due)
	}
	for _, action := range actions {
		if action.Satisfied || action.DueAt == nil {
			continue
		}
		out = earliest(out, action.DueAt)
	}
	return out
}

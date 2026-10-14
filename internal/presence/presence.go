// Package presence decides, when a snapshot is processed, which findings of
// the previous snapshot of the ref were not re-checked by their producer and
// must be carried forward as still open (ADR-034 §3). It is pure: callers load
// the rows and producer runs and apply the returned plan.
package presence

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
)

// Producer keys of the server-side producers; SARIF producers are
// lower(tool.driver.name), the vulnerabilities.scanner_name of their rows.
const (
	ProducerSecretScanning = "secret-scanning"
	ProducerSBOMMatching   = store.ProducerSBOMMatching
)

// Reasons a finding was not re-checked, stored in presence_reason.
const (
	ReasonProducerMissing = "producer_missing"
	ReasonProducerFailed  = "producer_failed"
	ReasonProducerPending = "producer_pending"
	ReasonOutsideScope    = "outside_scope"
	ReasonPartialScope    = "partial_scope"
	ReasonPartialRun      = "partial_run"
	// ReasonFileSkippedPrefix is followed by the skip reason
	// ("file_skipped:timeout").
	ReasonFileSkippedPrefix = "file_skipped:"
	// ReasonAssertion: a manual or agent-filed finding, carried until a
	// decision ends it (ADR-034 §4).
	ReasonAssertion = "assertion"
	// ReasonLocationGone: an assertion whose file was deleted or renamed
	// away; still open, needs review.
	ReasonLocationGone = "location_gone"
)

// Reasons an absent, covered finding stays open as unconfirmed (ADR-034 §3).
const (
	// ReasonUnchanged: the producer covered the file, which did not change
	// since the finding was last seen.
	ReasonUnchanged = "unchanged"
	// ReasonUnchangedTrace: a taint finding whose trace files did not change
	// (ADR-036 §6); a change elsewhere does not repair the flow.
	ReasonUnchangedTrace = "unchanged_trace"
	// ReasonAbsentCount: consecutive-absence policy, not yet at its threshold.
	ReasonAbsentCount = "absent"
	// ReasonExplicitPolicy: the producer's policy is explicit; only a
	// decision resolves its findings.
	ReasonExplicitPolicy = "explicit_policy"
	// ReasonChangeUnchecked: whether the code changed could not be asked of
	// the forge this time; checked again on the next snapshot.
	ReasonChangeUnchecked = "change_unchecked"
)

// Resolution reasons (ADR-034 §3), stored in finding_resolutions.
const (
	ResolvedFixed            = "fixed"
	ResolvedFileRemoved      = "file_removed"
	ResolvedNoLongerReported = "no_longer_reported"
	ResolvedProducerChanged  = "producer_changed"
	// ResolvedProducerRetired: an org admin retired the producer (removed
	// from CI on purpose) and it did not run. A decision, not a fix.
	ResolvedProducerRetired = "producer_retired"
)

// Resolution policies (ADR-034 §5).
const (
	PolicyCoverage           = "coverage"
	PolicyConsecutiveAbsence = "consecutive-absence"
	PolicyExplicit           = "explicit"
	// PolicyRetired: the producer was removed from CI on purpose; while it
	// does not run, its findings resolve as producer_retired instead of
	// staying "not re-checked" forever. If it runs again, the usual rules
	// apply.
	PolicyRetired = "retired"
)

// DefaultAbsenceThreshold is N for consecutive-absence, and the number of
// unchanged covered scans after which an unconfirmed finding is no longer
// reported (D9).
const DefaultAbsenceThreshold = 3

// Policy is how a producer's absent findings are resolved.
type Policy struct {
	Kind      string
	Threshold int
}

// DefaultPolicy is the policy when the org set none (ADR-034 §5): agents are
// explicit — sampling makes one missing result weak evidence — everything
// else follows coverage.
func DefaultPolicy(producer string) Policy {
	if strings.HasPrefix(producer, "agent:") {
		return Policy{Kind: PolicyExplicit, Threshold: DefaultAbsenceThreshold}
	}
	return Policy{Kind: PolicyCoverage, Threshold: DefaultAbsenceThreshold}
}

// Change is what the forge says about one path between two commits.
type Change struct {
	// Known is false when the forge cannot compare at all (no compare
	// support): coverage alone then decides, as ADR-034 §3 says.
	Known   bool
	Changed bool
	// Removed: deleted, or renamed away.
	Removed bool
	// Deferred: the question was not answered this time — compare budget
	// spent, forge error or rate limit, path beyond a truncated list. Never
	// read as "coverage alone": the finding stays unconfirmed.
	Deferred bool
}

// ChangeChecker answers whether path changed between base and the current
// snapshot's commit.
type ChangeChecker func(baseCommit, path string) Change

// Options carry what the plan needs beyond the two snapshots. Zero values
// fall back to DefaultPolicy and "change unknown".
type Options struct {
	Policy  func(producer string) Policy
	Changed ChangeChecker
	// ClosedAssertions are fingerprints of manual and agent findings a
	// decision resolved or retracted (ADR-034 §4): not carried.
	ClosedAssertions map[string]bool
}

func (o Options) policy(producer string) Policy {
	if o.Policy == nil {
		return DefaultPolicy(producer)
	}
	policy := o.Policy(producer)
	if policy.Kind == "" {
		return DefaultPolicy(producer)
	}
	if policy.Threshold <= 0 {
		policy.Threshold = DefaultAbsenceThreshold
	}
	return policy
}

func (o Options) changed(base, path string) Change {
	if o.Changed == nil || base == "" || path == "" {
		return Change{}
	}
	return o.Changed(base, path)
}

// Carry is one previous finding to keep open in the new snapshot.
type Carry struct {
	// Source is the row in the previous snapshot (itself possibly carried).
	Source   store.Vulnerability
	Presence string
	Reason   string
	// LastSeenSnapshotID / LastSeenCommit name where the producer last
	// actually reported the finding.
	LastSeenSnapshotID uuid.UUID
	LastSeenCommit     string
	// ConsecutiveAbsences counts covered scans in a row without the finding.
	ConsecutiveAbsences int
}

// Resolution is one previous finding that is resolved in the new snapshot,
// with the evidence (ADR-034 §3).
type Resolution struct {
	Source   store.Vulnerability
	Producer string
	Reason   string
}

// Snapshot is what Plan needs about one snapshot.
type Snapshot struct {
	ID        uuid.UUID
	CommitSHA string
	Rows      []store.Vulnerability
	Runs      []store.ProducerRun
}

// ProducerOf returns the producer key that must re-check a row, or "" for
// rows no producer re-checks (manual and agent assertions, ADR-034 §4).
func ProducerOf(vuln store.Vulnerability) string {
	if vuln.Origin == string(store.FindingOriginHuman) || vuln.Origin == string(store.FindingOriginAgent) || vuln.Type == "manual" {
		return ""
	}
	switch vuln.Type {
	case "secret":
		return ProducerSecretScanning
	case "dependency", "malware":
		return ProducerSBOMMatching
	}
	return strings.ToLower(strings.TrimSpace(vuln.ScannerName))
}

// Plan decides the fate of every open produced finding of the previous
// snapshot that the current snapshot does not report (ADR-034 §3):
//   - not covered by its producer: carried, not re-checked;
//   - covered: resolved on evidence (file changed, file removed, producer
//     changed, N unchanged absences), otherwise carried as unconfirmed.
func Plan(previous, current Snapshot, opts Options) ([]Carry, []Resolution) {
	reported := make(map[string]struct{}, len(current.Rows))
	for _, row := range current.Rows {
		if row.Presence != "" && row.Presence != store.PresenceReported {
			continue // an existing carried row is what this plan replaces
		}
		if key := FindingKey(row); key != "" {
			reported[key] = struct{}{}
		}
	}
	// Identities reported now, to recognise a finding whose fingerprint
	// changed while it stayed put (ADR-034 §7: the switch to content
	// fingerprints re-keyed every finding of fingerprint-less scanners).
	reportedIdentities := make(map[string]string, len(current.Rows))
	for _, row := range current.Rows {
		if row.Presence != "" && row.Presence != store.PresenceReported {
			continue
		}
		if id := IdentityKey(row); id != "" {
			reportedIdentities[id] = row.Fingerprint
		}
	}
	runsByProducer := groupRuns(current.Runs)
	previousRuns := groupRuns(previous.Runs)

	carries := make([]Carry, 0)
	resolutions := make([]Resolution, 0)
	seen := make(map[string]struct{})
	for _, row := range previous.Rows {
		if row.Status == "resolved" {
			continue
		}
		producer := ProducerOf(row)
		key := FindingKey(row)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if _, ok := reported[key]; ok {
			continue
		}

		carry := Carry{
			Source:              row,
			LastSeenSnapshotID:  previous.ID,
			LastSeenCommit:      previous.CommitSHA,
			ConsecutiveAbsences: row.ConsecutiveAbsences,
		}
		if row.Presence != "" && row.Presence != store.PresenceReported {
			if row.LastSeenSnapshotID != nil {
				carry.LastSeenSnapshotID = *row.LastSeenSnapshotID
			}
			if row.LastSeenCommit != nil {
				carry.LastSeenCommit = *row.LastSeenCommit
			}
		}

		// Same finding, same line, reported under another fingerprint: it was
		// re-keyed, not fixed. Carrying the old row would show it twice; it
		// is closed as a producer-side change (its triage already moved to
		// the new fingerprint, carryTriageAcrossRekeys). This also closes the
		// duplicates carried before this rule existed.
		if producer != "" {
			if fp, ok := reportedIdentities[IdentityKey(row)]; ok && fp != row.Fingerprint {
				resolutions = append(resolutions, Resolution{Source: row, Producer: producer, Reason: ResolvedProducerChanged})
				continue
			}
		}

		file := ptrString(row.FilePath)
		if producer == "" {
			// An assertion: nothing re-checks it, only a decision ends it.
			if opts.ClosedAssertions[row.Fingerprint] {
				continue
			}
			carry.Presence = store.PresenceNotRechecked
			carry.Reason = ReasonAssertion
			if file != "" && opts.changed(carry.LastSeenCommit, file).Removed {
				carry.Reason = ReasonLocationGone
			}
			carries = append(carries, carry)
			continue
		}
		traceFiles := TraceFiles(row)
		// A taint finding is only re-checked by a full-scope run: a partial
		// scan that saw the sink may have missed the source (ADR-036 §6).
		run, reason := coveringRun(runsByProducer[producer], file, len(traceFiles) > 0)
		policy := opts.policy(producer)
		if run == nil {
			if policy.Kind == PolicyRetired && len(runsByProducer[producer]) == 0 {
				resolutions = append(resolutions, Resolution{Source: row, Producer: producer, Reason: ResolvedProducerRetired})
				continue
			}
			carry.Presence = store.PresenceNotRechecked
			carry.Reason = reason
			carries = append(carries, carry)
			continue
		}

		if policy.Kind == PolicyRetired {
			policy.Kind = PolicyCoverage // it ran again: the usual rules
		}
		resolve := func(reason string) {
			resolutions = append(resolutions, Resolution{Source: row, Producer: producer, Reason: reason})
		}
		unconfirmed := func(reason string) {
			carry.Presence = store.PresenceUnconfirmed
			carry.Reason = reason
			carry.ConsecutiveAbsences = row.ConsecutiveAbsences + 1
			carries = append(carries, carry)
		}

		if policy.Kind == PolicyExplicit {
			unconfirmed(ReasonExplicitPolicy)
			continue
		}
		if producerChanged(previousRuns[producer], *run) {
			resolve(ResolvedProducerChanged)
			continue
		}
		if file != "" && opts.changed(carry.LastSeenCommit, file).Removed {
			resolve(ResolvedFileRemoved)
			continue
		}
		absences := row.ConsecutiveAbsences + 1
		if policy.Kind == PolicyConsecutiveAbsence {
			if absences >= policy.Threshold {
				resolve(ResolvedNoLongerReported)
			} else {
				unconfirmed(ReasonAbsentCount)
			}
			continue
		}

		// Coverage policy: the code must have changed where the finding is.
		relevant := traceFiles
		if file != "" {
			relevant = appendUnique(relevant, file)
		}
		known, changed, deferred := false, false, false
		for _, path := range relevant {
			change := opts.changed(carry.LastSeenCommit, path)
			if change.Deferred {
				deferred = true
				continue
			}
			if !change.Known {
				continue
			}
			known = true
			if change.Changed || change.Removed {
				changed = true
				break
			}
		}
		switch {
		case changed:
			resolve(ResolvedFixed)
		case deferred:
			unconfirmed(ReasonChangeUnchecked)
		case !known:
			// The forge cannot answer: coverage alone decides (ADR-034 §3).
			resolve(ResolvedFixed)
		case absences >= policy.Threshold:
			resolve(ResolvedNoLongerReported)
		case len(traceFiles) > 0:
			unconfirmed(ReasonUnchangedTrace)
		default:
			unconfirmed(ReasonUnchanged)
		}
	}
	return carries, resolutions
}

func groupRuns(runs []store.ProducerRun) map[string][]store.ProducerRun {
	out := make(map[string][]store.ProducerRun)
	for _, run := range runs {
		out[run.Producer] = append(out[run.Producer], run)
	}
	return out
}

// producerChanged: the run that covered the finding differs in version or
// ruleset from the producer's run in the previous snapshot. Both sides must
// say: an unknown version is not a change.
func producerChanged(previous []store.ProducerRun, current store.ProducerRun) bool {
	differs := func(before, after *string) bool {
		return before != nil && after != nil && *before != "" && *after != "" && *before != *after
	}
	for _, run := range previous {
		if run.Outcome == store.ProducerOutcomeFailed || run.Outcome == "" {
			continue
		}
		if differs(run.Version, current.Version) || differs(run.ConfigDigest, current.ConfigDigest) {
			return true
		}
	}
	return false
}

// TraceFiles reads metadata.trace_files: the files a taint finding's code
// flows pass through.
func TraceFiles(vuln store.Vulnerability) []string {
	if len(vuln.Metadata) == 0 {
		return nil
	}
	var metadata struct {
		TraceFiles []string `json:"trace_files"`
	}
	if err := json.Unmarshal(vuln.Metadata, &metadata); err != nil {
		return nil
	}
	return metadata.TraceFiles
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(append([]string(nil), values...), value)
}

// Covered reports whether one of a producer's runs on the snapshot looked at
// a file, and when none did, why.
func Covered(runs []store.ProducerRun, file string) (bool, string) {
	run, reason := coveringRun(runs, file, false)
	return run != nil, reason
}

// coveringRun returns the first run that covered a file, or nil and why none
// did. A run covers a file when it finished (completed or partial), did not
// skip the file, had it in scope, and left no diagnostic that names no file
// (a rule that failed to load leaves the whole run in doubt). requireFull
// also rejects partial-scope runs.
func coveringRun(runs []store.ProducerRun, file string, requireFull bool) (*store.ProducerRun, string) {
	if len(runs) == 0 {
		return nil, ReasonProducerMissing
	}
	file = normalizePath(file)
	reason := ReasonProducerFailed
	for i := range runs {
		run := &runs[i]
		switch run.Outcome {
		case "":
			reason = strongerReason(reason, ReasonProducerPending)
			continue
		case store.ProducerOutcomeFailed:
			continue
		}
		if skip, ok := skippedReason(*run, file); ok {
			reason = strongerReason(reason, ReasonFileSkippedPrefix+skip)
			continue
		}
		if run.Scope == store.ProducerScopePartial {
			if requireFull || len(run.ScopePaths) == 0 {
				reason = strongerReason(reason, ReasonPartialScope)
				continue
			}
			if file == "" || !underAny(file, run.ScopePaths) {
				reason = strongerReason(reason, ReasonOutsideScope)
				continue
			}
		}
		if run.Outcome == store.ProducerOutcomePartial && run.Detail != nil && strings.TrimSpace(*run.Detail) != "" {
			reason = strongerReason(reason, ReasonPartialRun)
			continue
		}
		return run, ""
	}
	return nil, reason
}

// reasonRank orders reasons by how much they say: a named skipped file beats
// "the producer failed".
var reasonRank = map[string]int{
	ReasonProducerFailed:  1,
	ReasonProducerPending: 2,
	ReasonPartialScope:    3,
	ReasonPartialRun:      4,
	ReasonOutsideScope:    5,
}

func strongerReason(current, candidate string) string {
	rank := func(reason string) int {
		if strings.HasPrefix(reason, ReasonFileSkippedPrefix) {
			return 6
		}
		return reasonRank[reason]
	}
	if rank(candidate) > rank(current) {
		return candidate
	}
	return current
}

func skippedReason(run store.ProducerRun, file string) (string, bool) {
	if file == "" {
		return "", false
	}
	for _, skipped := range run.SkippedFiles {
		if normalizePath(skipped.Path) == file {
			reason := skipped.Reason
			if reason == "" {
				reason = "other"
			}
			return reason, true
		}
	}
	return "", false
}

func underAny(file string, paths []string) bool {
	for _, path := range paths {
		path = strings.TrimSuffix(normalizePath(path), "/")
		if path == "" || path == "." || file == path || strings.HasPrefix(file, path+"/") {
			return true
		}
	}
	return false
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "file://")
	for strings.HasPrefix(path, "./") {
		path = path[2:]
	}
	return path
}

// FindingKey is the identity a finding keeps across snapshots: the delta's
// key (fingerprint) scoped by type, since the unique key of a snapshot's rows
// is (type, fingerprint).
func FindingKey(vuln store.Vulnerability) string {
	fingerprint := strings.TrimSpace(vuln.Fingerprint)
	if fingerprint == "" {
		return ""
	}
	return vuln.Type + "|" + fingerprint
}

func ptrString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// ReasonText is the human wording of a presence reason, shared by the PR
// comment and the API consumers that render it server-side.
func ReasonText(reason string) string {
	switch {
	case reason == ReasonProducerMissing:
		return "did not run on this build"
	case reason == ReasonProducerFailed:
		return "failed on this build"
	case reason == ReasonProducerPending:
		return "had not finished"
	case reason == ReasonOutsideScope:
		return "scanned only part of the code, not these files"
	case reason == ReasonPartialScope:
		return "ran a partial scan without saying what it covered"
	case reason == ReasonPartialRun:
		return "reported errors that may have skipped these findings"
	case strings.HasPrefix(reason, ReasonFileSkippedPrefix):
		return "skipped the file (" + strings.ReplaceAll(strings.TrimPrefix(reason, ReasonFileSkippedPrefix), "_", " ") + ")"
	case reason == ReasonUnchanged:
		return "disappeared, but the file did not change"
	case reason == ReasonUnchangedTrace:
		return "disappeared, but no file of its data flow changed"
	case reason == ReasonAbsentCount:
		return "absent, not yet for enough scans to resolve it"
	case reason == ReasonChangeUnchecked:
		return "disappeared; whether its code changed is checked on the next scan"
	case reason == ReasonExplicitPolicy:
		return "absent; this producer's findings are only resolved by a decision"
	case reason == ReasonAssertion:
		return "filed by a person or an agent; only an explicit decision resolves them"
	case reason == ReasonLocationGone:
		return "filed by a person or an agent; its file is gone, needs review"
	case reason == "":
		return "not re-checked since an earlier build"
	}
	return reason
}

// IdentityKey is a fingerprint-independent content identity: what the finding
// is and where it lives. Scanner name is case-normalized (SARIF driver names
// changed casing once already).
func IdentityKey(vuln store.Vulnerability) string {
	identifier := strings.TrimSpace(vuln.PrimaryIdentifierValue)
	purl := strings.TrimSpace(ptrString(vuln.ComponentPurl))
	filePath := strings.TrimSpace(ptrString(vuln.FilePath))
	// Without something that names WHAT the finding is or WHERE it lives, two
	// rows cannot be asserted identical — return no key rather than cancel
	// unrelated findings that merely share a type.
	if identifier == "" && purl == "" && filePath == "" {
		return ""
	}
	parts := []string{
		strings.ToLower(strings.TrimSpace(vuln.Type)),
		strings.ToLower(strings.TrimSpace(vuln.ScannerName)),
		identifier,
		purl,
		filePath,
	}
	if vuln.StartLine != nil {
		parts = append(parts, strconv.FormatInt(int64(*vuln.StartLine), 10))
	}
	return strings.Join(parts, "|")
}

// Package incident holds the incident model of ADR-053 as pure functions: the
// kinds and their states, the regimes and their clocks, the rules that open
// incidents, and the derivation of scope, actions and closure from facts the
// caller gathers. Nothing here touches a database; internal/server gathers the
// facts, persists what Derive returns, and runs the side effects.
package incident

import (
	"slices"
	"time"
)

// Kinds (ADR-053 §1). A kind says what an incident is about and how its scope
// and actions are derived.
const (
	KindExploitedVulnerability = "exploited_vulnerability"
	KindSevereIncident         = "severe_incident"
	KindSecretLeak             = "secret_leak"
	KindMalware                = "malware"
	KindPolicyBreach           = "policy_breach"
)

// Kinds lists every registered kind, in display order.
var Kinds = []string{KindExploitedVulnerability, KindSevereIncident, KindSecretLeak, KindMalware, KindPolicyBreach}

// KindLabel is the human name of a kind.
func KindLabel(kind string) string {
	switch kind {
	case KindExploitedVulnerability:
		return "Exploited vulnerability"
	case KindSevereIncident:
		return "Security incident (CRA Art. 14(3))"
	case KindSecretLeak:
		return "Secret leak"
	case KindMalware:
		return "Malicious package"
	case KindPolicyBreach:
		return "Policy breach"
	default:
		return kind
	}
}

// States (ADR-053 §10).
const (
	StateSignal        = "signal"
	StateAssessing     = "assessing"
	StateReportable    = "reportable"
	StateNotReportable = "not_reportable"
	StateConfirmed     = "confirmed"
	StateDismissed     = "dismissed"
	StateClosed        = "closed"
	StateWithdrawn     = "withdrawn"
)

// Open reports whether an incident in this state still has work.
func Open(state string) bool {
	return state != StateClosed && state != StateWithdrawn
}

// Decided reports whether a person made the decision step.
func Decided(state string) bool {
	switch state {
	case StateReportable, StateNotReportable, StateConfirmed, StateDismissed:
		return true
	}
	return false
}

// HidingDecision reports whether a decision is one the four-eyes rule
// applies to: the decisions that end obligations (ADR-053 §2).
func HidingDecision(state string) bool {
	return state == StateNotReportable || state == StateDismissed
}

// Subject types: what an incident is about, for the one-open-incident rule.
const (
	SubjectAdvisory = "advisory"
	SubjectFinding  = "finding"
	SubjectNone     = "none"
)

// Signal sources (ADR-053 §10).
var SignalSources = []string{"kev", "euvd", "epss", "trigger", "customer", "csirt", "researcher", "internal", "other"}

// SignalSourceKnown reports whether source is a recorded signal source.
func SignalSourceKnown(source string) bool {
	return slices.Contains(SignalSources, source)
}

// Decision steps of the exploited-vulnerability ladder (ADR-053, "The
// decision ladder"), after the Commission guidance on the CRA, C(2026) 5252,
// §218: a third-party vulnerability is reportable by the integrating
// manufacturer only when it is contained in the product, can be exploited in
// the product, and has been exploited in the product. Each earlier exit is a
// VEX statement on the releases in scope.
const (
	// StepNotPresent: no shipped version integrates the vulnerable version
	// (VEX not_affected, component_not_present).
	StepNotPresent = "not_present"
	// StepNotReachable: present, but it cannot be exploited in the product,
	// e.g. the vulnerable code is not reachable (VEX not_affected with the
	// justification that says why).
	StepNotReachable = "not_reachable"
	// StepReachableNoAttack: exploitable in the product, no reliable evidence
	// it was exploited in the product (VEX affected; fix owed, no filing).
	StepReachableNoAttack = "reachable_no_attack"
	// StepAttacked: reliable evidence it was exploited in the product
	// (reportable; T0 starts the clocks).
	StepAttacked = "attacked"
)

// DecisionSteps lists the ladder in order.
var DecisionSteps = []string{StepNotPresent, StepNotReachable, StepReachableNoAttack, StepAttacked}

// StepReportable reports whether a ladder step ends in a mandatory report.
func StepReportable(step string) bool { return step == StepAttacked }

// VEX justifications a "cannot be exploited in the product" exit may carry.
var NotExploitableJustifications = []string{
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
	"vulnerable_code_not_present",
}

// StepStatement gives the VEX status and justification a ladder step means
// for the releases in scope; the justification is the caller's for the
// not-reachable step (defaulting to the execute-path one) and empty for an
// affected status.
func StepStatement(step, justification string) (status, just string) {
	switch step {
	case StepNotPresent:
		return "not_affected", "component_not_present"
	case StepNotReachable:
		if !slices.Contains(NotExploitableJustifications, justification) {
			justification = NotExploitableJustifications[0]
		}
		return "not_affected", justification
	case StepReachableNoAttack, StepAttacked:
		return "affected", ""
	}
	return "", ""
}

// HasExternalRegime reports whether any regime carries external filings; such
// incidents decide reportable / not reportable, the others confirmed /
// dismissed.
func HasExternalRegime(regimes []string) bool {
	for _, regime := range regimes {
		if regime != RegimeInternal {
			return true
		}
	}
	return false
}

// DecisionStates returns the two states a decision can move an incident to.
func DecisionStates(regimes []string) (positive, negative string) {
	if HasExternalRegime(regimes) {
		return StateReportable, StateNotReportable
	}
	return StateConfirmed, StateDismissed
}

// ValidDecision reports whether state is a decision the incident accepts.
func ValidDecision(regimes []string, state string) bool {
	positive, negative := DecisionStates(regimes)
	return state == positive || state == negative
}

// Priorities are the team's own triage order, not a regulatory concept.
var Priorities = []string{"P1", "P2", "P3"}

// ValidPriority reports whether p is P1, P2 or P3.
func ValidPriority(p string) bool { return slices.Contains(Priorities, p) }

func earliest(times ...*time.Time) *time.Time {
	var out *time.Time
	for _, candidate := range times {
		if candidate == nil {
			continue
		}
		if out == nil || candidate.Before(*out) {
			value := *candidate
			out = &value
		}
	}
	return out
}

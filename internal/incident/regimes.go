package incident

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Regimes (ADR-053 §1): which external obligations attach to an incident —
// clocks, filings, recipients. The built-ins are data; national regimes come
// from organisation settings.
const (
	RegimeCRA      = "cra-article-14"
	RegimeNIS2     = "nis2-article-23"
	RegimeInternal = "internal"
)

// Deadline steps.
const (
	StepEarlyWarning = "early_warning"
	StepNotification = "notification"
	StepFinalReport  = "final_report"
	StepResolve      = "resolve"
)

// Anchors a deadline counts from.
const (
	AnchorAware        = "aware"
	AnchorSignal       = "signal"
	AnchorFixAvailable = "fix_available"
	AnchorNotification = "notification"
)

// StepSpec is one clock of a regime.
type StepSpec struct {
	Step   string `json:"step"`
	Label  string `json:"label"`
	Anchor string `json:"anchor"`
	After  string `json:"after"` // a Go duration, or "1mo" for one calendar month
	// Filing is the action kind recording that the step was filed; empty for
	// an internal target with nothing to file.
	Filing    string `json:"filing,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	// URL is where the filing is made, when the recipient has a portal.
	URL string `json:"url,omitempty"`
}

// SRPPortalURL is ENISA's single reporting platform (Art. 16), where every
// CRA Article 14 filing is made by a registered representative.
const SRPPortalURL = "https://portal.cra-srp.enisa.europa.eu/"

// Regime is a set of clocks.
type Regime struct {
	Name  string     `json:"name"`
	Label string     `json:"label"`
	Steps []StepSpec `json:"steps"`
}

// NationalRegime is an organisation-configured national rule.
type NationalRegime struct {
	Code      string             `json:"code"`
	Label     string             `json:"label"`
	Recipient string             `json:"recipient"`
	URL       string             `json:"url,omitempty"`
	Steps     []NationalStepSpec `json:"steps"`
}

// NationalStepSpec is one step of a national regime, counted from awareness.
type NationalStepSpec struct {
	Name  string `json:"name"`
	Hours int    `json:"hours"`
}

// InternalTargets are an organisation's targets stricter than the regulation;
// the regulatory deadline stays shown next to them.
type InternalTargets struct {
	EarlyWarningHours int `json:"early_warning_hours,omitempty"`
	NotificationHours int `json:"notification_hours,omitempty"`
}

// Deadline is one computed clock.
type Deadline struct {
	Regime string    `json:"regime"`
	Step   string    `json:"step"`
	Label  string    `json:"label"`
	DueAt  time.Time `json:"due_at"`
	Filing string    `json:"filing,omitempty"`
	// Pending: the step's clock has not started (its anchor — the fix, the
	// notification — is not known yet). The filing is still owed; DueAt is
	// zero.
	Pending bool `json:"pending,omitempty"`
}

// FilingKinds lists every action kind that records a filing.
func FilingKinds(regime Regime) []string {
	out := []string{}
	for _, step := range regime.Steps {
		if step.Filing != "" {
			out = append(out, step.Filing)
		}
	}
	return out
}

// BuiltinRegime returns a built-in regime for the given incident kind; the CRA
// final report counts from the fix for a vulnerability and from the
// notification for a severe incident (Art. 14(2)(c), 14(4)(c)).
func BuiltinRegime(name, kind string) (Regime, bool) {
	switch name {
	case RegimeCRA:
		final := StepSpec{Step: StepFinalReport, Label: "Final report", Anchor: AnchorFixAvailable, After: "336h", Filing: "srp_final_report", Recipient: "Single reporting platform", URL: SRPPortalURL}
		if kind == KindSevereIncident {
			final.Anchor, final.After = AnchorNotification, "1mo"
		}
		return Regime{Name: RegimeCRA, Label: "CRA Article 14", Steps: []StepSpec{
			{Step: StepEarlyWarning, Label: "Early warning", Anchor: AnchorAware, After: "24h", Filing: "srp_early_warning", Recipient: "Single reporting platform", URL: SRPPortalURL},
			{Step: StepNotification, Label: "Notification", Anchor: AnchorAware, After: "72h", Filing: "srp_notification", Recipient: "Single reporting platform", URL: SRPPortalURL},
			final,
		}}, true
	case RegimeNIS2:
		return Regime{Name: RegimeNIS2, Label: "NIS2 Article 23", Steps: []StepSpec{
			{Step: StepEarlyWarning, Label: "Early warning", Anchor: AnchorAware, After: "24h", Filing: "csirt_early_warning", Recipient: "CSIRT"},
			{Step: StepNotification, Label: "Incident notification", Anchor: AnchorAware, After: "72h", Filing: "csirt_notification", Recipient: "CSIRT"},
			{Step: StepFinalReport, Label: "Final report", Anchor: AnchorNotification, After: "1mo", Filing: "csirt_final_report", Recipient: "CSIRT"},
		}}, true
	case RegimeInternal:
		return Regime{Name: RegimeInternal, Label: "Internal targets"}, true
	}
	return Regime{}, false
}

// ResolveRegime returns a built-in or a configured national regime.
func ResolveRegime(name, kind string, national []NationalRegime) (Regime, bool) {
	if regime, ok := BuiltinRegime(name, kind); ok {
		return regime, true
	}
	code := strings.TrimPrefix(name, "national:")
	if code == name {
		return Regime{}, false
	}
	for _, configured := range national {
		if configured.Code != code {
			continue
		}
		regime := Regime{Name: name, Label: firstNonEmpty(configured.Label, "National rule "+code)}
		for _, step := range configured.Steps {
			slug := slugStep(step.Name)
			regime.Steps = append(regime.Steps, StepSpec{
				Step: slug, Label: step.Name, Anchor: AnchorAware, After: fmt.Sprintf("%dh", step.Hours),
				Filing: "national_" + code + "_" + slug, Recipient: configured.Recipient, URL: configured.URL,
			})
		}
		return regime, true
	}
	return Regime{}, false
}

func slugStep(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "_") {
				b.WriteByte('_')
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

// Anchors carries the instants deadlines count from.
type Anchors struct {
	Signal          time.Time
	Aware           *time.Time
	FixAvailable    *time.Time
	NotificationMet *time.Time
}

// ComputeDeadlines returns every clock of an incident: each regime's steps
// whose anchor is known, the organisation's stricter internal targets for
// incidents with an external regime, and a rule's own `due`.
func ComputeDeadlines(kind string, regimes []string, anchors Anchors, national []NationalRegime, targets InternalTargets, ruleDue time.Duration) []Deadline {
	out := []Deadline{}
	for _, name := range regimes {
		regime, ok := ResolveRegime(name, kind, national)
		if !ok {
			continue
		}
		var notificationDue *time.Time
		for _, step := range regime.Steps {
			anchor := anchorTime(step.Anchor, anchors, notificationDue)
			if anchor == nil {
				// Steps counted from awareness have no clock before T0; the
				// others are owed but not yet clocked.
				if step.Anchor != AnchorAware && anchors.Aware != nil {
					out = append(out, Deadline{Regime: regime.Name, Step: step.Step, Label: step.Label, Filing: step.Filing, Pending: true})
				}
				continue
			}
			due := addAfter(*anchor, step.After)
			if step.Step == StepNotification {
				value := due
				notificationDue = &value
			}
			out = append(out, Deadline{Regime: regime.Name, Step: step.Step, Label: step.Label, DueAt: due, Filing: step.Filing})
		}
	}
	if HasExternalRegime(regimes) && anchors.Aware != nil {
		if targets.EarlyWarningHours > 0 {
			out = append(out, Deadline{Regime: RegimeInternal, Step: StepEarlyWarning, Label: "Internal target: early warning", DueAt: anchors.Aware.Add(time.Duration(targets.EarlyWarningHours) * time.Hour)})
		}
		if targets.NotificationHours > 0 {
			out = append(out, Deadline{Regime: RegimeInternal, Step: StepNotification, Label: "Internal target: notification", DueAt: anchors.Aware.Add(time.Duration(targets.NotificationHours) * time.Hour)})
		}
	}
	if ruleDue > 0 {
		start := anchors.Signal
		if anchors.Aware != nil {
			start = *anchors.Aware
		}
		out = append(out, Deadline{Regime: RegimeInternal, Step: StepResolve, Label: "Internal target: resolve", DueAt: start.Add(ruleDue)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pending != out[j].Pending {
			return !out[i].Pending
		}
		return out[i].DueAt.Before(out[j].DueAt)
	})
	return out
}

func anchorTime(anchor string, anchors Anchors, notificationDue *time.Time) *time.Time {
	switch anchor {
	case AnchorAware:
		return anchors.Aware
	case AnchorSignal:
		value := anchors.Signal
		return &value
	case AnchorFixAvailable:
		return anchors.FixAvailable
	case AnchorNotification:
		if anchors.NotificationMet != nil {
			return anchors.NotificationMet
		}
		return notificationDue
	}
	return nil
}

func addAfter(anchor time.Time, after string) time.Time {
	if after == "1mo" {
		return anchor.AddDate(0, 1, 0)
	}
	duration, err := time.ParseDuration(after)
	if err != nil {
		return anchor
	}
	return anchor.Add(duration)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

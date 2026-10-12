package sarif

import (
	"regexp"
	"strings"
)

// Skip reasons recorded for files a producer did not analyse (ADR-034 §2).
const (
	SkipReasonTimeout       = "timeout"
	SkipReasonTooLarge      = "too_large"
	SkipReasonParseError    = "parse_error"
	SkipReasonResourceLimit = "resource_limit"
	SkipReasonOther         = "other"
)

// Run outcomes, matching store.ProducerOutcome*.
const (
	RunOutcomeCompleted = "completed"
	RunOutcomePartial   = "partial"
	RunOutcomeFailed    = "failed"
)

// SkippedFile is one input the tool gave up on.
type SkippedFile struct {
	Path   string
	Reason string
}

// RunEvidence is what a SARIF run says about its own execution: who ran,
// which version, whether it finished, and what it skipped.
type RunEvidence struct {
	Producer string
	Version  string
	Outcome  string
	Skipped  []SkippedFile
	// Detail joins diagnostics that name no file (a rule that failed to
	// load, an engine crash); they make the run partial without saying where.
	Detail       string
	FindingCount int
}

// OpenGrep and Semgrep put the path in the message text only:
// "Timeout when running <rule> on <path>:\n ..." and
// "Syntax error at line <path>:<n>:\n ...".
var (
	notificationRunningOnPath = regexp.MustCompile(`when running \S+ on (.+?):\s*(?:\n|$)`)
	notificationAtLinePath    = regexp.MustCompile(`at line (.+?):\d+:`)
)

// ExtractRunEvidence returns one RunEvidence per run, in document order (the
// run_index of producer_runs). Producer naming matches ExtractFindings, so a
// run and its findings share a producer key.
func ExtractRunEvidence(doc *Document) []RunEvidence {
	if doc == nil {
		return nil
	}
	out := make([]RunEvidence, 0, len(doc.Runs))
	for _, run := range doc.Runs {
		evidence := RunEvidence{
			Producer:     strings.ToLower(strings.TrimSpace(run.Tool.Driver.Name)),
			Version:      strings.TrimSpace(run.Tool.Driver.Version),
			Outcome:      RunOutcomeCompleted,
			Skipped:      []SkippedFile{},
			FindingCount: len(run.Results),
		}
		if evidence.Version == "" {
			evidence.Version = strings.TrimSpace(run.Tool.Driver.SemanticVersion)
		}
		seen := map[string]struct{}{}
		details := make([]string, 0)
		for _, invocation := range run.Invocations {
			if invocation.ExecutionSuccessful != nil && !*invocation.ExecutionSuccessful {
				evidence.Outcome = RunOutcomeFailed
			}
			for _, notification := range invocation.ToolExecutionNotifications {
				if !notificationMatters(notification.Level) {
					continue
				}
				reason := notificationReason(notification)
				paths := notificationPaths(notification)
				if len(paths) == 0 {
					details = append(details, firstLine(notification.Message.Text))
					continue
				}
				for _, path := range paths {
					if _, dup := seen[path]; dup {
						continue
					}
					seen[path] = struct{}{}
					evidence.Skipped = append(evidence.Skipped, SkippedFile{Path: path, Reason: reason})
				}
			}
		}
		if evidence.Outcome != RunOutcomeFailed && (len(evidence.Skipped) > 0 || len(details) > 0) {
			evidence.Outcome = RunOutcomePartial
		}
		evidence.Detail = strings.Join(details, "; ")
		out = append(out, evidence)
	}
	return out
}

// notificationMatters keeps errors and warnings (the spec's default level is
// warning); notes are informational.
func notificationMatters(level string) bool {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "warning", "error":
		return true
	}
	return false
}

func notificationPaths(notification Notification) []string {
	paths := make([]string, 0, len(notification.Locations))
	for _, location := range notification.Locations {
		if uri := strings.TrimSpace(location.PhysicalLocation.ArtifactLocation.URI); uri != "" {
			paths = append(paths, uri)
		}
	}
	if len(paths) > 0 {
		return paths
	}
	text := notification.Message.Text
	for _, pattern := range []*regexp.Regexp{notificationRunningOnPath, notificationAtLinePath} {
		if match := pattern.FindStringSubmatch(text); len(match) == 2 {
			return []string{strings.TrimSpace(match[1])}
		}
	}
	return nil
}

func notificationReason(notification Notification) string {
	label := notification.Message.Text
	if notification.Descriptor != nil && notification.Descriptor.ID != "" {
		label = notification.Descriptor.ID
	}
	label = strings.ToLower(label)
	switch {
	case strings.Contains(label, "timeout") || strings.Contains(label, "timed out"):
		return SkipReasonTimeout
	case strings.Contains(label, "too large") || strings.Contains(label, "too big") || strings.Contains(label, "max-target-bytes"):
		return SkipReasonTooLarge
	case strings.Contains(label, "memory") || strings.Contains(label, "oom") || strings.Contains(label, "stack overflow"):
		return SkipReasonResourceLimit
	case strings.Contains(label, "syntax") || strings.Contains(label, "parse") || strings.Contains(label, "lexical") || strings.Contains(label, "ast builder"):
		return SkipReasonParseError
	}
	return SkipReasonOther
}

func firstLine(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	return strings.TrimSuffix(text, ":")
}

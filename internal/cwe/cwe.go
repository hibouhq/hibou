// Package cwe is hibou's single notion of a CWE (ADR-037): an integer
// identifier, a normalizer every producer goes through, and the embedded MITRE
// catalog that supplies titles, the View 1000 hierarchy and named sets.
package cwe

import (
	"regexp"
	"strconv"
	"strings"
)

// maxID bounds parsed identifiers; MITRE ids are four digits today, and the
// bound keeps garbage like "CWE-99999999999" from overflowing an int4 column.
const maxID = 9_999_999

// idPattern accepts the spellings producers use for one CWE: "CWE-79",
// "cwe-079", "79", "CWE 79" and the GitHub tag form "external/cwe/cwe-79".
// NVD's "NVD-CWE-Other" / "NVD-CWE-noinfo" deliberately do not match: they
// mean "no mapping", which is the absence of a CWE, not a CWE.
var idPattern = regexp.MustCompile(`(?i)^\s*(?:external/cwe/)?(?:cwe[-_ ]?)?0*([1-9][0-9]*)\s*$`)

// Parse normalizes one producer spelling to its integer id.
func Parse(value string) (int, bool) {
	match := idPattern.FindStringSubmatch(value)
	if match == nil {
		return 0, false
	}
	id, err := strconv.Atoi(match[1])
	if err != nil || id <= 0 || id > maxID {
		return 0, false
	}
	return id, true
}

// tagPattern is the anchored tag convention (ADR-037 §2.3): GitHub's
// "external/cwe/cwe-<n>" or a tag that starts with "CWE-<n>" (semgrep writes
// "CWE-78: Improper Neutralization of …"). A CWE mentioned mid-tag is not a
// classification.
var tagPattern = regexp.MustCompile(`(?i)^\s*(?:external/cwe/cwe-|cwe-)0*([1-9][0-9]*)(?:\b|$)`)

// ParseTag extracts the CWE a rule tag classifies the rule under.
func ParseTag(tag string) (int, bool) {
	match := tagPattern.FindStringSubmatch(tag)
	if match == nil {
		return 0, false
	}
	return Parse(match[1])
}

// ParseAll normalizes a list, dropping unparseable values and duplicates while
// keeping first-seen order.
func ParseAll(values []string) []int {
	out := make([]int, 0, len(values))
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		id, ok := Parse(value)
		if !ok {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// Format renders the display form, "CWE-79".
func Format(id int) string {
	return "CWE-" + strconv.Itoa(id)
}

// FormatAll renders a list in display form.
func FormatAll(ids []int) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, Format(id))
	}
	return out
}

// Dedupe returns ids without duplicates, in first-seen order.
func Dedupe(ids []int) []int {
	out := make([]int, 0, len(ids))
	seen := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup || id <= 0 {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// normalizeSetSlug lowercases and trims a named-set slug ("Top25" → "top25").
func normalizeSetSlug(slug string) string {
	return strings.ToLower(strings.TrimSpace(slug))
}

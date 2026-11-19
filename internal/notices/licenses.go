package notices

import (
	"regexp"
	"sort"
	"strings"

	"github.com/hibouhq/hibou/internal/license"
)

// Reuse the licence-policy grammar so nested OR choices retain their AND
// obligations and WITH exceptions.

// alternatives expands the valid conjunctive choices of an expression.
func alternatives(expression string) []string {
	options, err := license.Alternatives(expression)
	if err != nil {
		return []string{expression}
	}
	var out []string
	for _, option := range options {
		out = append(out, strings.Join(option, " AND "))
	}
	return out
}

// expressionIDs lists the licence identifiers of an expression.
func expressionIDs(expression string) []string {
	options, err := license.Alternatives(expression)
	if err != nil {
		return nil
	}
	var out []string
	for _, option := range options {
		for _, token := range option {
			id := strings.Split(token, " WITH ")[0]
			if id != "NOASSERTION" {
				out = append(out, id)
			}
		}
	}
	return uniqueSorted(out)
}

// chooseAlternative picks one alternative of an OR expression: the override's
// choice when it names one, otherwise the least demanding (ADR-051 §4). The
// licence policy is not consulted here: it lives on the server.
func chooseAlternative(expression, choose string) (chosen, reason string) {
	options := alternatives(expression)
	if len(options) <= 1 {
		return expression, ""
	}
	if choose = strings.TrimSpace(choose); choose != "" {
		for _, option := range options {
			if strings.EqualFold(option, choose) {
				return option, "override"
			}
		}
	}
	sort.SliceStable(options, func(i, j int) bool {
		ri, rj := demand(options[i]), demand(options[j])
		if ri != rj {
			return ri < rj
		}
		return options[i] < options[j]
	})
	return options[0], "least demanding"
}

// demand ranks how much a licence asks of a distributor: 0 attribution only,
// 1 source of the covered files, 2 corresponding source, 3 unknown.
func demand(expression string) int {
	worst := 0
	ids := expressionIDs(expression)
	if len(ids) == 0 {
		return 3
	}
	for _, id := range ids {
		rank := 3
		switch license.Categorize(id) {
		case license.CategoryCopyleft, license.CategoryNetworkCopyleft:
			rank = 2
		case license.CategoryWeakCopyleft:
			rank = 1
		case license.CategoryPermissive, license.CategoryPublicDomain:
			rank = 0
		}
		if rank > worst {
			worst = rank
		}
	}
	return worst
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// needsCopyrightLine reports whether the chosen licence asks to reproduce a
// copyright notice that normally sits in the licence file itself. Apache-2.0,
// MPL and the GPL family keep copyright in NOTICE files or source headers, so
// a licence text without a "Copyright" line is not a gap for them.
func needsCopyrightLine(expression string) bool {
	for _, id := range expressionIDs(expression) {
		upper := strings.ToUpper(id)
		if upper == "MIT" || upper == "ISC" || upper == "ZLIB" || upper == "X11" || strings.HasPrefix(upper, "BSD-") {
			return true
		}
	}
	return false
}

// dutyFor names what a licence requires beyond attribution, for a person to
// act on (ADR-051 §4 item 5). Hibou never claims these are fulfilled.
func dutyFor(id string) string {
	upper := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(upper, "AGPL-"):
		return "offer the corresponding source, including to users who interact with it over a network"
	case strings.HasPrefix(upper, "LGPL-"):
		return "provide the source of the library and allow relinking with a modified version"
	case strings.HasPrefix(upper, "GPL-"):
		return "offer the corresponding source of the whole work"
	case hasAnyPrefix(upper, "MPL-", "EPL-", "CDDL-", "EUPL-", "CPL-"):
		return "make the source of the covered files available"
	}
	return ""
}

var copyrightLine = regexp.MustCompile(`(?i)^\s*(?:[-*#/]+\s*)?((?:copyright\b|\(c\)|©).{3,300})$`)
var copyrightHasYearOrHolder = regexp.MustCompile(`(?i)(\d{4}|\(c\)|©|copyright\s+(?:by|holders?\b)?\s*[A-Za-z])`)

// copyrightNoise are template sentences that mention copyright without being
// a copyright notice.
var copyrightNoise = []string{
	"copyright notice", "copyright holder", "copyright owner", "copyright license", "copyright licence",
	"copyright law", "copyright statement", "copyright and", "copyright interest", "copyright rights",
	"copyright treaty", "copyright in ", "copyright on ", "copyright to ", "copyrightable",
	"copyright (c) <year>", "copyright [yyyy]", "copyright {yyyy}", "copyright (c) year",
}

// CopyrightLines extracts the copyright notices of a text, verbatim.
func CopyrightLines(text string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		match := copyrightLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		candidate := strings.TrimSpace(match[1])
		lower := strings.ToLower(candidate)
		noise := false
		for _, phrase := range copyrightNoise {
			if strings.Contains(lower, phrase) {
				noise = true
				break
			}
		}
		if noise || !copyrightHasYearOrHolder.MatchString(candidate) {
			continue
		}
		out = append(out, candidate)
	}
	return uniqueStable(out)
}

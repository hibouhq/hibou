package lsp

import (
	"path"
	"regexp"
	"strings"
)

// A suppression directive is written in the scanner's own syntax (ADR-026):
// hibou does not parse source comments, it trusts the suppressions the
// scanner reports in SARIF. Only scanners whose directive placement is
// unambiguous get a quick fix; others (checkov, trivy) would need the
// enclosing resource block and are left to the user.

type directivePlacement int

const (
	// placeTrailing appends the comment to the finding's first line.
	placeTrailing directivePlacement = iota
	// placeAbove inserts a comment line above it, at the same indentation.
	placeAbove
)

type directive struct {
	// text is the comment body without the comment leader.
	text      string
	placement directivePlacement
	// leaders lists the comment leaders the scanner understands; nil means
	// any leader of the file's language.
	leaders []string
	// reasonAbove, when set, is written as its own comment line above the
	// directive, for scanners that would misread trailing text.
	reasonAbove string
}

// safeRuleID keeps directives on one line and free of comment terminators.
var safeRuleID = regexp.MustCompile(`^[A-Za-z0-9_.:/@\-]+$`)

// directiveFor returns the directive suppressing f, or false when the scanner
// has none hibou can write safely. reason must be non-empty: a suppression
// without a justification is exactly what ADR-026 set out to avoid.
func directiveFor(f apiFinding, reason string) (directive, bool) {
	reason = sanitizeReason(reason)
	rule := f.ruleID()
	if reason == "" || (rule != "" && !safeRuleID.MatchString(rule)) {
		return directive{}, false
	}
	tool := strings.ToLower(f.ScannerName)

	switch {
	case strings.Contains(tool, "gosec"):
		// "// #nosec G101 -- reason": name the rule, carry the justification.
		if rule == "" {
			return directive{}, false
		}
		return directive{text: "#nosec " + rule + " -- " + reason, placement: placeTrailing, leaders: []string{"//"}}, true
	case strings.Contains(tool, "semgrep") || strings.Contains(tool, "opengrep"):
		if rule == "" {
			return directive{}, false
		}
		// Semgrep reads every word after "nosemgrep:" as a rule ID, so the
		// justification goes on its own comment line above.
		return directive{text: "nosemgrep: " + rule, placement: placeAbove, reasonAbove: reason}, true
	case strings.Contains(tool, "eslint"):
		if rule == "" {
			return directive{}, false
		}
		return directive{text: "eslint-disable-next-line " + rule + " -- " + reason, placement: placeAbove, leaders: []string{"//"}}, true
	case strings.Contains(tool, "bandit"):
		if rule == "" {
			return directive{}, false
		}
		// Bandit stops reading test IDs at the next "#".
		return directive{text: "nosec " + rule + " # " + reason, placement: placeTrailing, leaders: []string{"#"}}, true
	case strings.Contains(tool, "gitleaks"):
		// gitleaks matches the literal "gitleaks:allow" anywhere on the line.
		return directive{text: "gitleaks:allow -- " + reason, placement: placeTrailing}, true
	}
	return directive{}, false
}

// sanitizeReason flattens the justification to one line and removes
// sequences that would end a block comment early.
func sanitizeReason(reason string) string {
	reason = strings.Join(strings.Fields(reason), " ")
	reason = strings.ReplaceAll(reason, "*/", "* /")
	reason = strings.ReplaceAll(reason, "-->", "-- >")
	if len(reason) > 200 {
		reason = reason[:200]
	}
	return strings.TrimSpace(reason)
}

// commentLeader returns the line-comment leader for a file, or "" when the
// language has none hibou knows.
func commentLeader(filePath string) string {
	base := strings.ToLower(path.Base(filePath))
	switch base {
	case "dockerfile", "makefile", "containerfile", "gemfile", "rakefile", "jenkinsfile":
		if base == "jenkinsfile" {
			return "//"
		}
		return "#"
	}
	if strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		return "#"
	}
	switch path.Ext(base) {
	case ".go", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".java", ".kt", ".kts",
		".scala", ".groovy", ".gradle", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rs", ".swift",
		".dart", ".php", ".vue", ".svelte", ".proto":
		return "//"
	case ".py", ".rb", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".tf", ".hcl", ".toml", ".r",
		".pl", ".pm", ".ps1", ".cmake", ".nix", ".conf", ".ini", ".properties", ".env":
		return "#"
	case ".sql", ".lua", ".hs":
		return "--"
	}
	return ""
}

// directiveEdit computes the edit inserting d for a finding on line (0-based)
// of a file whose current content is lines. ok is false when the file's
// comment syntax does not fit the directive.
func directiveEdit(d directive, filePath string, lines []string, line int) (textEdit, bool) {
	leader := commentLeader(filePath)
	if leader == "" || line < 0 || line >= len(lines) {
		return textEdit{}, false
	}
	if d.leaders != nil && !contains(d.leaders, leader) {
		return textEdit{}, false
	}
	current := lines[line]
	switch d.placement {
	case placeTrailing:
		end := utf16Len(current)
		sep := " "
		if strings.TrimSpace(current) == "" {
			sep = ""
		}
		return textEdit{
			Range:   lspRange{Start: position{Line: line, Character: end}, End: position{Line: line, Character: end}},
			NewText: sep + leader + " " + d.text,
		}, true
	default:
		indent := current[:len(current)-len(strings.TrimLeft(current, " \t"))]
		text := indent + leader + " " + d.text + "\n"
		if d.reasonAbove != "" {
			text = indent + leader + " " + d.reasonAbove + "\n" + text
		}
		return textEdit{
			Range:   lspRange{Start: position{Line: line}, End: position{Line: line}},
			NewText: text,
		}, true
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// utf16Len is the LSP character offset of the end of s.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// Directive patterns, matched case-insensitively on the finding's lines. The
// optional capture lists the rule IDs a directive is limited to.
var (
	gosecDirective   = regexp.MustCompile(`(?i)#nosec\b([^-#\n]*)`)
	banditDirective  = regexp.MustCompile(`(?i)#\s*nosec\b:?([^#\n]*)`)
	semgrepDirective = regexp.MustCompile(`(?i)\bnosemgrep\b(?::\s*([^\n]*))?`)
	eslintSameLine   = regexp.MustCompile(`(?i)eslint-disable-line\b([^\n]*)`)
	eslintNextLine   = regexp.MustCompile(`(?i)eslint-disable-next-line\b([^\n]*)`)
	gitleaksAllow    = regexp.MustCompile(`(?i)gitleaks:allow\b`)
)

// suppressedInSource reports whether the current buffer already carries the
// scanner's native directive for f on its lines [start, end] (0-based), or on
// the line above for directives that apply to the next line. hibou learns
// about it at the next scan; until then the editor shows the finding as
// suppressed rather than open.
func suppressedInSource(f apiFinding, lines []string, start, end int) bool {
	if start < 0 || start >= len(lines) {
		return false
	}
	end = min(max(end, start), len(lines)-1)
	rule := f.ruleID()
	tool := strings.ToLower(f.ScannerName)
	on := func(re *regexp.Regexp, from, to int) bool {
		for i := max(from, 0); i <= to && i < len(lines); i++ {
			if m := re.FindStringSubmatch(lines[i]); m != nil {
				if len(m) < 2 || rulesCover(m[1], rule) {
					return true
				}
			}
		}
		return false
	}
	switch {
	case strings.Contains(tool, "gosec"):
		return on(gosecDirective, start, end)
	case strings.Contains(tool, "semgrep") || strings.Contains(tool, "opengrep"):
		return on(semgrepDirective, start-1, end)
	case strings.Contains(tool, "eslint"):
		return on(eslintSameLine, start, end) || on(eslintNextLine, start-1, start-1)
	case strings.Contains(tool, "bandit"):
		return on(banditDirective, start, end)
	case strings.Contains(tool, "gitleaks"):
		return on(gitleaksAllow, start, end)
	}
	return false
}

// rulesCover reports whether a directive's rule list (possibly empty, which
// means every rule) names rule.
func rulesCover(list, rule string) bool {
	ids := strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	if len(ids) == 0 || rule == "" {
		return true
	}
	for _, id := range ids {
		if strings.EqualFold(strings.TrimSpace(id), rule) {
			return true
		}
	}
	return false
}

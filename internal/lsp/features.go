package lsp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// placedFinding is a finding located in the current buffer.
type placedFinding struct {
	f      apiFinding
	start  int // 0-based, current buffer
	end    int
	edited bool // code changed since the scan
	// manifest is true for a dependency finding attached to the manifest line
	// declaring its component.
	manifest bool
	// inSource: the buffer already carries the scanner's suppression
	// directive; hibou will see it at the next scan.
	inSource bool
}

func (s *Server) visible(f apiFinding) bool {
	if f.Status == "detected" && f.Acceptance == nil {
		return true
	}
	return s.showSuppressed()
}

// place locates a document's findings in its current content.
func (s *Server) place(ctx context.Context, d document) []placedFinding {
	if d.ws == nil {
		return nil
	}
	snap, findings := d.ws.fileFindings(d.rel)
	var placed []placedFinding
	if snap != nil && len(findings) > 0 {
		maps := map[string]*lineMap{}
		mapFrom := func(commit string) *lineMap {
			if lm := maps[commit]; lm != nil {
				return lm
			}
			lm := identityLineMap(len(d.lines))
			if sf := d.ws.scannedLines(ctx, commit, d.rel); sf.known {
				lm = newLineMap(sf.lines, d.lines)
			}
			maps[commit] = lm
			return lm
		}
		for _, f := range findings {
			if !s.visible(f) {
				continue
			}
			start, end := f.StartLine-1, f.EndLine-1
			if start < 0 {
				start = 0
			}
			if end < start {
				end = start
			}
			ns, ne, edited := mapFrom(findingCommit(f, snap.Commit)).mapRange(start, end)
			placed = append(placed, placedFinding{f: f, start: ns, end: ne, edited: edited,
				inSource: f.Status == "detected" && suppressedInSource(f, d.lines, ns, ne)})
		}
	}
	placed = append(placed, s.manifestFindings(d)...)
	sort.SliceStable(placed, func(i, j int) bool { return placed[i].start < placed[j].start })
	return placed
}

// findingCommit is the commit a finding's lines refer to: the snapshot's for a
// reported finding, the commit where a carried one was last seen otherwise.
// Mapping a carried row from the snapshot commit put it on stale lines.
func findingCommit(f apiFinding, snapshotCommit string) string {
	if carried(f) && f.LastSeenCommit != "" {
		return f.LastSeenCommit
	}
	return snapshotCommit
}

// carried reports a finding the latest scan did not re-confirm (ADR-034).
func carried(f apiFinding) bool {
	return f.Presence != "" && f.Presence != "reported"
}

// Manifests dependency findings without a source location attach to.
var manifestFiles = map[string]bool{
	"go.mod": true, "package.json": true, "pom.xml": true, "build.gradle": true, "build.gradle.kts": true,
	"requirements.txt": true, "pyproject.toml": true, "pipfile": true, "cargo.toml": true, "gemfile": true,
	"composer.json": true, "packages.config": true, "directory.packages.props": true, "mix.exs": true,
	"pubspec.yaml": true, "package.swift": true,
}

// manifestFindings attaches the workspace's dependency findings that carry no
// file to the line of this manifest that declares their component.
func (s *Server) manifestFindings(d document) []placedFinding {
	base := strings.ToLower(path.Base(d.rel))
	if !manifestFiles[base] && !strings.HasSuffix(base, ".csproj") {
		return nil
	}
	ws := d.ws
	ws.mu.Lock()
	if ws.state != stateReady {
		ws.mu.Unlock()
		return nil
	}
	var deps []apiFinding
	for _, f := range ws.findings {
		if f.Type == "dependency" && f.FilePath == "" && f.ComponentName != "" {
			deps = append(deps, f)
		}
	}
	ws.mu.Unlock()

	var out []placedFinding
	for _, f := range deps {
		if !s.visible(f) {
			continue
		}
		if line := declarationLine(d.lines, f.ComponentName); line >= 0 {
			out = append(out, placedFinding{f: f, start: line, end: line, manifest: true})
		}
	}
	return out
}

// declarationLine finds the manifest line naming a component. Group/name
// coordinates (Maven "g:a", npm "@scope/name", Go module paths) match on
// their last segment only when the full name does not appear.
func declarationLine(lines []string, component string) int {
	names := []string{component}
	if i := strings.LastIndexAny(component, ":/"); i >= 0 && i < len(component)-1 && !strings.HasPrefix(component, "@") {
		names = append(names, component[i+1:])
	}
	for _, name := range names {
		for i, l := range lines {
			if containsToken(l, name) {
				return i
			}
		}
	}
	return -1
}

// containsToken reports whether name appears in line delimited by
// characters that cannot be part of a package name.
func containsToken(line, name string) bool {
	for from := 0; ; {
		i := strings.Index(line[from:], name)
		if i < 0 {
			return false
		}
		i += from
		before, after := byte(' '), byte(' ')
		if i > 0 {
			before = line[i-1]
		}
		if j := i + len(name); j < len(line) {
			after = line[j]
		}
		if !isNameChar(before) && !isNameChar(after) {
			return true
		}
		from = i + 1
	}
}

func isNameChar(c byte) bool {
	return c == '-' || c == '_' || c == '.' || c == '/' || c == '@' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func severityToLSP(sev string) int {
	switch sev {
	case "critical", "high":
		return severityError
	case "medium":
		return severityWarning
	case "low":
		return severityInformation
	}
	return severityHint
}

func (s *Server) publish(ctx context.Context, live *document) {
	d := s.snapshotDoc(live)
	version := d.version
	s.publishSnapshot(ctx, d, &version)
}

// publishSnapshot publishes d's diagnostics; version is nil for a closed file
// read from disk.
func (s *Server) publishSnapshot(ctx context.Context, d document, version *int) {
	placed := s.place(ctx, d)
	s.mu.Lock()
	server := s.server
	s.mu.Unlock()
	diags := make([]diagnostic, 0, len(placed))
	for _, p := range placed {
		diags = append(diags, s.toDiagnostic(server, d, p))
	}
	_ = s.conn.notify("textDocument/publishDiagnostics", publishDiagnosticsParams{URI: d.uri, Version: version, Diagnostics: diags})
}

func lineRange(lines []string, start, end int) lspRange {
	endChar := 0
	if end >= 0 && end < len(lines) {
		endChar = utf16Len(lines[end])
	}
	return lspRange{Start: position{Line: start}, End: position{Line: end, Character: endChar}}
}

func (s *Server) toDiagnostic(server string, d document, p placedFinding) diagnostic {
	f := p.f
	msg := f.Title
	if msg == "" {
		msg = f.Description
	}
	if p.manifest && f.ComponentName != "" {
		msg = fmt.Sprintf("%s %s: %s", f.ComponentName, f.ComponentVersion, msg)
	}
	var tags []string
	if f.KEV {
		tags = append(tags, "known exploited")
	}
	for _, c := range f.CWEs {
		tags = append(tags, fmt.Sprintf("CWE-%d", c.ID))
	}
	if len(tags) > 0 {
		msg += " [" + strings.Join(tags, ", ") + "]"
	}
	sev := severityToLSP(f.Severity)
	var diagTags []int
	switch {
	case f.Status == "suppressed":
		msg = "Suppressed: " + msg
		sev, diagTags = severityHint, []int{tagUnnecessary}
	case f.Acceptance != nil:
		msg = "Accepted (" + strings.ReplaceAll(f.Acceptance.ReasonKind, "_", " ") + "): " + msg
		sev, diagTags = severityHint, []int{tagUnnecessary}
	case p.inSource:
		msg = "Suppressed in source (takes effect at the next scan): " + msg
		sev, diagTags = severityHint, []int{tagUnnecessary}
	}
	if p.edited && !p.inSource {
		msg += " — code changed since the scan; may already be fixed"
	}
	if carried(f) {
		msg += " — not re-confirmed by the latest scan"
	}

	code := f.ruleID()
	if code == "" {
		code = f.AdvisoryID
	}
	diag := diagnostic{
		Range:    lineRange(d.lines, p.start, p.end),
		Severity: sev,
		Code:     code,
		Source:   "hibou",
		Message:  msg,
		Tags:     diagTags,
		Data:     &diagnosticData{Fingerprint: f.Fingerprint},
	}
	if repo := d.ws.repoRef(); repo != nil && code != "" {
		diag.CodeDescription = &codeDescription{Href: findingURL(server, *repo, f.Fingerprint)}
	}
	return diag
}

func (w *workspace) repoRef() *repoRef {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.repo
}

func findingURL(server string, r repoRef, fingerprint string) string {
	q := url.Values{}
	q.Set("finding", fingerprint)
	return webURL(server, r, q)
}

func (s *Server) hover(ctx context.Context, p textDocumentPositionParams) *hover {
	live := s.doc(p.TextDocument.URI)
	if live == nil {
		return nil
	}
	d := s.snapshotDoc(live)
	var hits []placedFinding
	for _, pf := range s.place(ctx, d) {
		if p.Position.Line >= pf.start && p.Position.Line <= pf.end {
			hits = append(hits, pf)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	s.mu.Lock()
	server := s.server
	s.mu.Unlock()
	repo := d.ws.repoRef()
	var parts []string
	for _, h := range hits {
		parts = append(parts, hoverMarkdown(server, repo, h))
	}
	r := lineRange(d.lines, hits[0].start, hits[0].end)
	return &hover{Contents: markupContent{Kind: "markdown", Value: strings.Join(parts, "\n\n---\n\n")}, Range: &r}
}

func hoverMarkdown(server string, repo *repoRef, p placedFinding) string {
	f := p.f
	var b strings.Builder
	title := f.Title
	if title == "" {
		title = "Finding"
	}
	fmt.Fprintf(&b, "**%s** · %s\n\n", mdEscape(title), strings.ToUpper(orDefault(f.Severity, "unknown")))

	var facts []string
	if f.ScannerName != "" {
		facts = append(facts, "Scanner: `"+mdCode(f.ScannerName)+"`")
	}
	if r := f.ruleID(); r != "" {
		facts = append(facts, "Rule: `"+mdCode(r)+"`")
	}
	if f.AdvisoryID != "" {
		facts = append(facts, "Advisory: `"+mdCode(f.AdvisoryID)+"`")
	}
	if f.ComponentName != "" {
		facts = append(facts, "Component: `"+mdCode(f.ComponentName+" "+f.ComponentVersion)+"`")
	}
	for _, c := range f.CWEs {
		facts = append(facts, fmt.Sprintf("CWE-%d %s", c.ID, mdEscape(c.Name)))
	}
	if f.CVSS != nil && f.CVSS.Score != nil {
		facts = append(facts, fmt.Sprintf("CVSS %s %.1f", f.CVSS.Version, *f.CVSS.Score))
	}
	if f.EPSS != nil {
		facts = append(facts, fmt.Sprintf("EPSS %.1f%% (percentile %.0f)", f.EPSS.Score*100, f.EPSS.Percentile*100))
	}
	if f.KEV {
		facts = append(facts, "**Known exploited (KEV)**")
	}
	if f.Reachability != "" && f.Reachability != "unknown" {
		facts = append(facts, "Reachability: "+strings.ReplaceAll(f.Reachability, "_", " "))
	}
	if f.FirstSeenAt != nil {
		facts = append(facts, "First seen "+f.FirstSeenAt.Format("2006-01-02"))
	}
	for _, fact := range facts {
		b.WriteString("- " + fact + "\n")
	}

	switch {
	case p.inSource:
		b.WriteString("\nSuppressed in source by a directive in this file. hibou records it at the next scan.\n")
	case f.Status == "suppressed":
		b.WriteString("\nSuppressed in source")
		if j := f.suppressionJustification(); j != "" {
			b.WriteString(": " + mdEscape(j))
		}
		b.WriteString("\n")
		if f.Dispute != nil {
			b.WriteString("\nDisputed: " + mdEscape(f.Dispute.Reason) + "\n")
		}
	case f.Acceptance != nil:
		fmt.Fprintf(&b, "\nAccepted as %s: %s\n", strings.ReplaceAll(f.Acceptance.ReasonKind, "_", " "), mdEscape(f.Acceptance.Reason))
	}
	if p.edited && !p.inSource {
		b.WriteString("\n_The code changed since this scan. The finding may already be fixed; the next scan will tell._\n")
	}
	if carried(f) {
		b.WriteString("\n_Not re-confirmed by the latest scan (" + strings.ReplaceAll(f.Presence, "_", " ") + "); shown where it was last seen._\n")
	}
	if desc := strings.TrimSpace(f.Description); desc != "" && desc != f.Title {
		b.WriteString("\n" + mdEscape(truncate(desc, 600)) + "\n")
	}
	if sol := strings.TrimSpace(f.Solution); sol != "" {
		b.WriteString("\n**Fix:** " + mdEscape(truncate(sol, 400)) + "\n")
	}
	if repo != nil {
		fmt.Fprintf(&b, "\n[Open in hibou](%s)", findingURL(server, *repo, f.Fingerprint))
	}
	return b.String()
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

// mdEscape keeps scanner-provided text from injecting links, images or HTML
// into the hover. Scanner messages come from analysed code and are untrusted.
func mdEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '`', '*', '_', '[', ']', '(', ')', '<', '>', '#', '!', '|', '{', '}':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func mdCode(s string) string { return strings.ReplaceAll(s, "`", "'") }

// reasonPlaceholder marks where the justification goes in a directive built
// for a snippet edit.
const reasonPlaceholder = "\x00reason\x00"

func (s *Server) codeActions(p codeActionParams) []codeAction {
	live := s.doc(p.TextDocument.URI)
	if live == nil || live.ws == nil {
		return []codeAction{}
	}
	d := s.snapshotDoc(live)
	s.mu.Lock()
	snippets := s.caps.Workspace.WorkspaceEdit.SnippetEditSupport && s.caps.Workspace.WorkspaceEdit.DocumentChanges
	s.mu.Unlock()

	seen := map[string]bool{}
	var actions []codeAction
	for _, diag := range p.Context.Diagnostics {
		if diag.Source != "hibou" || diag.Data == nil || seen[diag.Data.Fingerprint] {
			continue
		}
		fp := diag.Data.Fingerprint
		seen[fp] = true
		f, _, ok := d.ws.finding(fp)
		if !ok {
			continue
		}
		diags := []diagnostic{diag}
		actions = append(actions, codeAction{
			Title: "hibou: open finding in the browser", Kind: "quickfix", Diagnostics: diags,
			Command: &command{Title: "Open in hibou", Command: cmdOpenFinding, Arguments: []any{fp}},
		})

		inSource := suppressedInSource(f, d.lines, diag.Range.Start.Line, diag.Range.End.Line)
		if f.Status == "detected" && f.Acceptance == nil && !inSource {
			if _, ok := directiveFor(f, reasonPlaceholder); ok {
				line := diag.Range.Start.Line
				if snippets {
					if edit, ok := s.directiveWorkspaceEdit(d, f, line, reasonPlaceholder, true); ok {
						actions = append(actions, codeAction{Title: "hibou: suppress with a " + scannerLabel(f) + " directive", Kind: "quickfix", Diagnostics: diags, Edit: edit, IsPreferred: true})
					}
				} else {
					actions = append(actions, codeAction{
						Title: "hibou: suppress with a " + scannerLabel(f) + " directive…", Kind: "quickfix", Diagnostics: diags,
						Command: &command{Title: "Suppress", Command: clientCmdSuppress, Arguments: []any{map[string]any{"uri": d.uri, "fingerprint": fp, "line": line}}},
					})
				}
			}
			actions = append(actions,
				triageAction(diags, d.uri, fp, "accept", "hibou: accept the risk…"),
				triageAction(diags, d.uri, fp, "false_positive", "hibou: mark as false positive…"))
		}
		if f.Acceptance != nil {
			actions = append(actions, triageAction(diags, d.uri, fp, "reopen", "hibou: reopen (remove the acceptance)"))
		}
		if f.Status == "suppressed" {
			if f.Dispute == nil {
				actions = append(actions, triageAction(diags, d.uri, fp, "dispute", "hibou: dispute this suppression…"))
			} else {
				actions = append(actions, triageAction(diags, d.uri, fp, "undispute", "hibou: withdraw the dispute"))
			}
		}
	}
	if actions == nil {
		return []codeAction{}
	}
	return actions
}

func triageAction(diags []diagnostic, uri, fp, action, title string) codeAction {
	return codeAction{
		Title: title, Kind: "quickfix", Diagnostics: diags,
		Command: &command{Title: title, Command: clientCmdTriage, Arguments: []any{map[string]any{"uri": uri, "fingerprint": fp, "action": action}}},
	}
}

func scannerLabel(f apiFinding) string {
	tool := strings.ToLower(f.ScannerName)
	for _, name := range []string{"gosec", "opengrep", "semgrep", "eslint", "bandit", "gitleaks"} {
		if strings.Contains(tool, name) {
			return name
		}
	}
	return "scanner"
}

// directiveWorkspaceEdit builds the edit inserting f's directive above or on
// line. With snippet set, reason is replaced by a tab stop.
func (s *Server) directiveWorkspaceEdit(d document, f apiFinding, line int, reason string, snippet bool) (*workspaceEdit, bool) {
	dir, ok := directiveFor(f, reason)
	if !ok {
		return nil, false
	}
	edit, ok := directiveEdit(dir, d.rel, d.lines, line)
	if !ok {
		return nil, false
	}
	if !snippet {
		return &workspaceEdit{Changes: map[string][]textEdit{d.uri: {edit}}}, true
	}
	value := strings.ReplaceAll(snippetEscape(edit.NewText), snippetEscape(reasonPlaceholder), "${1:why this is safe}")
	version := d.version
	return &workspaceEdit{DocumentChanges: []textDocumentEdit{{
		TextDocument: optionalVersionedTextDocumentIdentifier{URI: d.uri, Version: &version},
		Edits:        []snippetTextEdit{{Range: edit.Range, Snippet: stringValue{Kind: "snippet", Value: value}}},
	}}}, true
}

func snippetEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `$`, `\$`, `}`, `\}`)
	return r.Replace(s)
}

type suppressionEditParams struct {
	URI         string `json:"uri"`
	Fingerprint string `json:"fingerprint"`
	Line        int    `json:"line"`
	Reason      string `json:"reason"`
}

// suppressionEdit is the non-snippet path: the client asked the user for the
// justification and wants the edit to apply.
func (s *Server) suppressionEdit(_ context.Context, p suppressionEditParams) (*workspaceEdit, error) {
	live := s.doc(p.URI)
	if live == nil || live.ws == nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "document is not open"}
	}
	if strings.TrimSpace(p.Reason) == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "a justification is required"}
	}
	d := s.snapshotDoc(live)
	f, _, ok := d.ws.finding(p.Fingerprint)
	if !ok {
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown finding"}
	}
	edit, ok := s.directiveWorkspaceEdit(d, f, p.Line, p.Reason, false)
	if !ok {
		return nil, &rpcError{Code: codeInvalidParams, Message: "this scanner has no directive hibou can write for this file"}
	}
	return edit, nil
}

type triageParams struct {
	Fingerprint string `json:"fingerprint"`
	URI         string `json:"uri"`
	// Action is accept, false_positive, reopen, dispute or undispute.
	Action string `json:"action"`
	Reason string `json:"reason"`
	// ExpiresInDays bounds a risk acceptance; 0 means no expiry.
	ExpiresInDays int `json:"expiresInDays"`
}

type triageResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// WebURL is set when the IDE cannot triage (missing permission) and the
	// user should continue in the browser.
	WebURL string `json:"webUrl,omitempty"`
}

// triage applies a phase-2 triage decision (ADR-042 §5). The server refuses
// it unless the token holds triage:write and the user is an org admin; the
// result then points to the finding in the browser.
func (s *Server) triage(ctx, sessionCtx context.Context, p triageParams) (*triageResult, error) {
	ws := s.workspaceOfFinding(p.URI, p.Fingerprint)
	if ws == nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown finding"}
	}
	f, repo, ok := ws.finding(p.Fingerprint)
	if !ok || repo == nil {
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown finding"}
	}
	client, err := s.api()
	if err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(p.Reason)
	needsReason := p.Action == "accept" || p.Action == "false_positive" || p.Action == "dispute"
	if needsReason && reason == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "a justification is required"}
	}

	switch p.Action {
	case "accept", "false_positive":
		req := acceptanceRequest{Status: "accepted", ReasonKind: "risk_accepted", Reason: reason}
		if p.Action == "false_positive" {
			req.ReasonKind = "false_positive"
		}
		if p.ExpiresInDays > 0 {
			exp := time.Now().Add(time.Duration(p.ExpiresInDays) * 24 * time.Hour).UTC()
			req.ExpiresAt = &exp
		}
		err = client.setAcceptance(ctx, *repo, f.ID, req)
	case "reopen":
		err = client.setAcceptance(ctx, *repo, f.ID, acceptanceRequest{Status: "open"})
	case "dispute":
		err = client.setDispute(ctx, *repo, f.ID, reason)
	case "undispute":
		err = client.deleteDispute(ctx, *repo, f.ID)
	default:
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown triage action " + p.Action}
	}

	s.mu.Lock()
	server := s.server
	s.mu.Unlock()
	link := findingURL(server, *repo, f.Fingerprint)
	var apiErr *apiError
	switch {
	case err == nil:
		// The finding list carries acceptance state: refetch it.
		ws.mu.Lock()
		ws.snapshot = nil
		ws.mu.Unlock()
		go s.refreshWorkspace(sessionCtx, ws, true)
		return &triageResult{OK: true, Message: "Saved in hibou."}, nil
	case isStatus(err, http.StatusForbidden):
		return &triageResult{Message: "Your IDE token cannot triage here: it needs the triage:write permission and the org admin role. Continue in the browser.", WebURL: link}, nil
	case errors.As(err, &apiErr) && (apiErr.Status == http.StatusBadRequest || apiErr.Status == http.StatusUnprocessableEntity):
		return &triageResult{Message: "hibou refused the change: " + apiErr.Message, WebURL: link}, nil
	default:
		return nil, err
	}
}

func (s *Server) workspaceOfFinding(uri, fingerprint string) *workspace {
	if d := s.doc(uri); d != nil {
		s.mu.Lock()
		ws := d.ws
		s.mu.Unlock()
		if ws != nil {
			return ws
		}
	}
	for _, ws := range s.allWorkspaces() {
		if _, _, ok := ws.finding(fingerprint); ok {
			return ws
		}
	}
	return nil
}

func (s *Server) executeCommand(ctx, sessionCtx context.Context, p executeCommandParams) (any, error) {
	switch p.Command {
	case cmdOpenFinding:
		var fp string
		if len(p.Arguments) > 0 {
			_ = json.Unmarshal(p.Arguments[0], &fp)
		}
		for _, ws := range s.allWorkspaces() {
			if _, repo, ok := ws.finding(fp); ok {
				s.mu.Lock()
				server, canShow := s.server, s.caps.Window.ShowDocument.Support
				s.mu.Unlock()
				link := findingURL(server, *repo, fp)
				if !canShow {
					return map[string]string{"url": link}, nil
				}
				return nil, s.conn.call(ctx, "window/showDocument", showDocumentParams{URI: link, External: true}, nil)
			}
		}
		return nil, &rpcError{Code: codeInvalidParams, Message: "unknown finding"}
	case cmdRefresh:
		s.refreshAll(sessionCtx, true)
		return nil, nil
	}
	return nil, &rpcError{Code: codeInvalidParams, Message: "unknown command " + p.Command}
}

// panelFinding is one row of the clients' findings panel.
type panelFinding struct {
	Fingerprint string   `json:"fingerprint"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	Accepted    bool     `json:"accepted"`
	Type        string   `json:"type"`
	Rule        string   `json:"rule,omitempty"`
	Scanner     string   `json:"scanner,omitempty"`
	Component   string   `json:"component,omitempty"`
	Path        string   `json:"path,omitempty"`
	URI         string   `json:"uri,omitempty"`
	Range       lspRange `json:"range"`
	Edited      bool     `json:"edited,omitempty"`
	KEV         bool     `json:"kev,omitempty"`
	WebURL      string   `json:"webUrl"`
}

// findingsFor lists findings for the panel: one document's when uri is set,
// else every workspace's. Positions use the open buffer when there is one.
func (s *Server) findingsFor(ctx context.Context, uri string) []panelFinding {
	s.mu.Lock()
	server := s.server
	s.mu.Unlock()
	out := []panelFinding{}
	if uri != "" {
		live := s.doc(uri)
		if live == nil {
			return out
		}
		d := s.snapshotDoc(live)
		repo := d.ws.repoRef()
		for _, p := range s.place(ctx, d) {
			out = append(out, toPanel(server, repo, p.f, d.rel, d.uri, lineRange(d.lines, p.start, p.end), p.edited))
		}
		return out
	}
	open := map[string]bool{}
	for _, ws := range s.allWorkspaces() {
		for _, d := range s.docsOf(ws) {
			snap := s.snapshotDoc(d)
			open[snap.uri] = true
			repo := ws.repoRef()
			for _, p := range s.place(ctx, snap) {
				out = append(out, toPanel(server, repo, p.f, snap.rel, snap.uri, lineRange(snap.lines, p.start, p.end), p.edited))
			}
		}
		ws.mu.Lock()
		findings, repo, root := ws.findings, ws.repo, ws.root
		ws.mu.Unlock()
		for _, f := range findings {
			if !s.visible(f) {
				continue
			}
			rel := normalizeRepoPath(f.FilePath)
			fileURI := ""
			if rel != "" && !isAbsScannerPath(f.FilePath) {
				fileURI = pathToURI(root + "/" + rel)
				if open[fileURI] {
					continue
				}
			}
			line := max(f.StartLine-1, 0)
			out = append(out, toPanel(server, repo, f, rel, fileURI, lspRange{Start: position{Line: line}, End: position{Line: line}}, false))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i].Severity) < severityRank(out[j].Severity) })
	return out
}

func toPanel(server string, repo *repoRef, f apiFinding, rel, uri string, r lspRange, edited bool) panelFinding {
	pf := panelFinding{
		Fingerprint: f.Fingerprint, Title: orDefault(f.Title, f.Description), Severity: f.Severity, Status: f.Status,
		Accepted: f.Acceptance != nil, Type: f.Type, Rule: f.ruleID(), Scanner: f.ScannerName, Path: rel, URI: uri,
		Range: r, Edited: edited, KEV: f.KEV,
	}
	if f.ComponentName != "" {
		pf.Component = strings.TrimSpace(f.ComponentName + " " + f.ComponentVersion)
	}
	if repo != nil {
		pf.WebURL = findingURL(server, *repo, f.Fingerprint)
	}
	return pf
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	}
	return 5
}

// coverageResult carries current-buffer line numbers (0-based). Lines edited
// since the scan are omitted: their coverage is unknown.
type coverageResult struct {
	Covered   []int  `json:"covered"`
	Uncovered []int  `json:"uncovered"`
	Partial   []int  `json:"partial"`
	Commit    string `json:"commit,omitempty"`
	Message   string `json:"message,omitempty"`
}

// coverage returns per-line coverage of a document (ADR-018 line hits),
// fetched on demand: the server reads the file from the forge to answer.
func (s *Server) coverage(ctx context.Context, uri string) (*coverageResult, error) {
	empty := &coverageResult{Covered: []int{}, Uncovered: []int{}, Partial: []int{}}
	live := s.doc(uri)
	if live == nil || live.ws == nil {
		empty.Message = "The file is not in a repository tracked by hibou."
		return empty, nil
	}
	d := s.snapshotDoc(live)
	ws := d.ws
	ws.mu.Lock()
	snap, repo := ws.snapshot, ws.repo
	key := ""
	if snap != nil {
		key = snap.ID + ":" + d.rel
	}
	cached := ws.coverage[key]
	ws.mu.Unlock()
	if snap == nil || repo == nil {
		empty.Message = "No hibou scan for this commit."
		return empty, nil
	}
	if cached == nil {
		client, err := s.api()
		if err != nil {
			return nil, err
		}
		src, err := client.coverageSource(ctx, *repo, snap.ID, d.rel)
		if err != nil {
			if isStatus(err, http.StatusNotFound) || isStatus(err, http.StatusUnprocessableEntity) {
				empty.Message = "No coverage recorded for this file."
				return empty, nil
			}
			return nil, err
		}
		cached = &src
		ws.mu.Lock()
		if len(ws.coverage) > 256 {
			ws.coverage = map[string]*apiCoverageSource{}
		}
		ws.coverage[key] = cached
		ws.mu.Unlock()
	}

	var lm *lineMap
	if sf := ws.scannedLines(ctx, snap.Commit, d.rel); sf.known {
		lm = newLineMap(sf.lines, d.lines)
	} else {
		lm = identityLineMap(len(d.lines))
	}
	res := &coverageResult{Covered: []int{}, Uncovered: []int{}, Partial: []int{}, Commit: snap.Commit}
	for _, l := range cached.Lines {
		i := l.Number - 1
		if i < 0 || i >= len(lm.newLine) || lm.newLine[i] < 0 {
			continue
		}
		line := lm.newLine[i]
		switch {
		case l.Hits == 0:
			res.Uncovered = append(res.Uncovered, line)
		case l.BranchesValid > 0 && l.BranchesCovered < l.BranchesValid:
			res.Partial = append(res.Partial, line)
		default:
			res.Covered = append(res.Covered, line)
		}
	}
	return res, nil
}

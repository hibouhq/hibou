package lsp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Workspace states reported to the clients.
const (
	stateUnconfigured = "unconfigured" // no server URL
	stateSignedOut    = "signedOut"    // no token, or the token was refused
	stateUntracked    = "untracked"    // repository not enrolled in hibou
	stateNoSnapshot   = "noSnapshot"   // enrolled, but no scan of an ancestor of HEAD
	stateReady        = "ready"
	stateError        = "error"
)

// snapshotPages bounds how far back the ancestor search looks (100 per page).
const snapshotPages = 3

// workspace is one git work tree and its hibou state.
type workspace struct {
	s    *Server
	root string
	git  git

	refreshMu sync.Mutex // serialises refreshes

	mu        sync.Mutex
	started   bool
	lastHead  string
	branch    string
	repo      *repoRef
	repoInfo  apiRepo
	state     string
	message   string
	snapshot  *pickedSnapshot
	findings  []apiFinding
	byPath    map[string][]int // repo-relative path -> indexes into findings
	byAbsPath map[string][]int // absolute scanner paths (CI checkout) -> indexes
	truncated bool
	pr        string
	gate      *apiGate
	ancestors map[string]bool // "sha head" -> isAncestor
	scanned   map[string]*scannedFile
	coverage  map[string]*apiCoverageSource
	refs      []apiRef
	diskKey   string          // snapshot@HEAD#digest the closed files were last published for
	digest    string          // findingsDigest of the current findings
	diskURIs  map[string]bool // closed files currently carrying diagnostics
}

type pickedSnapshot struct {
	ID        string    `json:"id"`
	Commit    string    `json:"commit"`
	Ref       string    `json:"ref"`
	CreatedAt time.Time `json:"createdAt"`
	// AtHead is true when the snapshot is of HEAD itself.
	AtHead bool `json:"atHead"`
}

type scannedFile struct {
	lines []string
	known bool // false: file absent at the commit or too large; identity mapping
}

func newWorkspace(s *Server, root string) *workspace {
	return &workspace{s: s, root: root, git: git{root: root}, state: stateNoSnapshot, ancestors: map[string]bool{}, scanned: map[string]*scannedFile{}, coverage: map[string]*apiCoverageSource{}}
}

func (w *workspace) isNew() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.started
}

// headMoved reports whether HEAD changed since the last refresh.
func (w *workspace) headMoved(ctx context.Context) bool {
	head, err := w.git.head(ctx)
	if err != nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.started && head != w.lastHead
}

// status is the hibou/status payload for one workspace.
type status struct {
	Root      string          `json:"root"`
	State     string          `json:"state"`
	Message   string          `json:"message,omitempty"`
	Server    string          `json:"server,omitempty"`
	User      string          `json:"user,omitempty"`
	Repo      *repoRef        `json:"repo,omitempty"`
	WebURL    string          `json:"webUrl,omitempty"`
	Branch    string          `json:"branch,omitempty"`
	Snapshot  *pickedSnapshot `json:"snapshot,omitempty"`
	Counts    map[string]int  `json:"counts,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
	Gate      *gateStatus     `json:"gate,omitempty"`
}

type gateStatus struct {
	PR      string   `json:"pr"`
	State   string   `json:"state"`
	Passed  bool     `json:"passed"`
	Reasons []string `json:"reasons,omitempty"`
	URL     string   `json:"url,omitempty"`
}

func (w *workspace) status() status {
	w.s.mu.Lock()
	server, user := w.s.server, w.s.user
	w.s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	st := status{Root: w.root, State: w.state, Message: w.message, Server: server, User: user, Branch: w.branch, Snapshot: w.snapshot, Truncated: w.truncated}
	if w.repo != nil {
		r := *w.repo
		st.Repo = &r
		q := url.Values{}
		if w.snapshot != nil {
			q.Set("snapshot", w.snapshot.ID)
		}
		st.WebURL = webURL(server, r, q)
	}
	if w.state == stateReady {
		st.Counts = map[string]int{}
		for _, f := range w.findings {
			if f.Status == "detected" && f.Acceptance == nil {
				st.Counts[f.Severity]++
			}
		}
	}
	if w.gate != nil {
		st.Gate = &gateStatus{PR: w.pr, State: w.gate.State, Passed: w.gate.Passed, Reasons: w.gate.Reasons, URL: w.gate.TargetURL}
	}
	return st
}

func (s *Server) statuses() []status {
	var out []status
	for _, ws := range s.allWorkspaces() {
		out = append(out, ws.status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Root < out[j].Root })
	if len(out) == 0 {
		// No git repository open: still report sign-in state.
		s.mu.Lock()
		st := status{State: stateUntracked, Message: "No git repository is open.", Server: s.server, User: s.user}
		if s.server == "" {
			st.State = stateUnconfigured
		} else if s.token == "" {
			st.State = stateSignedOut
		}
		s.mu.Unlock()
		out = append(out, st)
	}
	return out
}

func (w *workspace) setState(state, msg string) {
	w.mu.Lock()
	w.state, w.message = state, msg
	w.mu.Unlock()
}

// refreshWorkspace re-reads git state and, when remote is set or HEAD moved,
// asks hibou for the snapshot and gate. Diagnostics of open documents and the
// status are republished afterwards.
func (s *Server) refreshWorkspace(ctx context.Context, w *workspace, remote bool) {
	w.refreshMu.Lock()
	defer w.refreshMu.Unlock()
	before := w.status()

	w.refresh(ctx, remote)

	w.mu.Lock()
	w.started = true
	w.mu.Unlock()
	for _, d := range s.docsOf(w) {
		s.publish(ctx, d)
	}
	s.publishClosedFiles(ctx, w, false)
	if after := w.status(); !sameStatus(before, after) {
		_ = s.conn.notify("hibou/statusChanged", after)
	}
}

func sameStatus(a, b status) bool {
	snap := func(s status) string {
		if s.Snapshot == nil {
			return ""
		}
		return s.Snapshot.ID
	}
	gate := func(s status) string {
		if s.Gate == nil {
			return ""
		}
		return s.Gate.PR + s.Gate.State + strconv.FormatBool(s.Gate.Passed)
	}
	return a.State == b.State && a.Message == b.Message && a.Branch == b.Branch && a.User == b.User &&
		snap(a) == snap(b) && gate(a) == gate(b) && fmt.Sprint(a.Counts) == fmt.Sprint(b.Counts)
}

func (w *workspace) refresh(ctx context.Context, remote bool) {
	head, err := w.git.head(ctx)
	if err != nil {
		w.setState(stateNoSnapshot, "The repository has no commits yet.")
		return
	}
	branch := w.git.branch(ctx)
	w.mu.Lock()
	headChanged := head != w.lastHead
	w.lastHead, w.branch = head, branch
	w.mu.Unlock()
	if !remote && !headChanged {
		return
	}

	client, err := w.s.api()
	if errors.Is(err, errUnconfigured) {
		w.setState(stateUnconfigured, "Set the hibou server URL to see findings.")
		return
	}
	if err != nil {
		w.setState(stateError, err.Error())
		return
	}
	if client.token == "" {
		w.setState(stateSignedOut, "Sign in to hibou to see findings.")
		return
	}
	if err := w.s.ensureUser(ctx, client); err != nil {
		w.reportAPIError(err)
		return
	}

	repo, err := w.resolveRepo(ctx, client, branch)
	if errors.Is(err, errUntracked) {
		return // state already set
	}
	if err != nil {
		w.reportAPIError(err)
		return
	}

	snap, err := w.pickSnapshot(ctx, client, *repo, branch, head)
	if err != nil {
		w.reportAPIError(err)
		return
	}
	w.refreshGate(ctx, client, *repo, branch, remote)
	if snap == nil {
		w.mu.Lock()
		w.snapshot, w.findings, w.byPath = nil, nil, nil
		w.mu.Unlock()
		w.setState(stateNoSnapshot, "hibou has no scan of this commit or of any commit it is based on.")
		return
	}

	w.mu.Lock()
	same := w.snapshot != nil && w.snapshot.ID == snap.ID && w.state == stateReady
	w.mu.Unlock()
	// A local HEAD move with the same snapshot changes nothing on the
	// server. A server poll (or Refresh) re-fetches even then: triage done in
	// the web UI (false positive, acceptance, dispute) changes findings
	// without a new snapshot.
	if same && !remote {
		w.mu.Lock()
		w.snapshot = snap // AtHead may change while the ID does not
		w.mu.Unlock()
		return
	}

	findings, truncated, err := client.findings(ctx, *repo, snap.ID)
	if err != nil {
		w.reportAPIError(err)
		return
	}
	byPath, byAbsPath := map[string][]int{}, map[string][]int{}
	for i, f := range findings {
		p := normalizeRepoPath(f.FilePath)
		switch {
		case p == "":
		case isAbsScannerPath(f.FilePath):
			byAbsPath[p] = append(byAbsPath[p], i)
		default:
			byPath[p] = append(byPath[p], i)
		}
	}
	w.mu.Lock()
	w.snapshot, w.findings, w.byPath, w.byAbsPath, w.truncated = snap, findings, byPath, byAbsPath, truncated
	w.digest = findingsDigest(findings)
	if !same {
		// Same snapshot: the scanned file contents and coverage still hold.
		w.scanned = map[string]*scannedFile{}
		w.coverage = map[string]*apiCoverageSource{}
	}
	w.state, w.message = stateReady, ""
	w.mu.Unlock()
}

// findingsDigest summarises what the editor shows of each finding, so a
// re-fetch that changed nothing does not republish every closed file.
func findingsDigest(findings []apiFinding) string {
	h := sha256.New()
	for _, f := range findings {
		fmt.Fprintf(h, "%s|%s|%s|%t|%t|%d|%d\n", f.Fingerprint, f.Status, f.Presence, f.Acceptance != nil, f.Dispute != nil, f.StartLine, f.EndLine)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (w *workspace) reportAPIError(err error) {
	switch {
	case isStatus(err, http.StatusUnauthorized):
		w.s.mu.Lock()
		w.s.user = ""
		w.s.mu.Unlock()
		w.setState(stateSignedOut, "hibou refused the token (expired or revoked). Sign in again.")
	case isStatus(err, http.StatusForbidden):
		w.setState(stateError, "hibou refused access: "+err.Error()+". The token needs read access to this repository's findings.")
	case errors.Is(err, context.Canceled):
	default:
		w.setState(stateError, err.Error())
	}
}

func (s *Server) ensureUser(ctx context.Context, client *apiClient) error {
	s.mu.Lock()
	known := s.user != ""
	s.mu.Unlock()
	if known {
		return nil
	}
	u, err := client.me(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.user = u.label()
	s.mu.Unlock()
	return nil
}

var errUntracked = errors.New("untracked")

// resolveRepo finds the hibou repository for the work tree: the explicit
// org/repo settings when given, else the git remote matched against the orgs
// the user can see.
func (w *workspace) resolveRepo(ctx context.Context, client *apiClient, branch string) (*repoRef, error) {
	w.mu.Lock()
	cached := w.repo
	w.mu.Unlock()
	if cached != nil {
		return cached, nil
	}

	w.s.mu.Lock()
	orgOpt, repoOpt := strings.TrimSpace(w.s.opts.Org), strings.TrimSpace(w.s.opts.Repo)
	w.s.mu.Unlock()

	var candidates []repoRef
	var rem remote
	if orgOpt != "" {
		provider, slug, ok := strings.Cut(orgOpt, "/")
		if !ok {
			return nil, fmt.Errorf("the org setting must be \"provider/slug\", got %q", orgOpt)
		}
		name := repoOpt
		if name == "" {
			if raw, err := w.git.remoteURL(ctx, branch); err == nil {
				if r, err := parseRemote(raw); err == nil {
					name = r.Repo
				}
			}
		}
		if name == "" {
			return nil, errors.New("set the repository setting: the git remote gives no repository name")
		}
		candidates = append(candidates, repoRef{Provider: provider, Org: slug, Repo: name})
	} else {
		raw, err := w.git.remoteURL(ctx, branch)
		if err != nil {
			w.setState(stateUntracked, "No git remote: set the hibou org and repository settings.")
			return nil, errUntracked
		}
		rem, err = parseRemote(raw)
		if err != nil {
			w.setState(stateUntracked, "The git remote is not a forge URL: set the hibou org and repository settings.")
			return nil, errUntracked
		}
		// GET /orgs is browser-session only, so the candidates are guessed
		// from the remote and probed directly.
		candidates = remoteCandidates(rem, repoOpt)
	}

	for _, c := range candidates {
		info, err := client.repo(ctx, c)
		if err == nil {
			ref := c
			if info.Slug != "" {
				ref.Repo = info.Slug
			}
			w.mu.Lock()
			w.repo, w.repoInfo = &ref, info
			w.mu.Unlock()
			return &ref, nil
		}
		if !isStatus(err, http.StatusNotFound) && !isStatus(err, http.StatusForbidden) {
			return nil, err
		}
	}
	msg := "This repository is not tracked by hibou."
	if rem.Repo != "" {
		msg = fmt.Sprintf("%s/%s is not tracked by hibou (or you cannot see it).", rem.Owner, rem.Repo)
	}
	w.setState(stateUntracked, msg)
	return nil, errUntracked
}

// remoteCandidates lists the hibou repositories a git remote may be, most
// likely first: the provider the host implies, then the others; the owner as
// is, flattened ("group/sub" -> "group-sub"), then its last segment.
func remoteCandidates(rem remote, repoOpt string) []repoRef {
	providers := []string{"github", "gitlab", "forgejo"}
	hostProvider := ""
	switch {
	case rem.Host == "github.com" || strings.HasPrefix(rem.Host, "github."):
		hostProvider = "github"
	case rem.Host == "gitlab.com" || strings.HasPrefix(rem.Host, "gitlab."):
		hostProvider = "gitlab"
	case strings.Contains(rem.Host, "forgejo") || strings.Contains(rem.Host, "gitea") || rem.Host == "codeberg.org":
		hostProvider = "forgejo"
	}
	if hostProvider != "" {
		ordered := []string{hostProvider}
		for _, p := range providers {
			if p != hostProvider {
				ordered = append(ordered, p)
			}
		}
		providers = ordered
	}
	owners := []string{rem.Owner}
	if flat := strings.ReplaceAll(rem.Owner, "/", "-"); flat != rem.Owner {
		owners = append(owners, flat)
	}
	if last := rem.Owner[strings.LastIndex(rem.Owner, "/")+1:]; last != rem.Owner {
		owners = append(owners, last)
	}
	name := rem.Repo
	if repoOpt != "" {
		name = repoOpt
	}
	var out []repoRef
	for _, p := range providers {
		for _, o := range owners {
			out = append(out, repoRef{Provider: p, Org: o, Repo: name})
		}
	}
	return out
}

// pickSnapshot returns the newest finished snapshot whose commit is HEAD or
// an ancestor of it, looking at the current branch first and then at the
// default branch (ADR-042 §4).
func (w *workspace) pickSnapshot(ctx context.Context, client *apiClient, repo repoRef, branch, head string) (*pickedSnapshot, error) {
	w.mu.Lock()
	defaultBranch := w.repoInfo.DefaultBranch
	w.mu.Unlock()
	refs := []string{}
	if branch != "" {
		refs = append(refs, branch)
	}
	if defaultBranch != "" && defaultBranch != branch {
		refs = append(refs, defaultBranch)
	}
	if len(refs) == 0 {
		refs = append(refs, "") // server default branch
	}

	var best *pickedSnapshot
	for _, ref := range refs {
		snaps, err := client.snapshots(ctx, repo, ref, snapshotPages)
		if isStatus(err, http.StatusNotFound) {
			continue // branch not known to hibou
		}
		if err != nil {
			return nil, err
		}
		sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].CreatedAt.After(snaps[j].CreatedAt) })
		for _, sn := range snaps {
			if !usableSnapshot(sn.Status) || sn.CommitSHA == "" {
				continue
			}
			if !w.isAncestor(ctx, sn.CommitSHA, head) {
				continue
			}
			cand := &pickedSnapshot{ID: sn.ID, Commit: sn.CommitSHA, Ref: ref, CreatedAt: sn.CreatedAt, AtHead: sn.CommitSHA == head}
			if ref == "" {
				cand.Ref = defaultBranch
			}
			if best == nil || cand.CreatedAt.After(best.CreatedAt) {
				best = cand
			}
			break // newest usable ancestor on this ref
		}
		if best != nil && best.AtHead {
			break
		}
	}
	return best, nil
}

func usableSnapshot(status string) bool {
	switch status {
	case "pending", "processing", "failed", "purged":
		return false
	}
	return true
}

func (w *workspace) isAncestor(ctx context.Context, sha, head string) bool {
	if sha == head {
		return true
	}
	key := sha + " " + head
	w.mu.Lock()
	v, ok := w.ancestors[key]
	w.mu.Unlock()
	if ok {
		return v
	}
	v, err := w.git.isAncestor(ctx, sha, head)
	if err != nil {
		return false
	}
	w.mu.Lock()
	if len(w.ancestors) > 4096 {
		w.ancestors = map[string]bool{}
	}
	w.ancestors[key] = v
	w.mu.Unlock()
	return v
}

// refreshGate finds the open pull request of the branch and its gate verdict.
func (w *workspace) refreshGate(ctx context.Context, client *apiClient, repo repoRef, branch string, remote bool) {
	if branch == "" {
		w.mu.Lock()
		w.pr, w.gate = "", nil
		w.mu.Unlock()
		return
	}
	w.mu.Lock()
	refs := w.refs
	w.mu.Unlock()
	if remote || refs == nil {
		fresh, err := client.refs(ctx, repo)
		if err != nil {
			return
		}
		refs = fresh
		w.mu.Lock()
		w.refs = refs
		w.mu.Unlock()
	}
	pr := ""
	for _, r := range refs {
		if r.RefType == "pull_request" && r.PRSourceBranch == branch && r.PRNumber != "" && (r.PRState == "" || strings.EqualFold(r.PRState, "open") || strings.EqualFold(r.PRState, "opened")) {
			pr = r.PRNumber
			break
		}
	}
	var gate *apiGate
	if pr != "" {
		if g, err := client.gate(ctx, repo, pr); err == nil {
			gate = &g
		}
	}
	w.mu.Lock()
	w.pr, w.gate = pr, gate
	w.mu.Unlock()
}

// hasFindings reports whether the current snapshot has findings in rel.
func (w *workspace) hasFindings(rel string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state == stateReady && len(w.byPath[rel]) > 0
}

// fileFindings returns the findings recorded for a repo-relative path.
func (w *workspace) fileFindings(rel string) (snap *pickedSnapshot, findings []apiFinding) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != stateReady {
		return nil, nil
	}
	idx := append([]int(nil), w.byPath[rel]...)
	// Some scanners report absolute CI paths
	// (/home/runner/work/app/app/cmd/main.go): match those on the suffix.
	for p, list := range w.byAbsPath {
		if strings.HasSuffix(p, "/"+rel) {
			idx = append(idx, list...)
		}
	}
	for _, i := range idx {
		findings = append(findings, w.findings[i])
	}
	return w.snapshot, findings
}

// canTriage reports whether the server said this sign-in may triage the
// repository's findings. Unknown (older server, repo not loaded) counts as
// yes, so the actions stay and a refusal points to the browser.
func (w *workspace) canTriage() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.repoInfo.ViewerCanTriage == nil || *w.repoInfo.ViewerCanTriage
}

func (w *workspace) finding(fingerprint string) (apiFinding, *repoRef, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, f := range w.findings {
		if f.Fingerprint == fingerprint {
			return f, w.repo, w.repo != nil
		}
	}
	return apiFinding{}, nil, false
}

// scannedLines returns the file as it was at the snapshot's commit.
func (w *workspace) scannedLines(ctx context.Context, commit, rel string) *scannedFile {
	key := commit + ":" + rel
	w.mu.Lock()
	sf := w.scanned[key]
	w.mu.Unlock()
	if sf != nil {
		return sf
	}
	text, ok := w.git.show(ctx, commit, rel)
	sf = &scannedFile{known: ok}
	if ok {
		sf.lines = splitLines(text)
	}
	w.mu.Lock()
	if len(w.scanned) > 512 {
		w.scanned = map[string]*scannedFile{}
	}
	w.scanned[key] = sf
	w.mu.Unlock()
	return sf
}

func isAbsScannerPath(p string) bool {
	p = strings.TrimPrefix(strings.TrimSpace(p), "file://")
	return strings.HasPrefix(p, "/") || windowsDrivePath.MatchString("/"+strings.ReplaceAll(p, "\\", "/"))
}

// normalizeRepoPath turns a scanner-reported path into a slash path relative
// to the repository root.
func normalizeRepoPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	p = strings.TrimPrefix(p, "file://")
	if p == "" {
		return ""
	}
	p = path.Clean("/" + p)
	return strings.TrimPrefix(p, "/")
}

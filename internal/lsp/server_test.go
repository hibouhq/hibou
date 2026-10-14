package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testClient drives a Server over in-memory pipes.
type testClient struct {
	t      *testing.T
	w      io.Writer
	nextID atomic.Int64

	mu        sync.Mutex
	responses map[int64]chan message
	notes     chan message
}

func startServer(t *testing.T) (*testClient, func()) {
	t.Helper()
	clientToServerR, clientToServerW := io.Pipe()
	serverToClientR, serverToClientW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{In: clientToServerR, Out: serverToClientW, Log: io.Discard, Version: "test"})
		_ = serverToClientW.Close()
	}()

	c := &testClient{t: t, w: clientToServerW, responses: map[int64]chan message{}, notes: make(chan message, 64)}
	go c.readLoop(serverToClientR)
	return c, func() {
		cancel()
		_ = clientToServerW.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}
}

func (c *testClient) readLoop(r io.Reader) {
	conn := newConn(r, io.Discard, nil)
	for {
		msg, err := conn.read()
		if err != nil {
			return
		}
		switch {
		case msg.Method != "" && msg.ID != nil:
			// Server-to-client request (window/showDocument): acknowledge.
			c.send(map[string]any{"jsonrpc": "2.0", "id": *msg.ID, "result": map[string]any{"success": true}})
		case msg.Method != "":
			c.notes <- *msg
		default:
			var id int64
			_ = json.Unmarshal(*msg.ID, &id)
			c.mu.Lock()
			ch := c.responses[id]
			c.mu.Unlock()
			if ch != nil {
				ch <- *msg
			}
		}
	}
}

func (c *testClient) send(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := fmt.Fprintf(c.w, "Content-Length: %d\r\n\r\n%s", len(data), data); err != nil {
		c.t.Fatal(err)
	}
}

func (c *testClient) call(method string, params any, out any) error {
	c.t.Helper()
	id := c.nextID.Add(1)
	ch := make(chan message, 1)
	c.mu.Lock()
	c.responses[id] = ch
	c.mu.Unlock()
	c.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	select {
	case msg := <-ch:
		if msg.Error != nil {
			return msg.Error
		}
		if out != nil {
			return json.Unmarshal(msg.Result, out)
		}
		return nil
	case <-time.After(10 * time.Second):
		c.t.Fatalf("%s: no response", method)
		return nil
	}
}

func (c *testClient) notify(method string, params any) {
	c.send(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

// waitDiagnostics returns the first non-empty diagnostics published for the
// open document uri (publishes for open documents carry a version).
func (c *testClient) waitDiagnostics(uri string) []diagnostic {
	return c.waitDiagnosticsFor(uri, true)
}

// waitDiagnosticsFor waits for diagnostics of the open buffer (open=true) or
// of the closed file read from disk (open=false, no version).
func (c *testClient) waitDiagnosticsFor(uri string, open bool) []diagnostic {
	c.t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case msg := <-c.notes:
			if msg.Method != "textDocument/publishDiagnostics" {
				continue
			}
			var p publishDiagnosticsParams
			_ = json.Unmarshal(msg.Params, &p)
			if p.URI == uri && len(p.Diagnostics) > 0 && (p.Version != nil) == open {
				return p.Diagnostics
			}
		case <-deadline:
			c.t.Fatal("no diagnostics published")
			return nil
		}
	}
}

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

const scannedSource = `package main

func main() {
	password := "hunter2"
	_ = password
}
`

// fakeHibou serves the endpoints the language server reads.
func fakeHibou(t *testing.T, commit string, acceptances *atomic.Int32) *httptest.Server {
	t.Helper()
	finding := map[string]any{
		"id": "11111111-1111-1111-1111-111111111111", "type": "sast", "title": "Hardcoded credentials",
		"description": "Potential hardcoded credentials", "severity": "high", "status": "detected",
		"primary_identifier_kind": "rule", "primary_identifier_value": "G101", "scanner_name": "gosec",
		"file_path": "main.go", "start_line": 4, "end_line": 4, "fingerprint": "fp-1",
		"cwes": []map[string]any{{"id": 798, "name": "Use of Hard-coded Credentials"}},
	}
	list := func(w http.ResponseWriter, items any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": items, "pagination": map[string]int{"page": 1, "per_page": 100, "total": 1}})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/users/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hb_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"display_name": "Dev"}})
	})
	mux.HandleFunc("GET /api/v1/orgs", func(w http.ResponseWriter, r *http.Request) {
		list(w, []map[string]any{{"slug": "other", "provider": "github"}, {"slug": "acme", "provider": "github"}})
	})
	mux.HandleFunc("GET /api/v1/orgs/github/acme/repos/app", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"slug": "app", "default_branch": "main"}})
	})
	mux.HandleFunc("GET /api/v1/orgs/github/acme/repos/app/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if ref := r.URL.Query().Get("ref"); ref != "main" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		list(w, []map[string]any{{"id": "snap-1", "commit_sha": commit, "status": "complete", "created_at": time.Now().Format(time.RFC3339)}})
	})
	mux.HandleFunc("GET /api/v1/orgs/github/acme/repos/app/refs/enhanced", func(w http.ResponseWriter, r *http.Request) {
		list(w, []map[string]any{{"name": "refs/pull/7", "ref_type": "pull_request", "pr_number": "7", "pr_state": "open", "pr_source_branch": "main"}})
	})
	mux.HandleFunc("GET /api/v1/orgs/github/acme/repos/app/pulls/7/gate", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"pr_number": 7, "state": "failure", "passed": false, "reasons": []string{"1 new high finding"}}})
	})
	mux.HandleFunc("GET /api/v1/orgs/github/acme/repos/app/findings", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("snapshot") != "snap-1" {
			t.Errorf("findings asked for snapshot %q", r.URL.Query().Get("snapshot"))
		}
		list(w, []map[string]any{finding})
	})
	mux.HandleFunc("PUT /api/v1/orgs/github/acme/repos/app/vulnerabilities/11111111-1111-1111-1111-111111111111/acceptance", func(w http.ResponseWriter, r *http.Request) {
		var body acceptanceRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Status != "accepted" || body.ReasonKind != "false_positive" || body.Reason != "test data" {
			t.Errorf("unexpected acceptance body %+v", body)
		}
		acceptances.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": 403, "message": "token lacks triage:write"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestServerEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HIBOU_SERVER", "")
	t.Setenv("HIBOU_TOKEN", "hb_test")

	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte(scannedSource), 0o600); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "main.go")
	gitCmd(t, repo, "commit", "-q", "-m", "init")
	gitCmd(t, repo, "remote", "add", "origin", "git@github.com:acme/app.git")
	commit := gitCmd(t, repo, "rev-parse", "HEAD")

	var acceptances atomic.Int32
	api := fakeHibou(t, commit, &acceptances)

	c, stop := startServer(t)
	defer stop()

	var initResult map[string]any
	if err := c.call("initialize", map[string]any{
		"processId":             nil,
		"workspaceFolders":      []map[string]string{{"uri": pathToURI(repo), "name": "app"}},
		"capabilities":          map[string]any{},
		"initializationOptions": map[string]any{"server": api.URL, "clientId": "hibou-vscode"},
	}, &initResult); err != nil {
		t.Fatal(err)
	}
	c.notify("initialized", map[string]any{})

	// Before the file is opened, its findings are published from disk so the
	// editor's problems panel lists them.
	uri := pathToURI(filepath.Join(repo, "main.go"))
	if disk := c.waitDiagnosticsFor(uri, false); len(disk) != 1 || disk[0].Range.Start.Line != 3 {
		t.Fatalf("closed file diagnostics = %+v, want one on line 3", disk)
	}
	caps, _ := initResult["capabilities"].(map[string]any)
	exp, _ := caps["experimental"].(map[string]any)
	hib, _ := exp["hibou"].(map[string]any)
	if hib["protocol"] != float64(protocolVersion) || len(hib["requests"].([]any)) != len(hibouRequests) {
		t.Fatalf("initialize must advertise the hibou protocol, got %v", exp)
	}

	// The buffer gained two lines above the finding since the scan.
	edited := strings.Replace(scannedSource, "func main() {\n", "// added\n// added\nfunc main() {\n", 1)
	c.notify("textDocument/didOpen", map[string]any{"textDocument": map[string]any{"uri": uri, "languageId": "go", "version": 1, "text": edited}})

	diags := c.waitDiagnostics(uri)
	if len(diags) != 1 {
		t.Fatalf("got %d diagnostics, want 1: %+v", len(diags), diags)
	}
	d := diags[0]
	if d.Range.Start.Line != 5 || d.Severity != severityError || d.Code != "G101" || !strings.Contains(d.Message, "CWE-798") {
		t.Fatalf("unexpected diagnostic %+v", d)
	}
	if strings.Contains(d.Message, "code changed") {
		t.Fatalf("an unchanged line was reported as edited: %q", d.Message)
	}
	if d.CodeDescription == nil || !strings.Contains(d.CodeDescription.Href, "/orgs/github/acme/repos/app/vulnerabilities?finding=fp-1") {
		t.Fatalf("missing deep link: %+v", d.CodeDescription)
	}

	var h hover
	if err := c.call("textDocument/hover", map[string]any{"textDocument": map[string]string{"uri": uri}, "position": map[string]int{"line": 5, "character": 3}}, &h); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.Contents.Value, "G101") || !strings.Contains(h.Contents.Value, "Open in hibou") {
		t.Fatalf("hover = %q", h.Contents.Value)
	}

	var actions []codeAction
	if err := c.call("textDocument/codeAction", map[string]any{
		"textDocument": map[string]string{"uri": uri}, "range": d.Range,
		"context": map[string]any{"diagnostics": []diagnostic{d}},
	}, &actions); err != nil {
		t.Fatal(err)
	}
	var suppress *codeAction
	for i := range actions {
		if strings.Contains(actions[i].Title, "gosec directive") {
			suppress = &actions[i]
		}
	}
	// No snippetEditSupport advertised: the client must ask for the reason.
	if suppress == nil || suppress.Command == nil || suppress.Command.Command != clientCmdSuppress {
		t.Fatalf("no client-side suppress action in %+v", actions)
	}

	var edit workspaceEdit
	if err := c.call("hibou/suppressionEdit", map[string]any{"uri": uri, "fingerprint": "fp-1", "line": 5, "reason": "test fixture,\nnot a real secret"}, &edit); err != nil {
		t.Fatal(err)
	}
	edits := edit.Changes[uri]
	if len(edits) != 1 || edits[0].NewText != " // #nosec G101 -- test fixture, not a real secret" || edits[0].Range.Start.Line != 5 {
		t.Fatalf("unexpected edit %+v", edits)
	}

	var statuses []status
	if err := c.call("hibou/status", nil, &statuses); err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].State != stateReady || statuses[0].Counts["high"] != 1 || statuses[0].Gate == nil || statuses[0].Gate.PR != "7" || statuses[0].Snapshot == nil || !statuses[0].Snapshot.AtHead {
		t.Fatalf("unexpected status %+v", statuses)
	}

	var tr triageResult
	if err := c.call("hibou/triage", map[string]any{"uri": uri, "fingerprint": "fp-1", "action": "false_positive", "reason": "test data"}, &tr); err != nil {
		t.Fatal(err)
	}
	if tr.OK || !strings.Contains(tr.WebURL, "finding=fp-1") || acceptances.Load() != 1 {
		t.Fatalf("a 403 must point to the browser: %+v", tr)
	}

	if err := c.call("shutdown", nil, nil); err != nil {
		t.Fatal(err)
	}
	c.notify("exit", nil)
}

func TestServerMarksEditedFindingLines(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HIBOU_TOKEN", "hb_test")

	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte(scannedSource), 0o600); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "main.go")
	gitCmd(t, repo, "commit", "-q", "-m", "init")
	gitCmd(t, repo, "remote", "add", "origin", "https://github.com/acme/app")
	commit := gitCmd(t, repo, "rev-parse", "HEAD")
	// A later local commit: the scan is of an ancestor of HEAD.
	gitCmd(t, repo, "commit", "-q", "--allow-empty", "-m", "local")

	var acceptances atomic.Int32
	api := fakeHibou(t, commit, &acceptances)
	c, stop := startServer(t)
	defer stop()
	if err := c.call("initialize", map[string]any{
		"rootUri": pathToURI(repo), "capabilities": map[string]any{"workspace": map[string]any{"workspaceEdit": map[string]any{"documentChanges": true, "snippetEditSupport": true}}},
		"initializationOptions": map[string]any{"server": api.URL},
	}, nil); err != nil {
		t.Fatal(err)
	}
	c.notify("initialized", map[string]any{})

	fixed := strings.Replace(scannedSource, `password := "hunter2"`, `password := os.Getenv("PASSWORD")`, 1)
	uri := pathToURI(filepath.Join(repo, "main.go"))
	c.notify("textDocument/didOpen", map[string]any{"textDocument": map[string]any{"uri": uri, "languageId": "go", "version": 1, "text": fixed}})
	diags := c.waitDiagnostics(uri)
	if len(diags) != 1 || diags[0].Range.Start.Line != 3 || !strings.Contains(diags[0].Message, "may already be fixed") {
		t.Fatalf("edited line must stay visible and be flagged: %+v", diags)
	}

	var statuses []status
	if err := c.call("hibou/status", nil, &statuses); err != nil {
		t.Fatal(err)
	}
	if statuses[0].Snapshot == nil || statuses[0].Snapshot.AtHead {
		t.Fatalf("snapshot of an ancestor must not be reported at HEAD: %+v", statuses[0].Snapshot)
	}

	// With snippet support the suppression is a one-step snippet edit.
	var actions []codeAction
	if err := c.call("textDocument/codeAction", map[string]any{
		"textDocument": map[string]string{"uri": uri}, "range": diags[0].Range,
		"context": map[string]any{"diagnostics": diags},
	}, &actions); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range actions {
		if a.Edit != nil && len(a.Edit.DocumentChanges) == 1 {
			snippet := a.Edit.DocumentChanges[0].Edits[0].Snippet.Value
			if snippet != " // #nosec G101 -- ${1:why this is safe}" {
				t.Fatalf("snippet = %q", snippet)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no snippet suppression in %+v", actions)
	}
	_ = c.call("shutdown", nil, nil)
	c.notify("exit", nil)
}

func TestJSONRPCFraming(t *testing.T) {
	t.Parallel()

	in := "Content-Length: 2\r\n\r\n{}" + "Content-Type: x\r\n\r\n"
	c := newConn(bufio.NewReader(strings.NewReader(in)), io.Discard, nil)
	if _, err := c.read(); err != nil {
		t.Fatalf("first message: %v", err)
	}
	if _, err := c.read(); err == nil || !strings.Contains(err.Error(), "Content-Length") {
		t.Fatalf("missing Content-Length must fail, got %v", err)
	}
	big := fmt.Sprintf("Content-Length: %d\r\n\r\n", maxMessageBytes+1)
	c = newConn(strings.NewReader(big), io.Discard, nil)
	if _, err := c.read(); err == nil {
		t.Fatal("oversized message accepted")
	}
}

func TestSecretCheckSendsOnlyTheStagedDiffWhenEnabled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HIBOU_TOKEN", "hb_test")

	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "app.env")
	gitCmd(t, repo, "commit", "-q", "-m", "init")
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("A=1\nAWS_SECRET=staged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "app.env")
	// An unstaged edit must not be sent.
	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("A=1\nAWS_SECRET=staged\nUNSTAGED=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var bodies []string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/secret-scan/check", func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "text/x-diff" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		bodies = append(bodies, string(data))
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"block":    true,
			"findings": []map[string]any{{"tool": "gitleaks", "rule_id": "aws", "severity": "high", "file_path": "app.env", "line": 2, "secret_type": "aws", "verified": false}},
		}})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	run := func(enabled bool) (*secretCheckResult, error) {
		c, stop := startServer(t)
		defer stop()
		if err := c.call("initialize", map[string]any{
			"rootUri": pathToURI(repo), "capabilities": map[string]any{},
			"initializationOptions": map[string]any{"server": api.URL, "secretCheck": enabled},
		}, nil); err != nil {
			t.Fatal(err)
		}
		c.notify("initialized", map[string]any{})
		// Workspace discovery runs in the background after initialized.
		deadline := time.Now().Add(10 * time.Second)
		var res secretCheckResult
		for {
			err := c.call("hibou/secretCheck", map[string]any{}, &res)
			if err != nil || res.Message != "Nothing staged to check." || time.Now().After(deadline) {
				_ = c.call("shutdown", nil, nil)
				c.notify("exit", nil)
				return &res, err
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	if _, err := run(false); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("secret check must be off by default, got %v", err)
	}
	if len(bodies) != 0 {
		t.Fatal("a disabled check sent the diff")
	}

	res, err := run(true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Block || len(res.Findings) != 1 || res.Findings[0].Line != 1 || !strings.HasSuffix(res.Findings[0].URI, "/app.env") {
		t.Fatalf("unexpected result %+v", res)
	}
	if len(bodies) != 1 || !strings.Contains(bodies[0], "+AWS_SECRET=staged") || strings.Contains(bodies[0], "UNSTAGED") {
		t.Fatalf("sent %q", bodies)
	}
}

// A carried (unconfirmed) finding's lines refer to the commit where it was
// last seen, not to the snapshot's commit: mapping it from the snapshot put it
// on stale lines once the file had grown.
func TestPlaceMapsCarriedFindingsFromLastSeenCommit(t *testing.T) {
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(repo, "a.go"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("package a\nvar secret = 1\n")
	gitCmd(t, repo, "add", "a.go")
	gitCmd(t, repo, "commit", "-q", "-m", "old")
	old := gitCmd(t, repo, "rev-parse", "HEAD")
	write("package a\n// one\n// two\n// three\nvar secret = 1\n")
	gitCmd(t, repo, "commit", "-q", "-am", "grow")
	head := gitCmd(t, repo, "rev-parse", "HEAD")

	s := &Server{docs: map[string]*document{}, workspaces: map[string]*workspace{}, rootOfDir: map[string]string{}}
	ws := newWorkspace(s, repo)
	ws.state = stateReady
	ws.snapshot = &pickedSnapshot{ID: "s", Commit: head}
	ws.findings = []apiFinding{
		{Fingerprint: "new", Status: "detected", Presence: "reported", StartLine: 5, EndLine: 5, FilePath: "a.go"},
		{Fingerprint: "old", Status: "detected", Presence: "unconfirmed", LastSeenCommit: old, StartLine: 2, EndLine: 2, FilePath: "a.go"},
	}
	ws.byPath = map[string][]int{"a.go": {0, 1}}

	d := document{uri: "file:///a.go", ws: ws, rel: "a.go"}
	d.setText("package a\n// one\n// two\n// three\nvar secret = 1\n")
	for _, p := range s.place(context.Background(), d) {
		if p.start != 4 {
			t.Errorf("%s placed on line %d, want 4", p.f.Fingerprint, p.start)
		}
	}
}

package lsp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/cliconfig"
)

// protocolVersion is the version of the hibou/* extension protocol. The IDE
// extensions are released on their own (hibouhq/hibou-ide) while this server
// ships with each hibou release, so one extension version talks to many
// server versions. Additive changes (a new request) only extend
// hibouRequests; an incompatible change increments protocolVersion.
const protocolVersion = 1

// hibouRequests lists the hibou/* requests this server answers, advertised at
// initialize so a client can hide features an older server lacks.
var hibouRequests = []string{
	"hibou/status", "hibou/findings", "hibou/refresh",
	"hibou/login/start", "hibou/login/wait", "hibou/login/cancel", "hibou/logout", "hibou/setToken",
	"hibou/suppressionEdit", "hibou/triage", "hibou/coverage", "hibou/secretCheck",
}

// Commands the server executes itself (advertised in executeCommandProvider).
// LSP clients register them as editor commands, so they live under their own
// hibou.server.* prefix: a name the extension also registers would collide.
const (
	cmdOpenFinding = "hibou.server.openFinding"
	cmdRefresh     = "hibou.server.refresh"
)

// Commands the clients implement, because they need user input the protocol
// cannot ask for. They are deliberately not advertised, so the LSP client
// routes them to the IDE instead of back to the server.
const (
	clientCmdSuppress = "hibou.suppress"
	clientCmdTriage   = "hibou.triage"
)

// Options are the initializationOptions the IDE clients send.
type Options struct {
	// Server is the hibou base URL. Empty falls back to HIBOU_SERVER, then the
	// CLI's saved login.
	Server string `json:"server"`
	// ClientID is the ADR-043 device-flow client: hibou-vscode or hibou-intellij.
	ClientID string `json:"clientId"`
	// ClientName labels the device-flow token ("IDE — VS Code on <name>").
	ClientName string `json:"clientName"`
	// Org ("provider/slug") and Repo override git-remote detection.
	Org  string `json:"org"`
	Repo string `json:"repo"`
	// PollSeconds is how often the server checks hibou for a newer snapshot
	// and gate verdict. 0 means the default; below 30 is raised to 30.
	PollSeconds int `json:"pollSeconds"`
	// ShowSuppressed also shows suppressed and accepted findings, as hints.
	ShowSuppressed *bool `json:"showSuppressed"`
	// SecretCheck enables hibou/secretCheck, which sends the staged diff to
	// the server (ADR-042 phase 3). Off unless the user turned it on.
	SecretCheck bool `json:"secretCheck"`
}

const (
	defaultPoll  = 120 * time.Second
	minPoll      = 30 * time.Second
	headCheck    = 5 * time.Second
	agentProduct = "hibou-lsp"
)

// Config is how `hibou lsp` is started.
type Config struct {
	In      io.Reader
	Out     io.Writer
	Log     io.Writer // stderr; never stdout, which carries the protocol
	Version string
}

// Server is one language-server session.
type Server struct {
	cfg  Config
	conn *conn

	mu          sync.Mutex
	initialized bool
	shutdown    bool
	caps        clientCapabilities
	opts        Options
	server      string
	token       string
	tokenSource string // "client", "env", "cli-config", "login", ""
	user        string
	roots       []string
	workspaces  map[string]*workspace // by git root
	rootOfDir   map[string]string     // dir -> git root ("" = not in a repo)
	docs        map[string]*document  // by URI
	cancelLoops context.CancelFunc

	login *pendingLogin
}

type document struct {
	uri     string
	path    string // absolute, OS-native
	version int
	text    string
	lines   []string
	ws      *workspace
	rel     string // slash path relative to the git root
}

// Run serves one session until the client exits. It returns nil after an
// orderly shutdown/exit sequence.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	s := &Server{
		cfg:        cfg,
		workspaces: map[string]*workspace{},
		rootOfDir:  map[string]string{},
		docs:       map[string]*document{},
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.conn = newConn(cfg.In, cfg.Out, func(reqCtx context.Context, method string, params json.RawMessage) (any, error) {
		return s.handle(reqCtx, ctx, cancel, method, params)
	})
	err := s.conn.run(ctx)
	s.mu.Lock()
	clean := s.shutdown
	if s.cancelLoops != nil {
		s.cancelLoops()
	}
	s.mu.Unlock()
	if errors.Is(err, context.Canceled) && clean {
		return nil
	}
	if err == nil && !clean {
		return errors.New("client closed the connection without shutdown")
	}
	return err
}

func (s *Server) handle(ctx, sessionCtx context.Context, stop context.CancelFunc, method string, params json.RawMessage) (any, error) {
	s.mu.Lock()
	ready, down := s.initialized, s.shutdown
	s.mu.Unlock()
	if !ready && method != "initialize" && method != "exit" {
		return nil, &rpcError{Code: codeServerNotInitialized, Message: "server not initialized"}
	}
	if down && method != "exit" {
		return nil, &rpcError{Code: codeInvalidRequest, Message: "server is shutting down"}
	}

	switch method {
	case "initialize":
		return s.initialize(params)
	case "initialized":
		s.startLoops(sessionCtx)
		return nil, nil
	case "shutdown":
		s.mu.Lock()
		s.shutdown = true
		s.mu.Unlock()
		return nil, nil
	case "exit":
		stop()
		return nil, nil
	case "textDocument/didOpen":
		var p didOpenParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		s.didOpen(sessionCtx, p)
		return nil, nil
	case "textDocument/didChange":
		var p didChangeParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		s.didChange(p)
		return nil, nil
	case "textDocument/didClose":
		var p didCloseParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		s.didClose(p)
		return nil, nil
	case "textDocument/didSave", "workspace/didChangeConfiguration", "workspace/didChangeWatchedFiles", "$/setTrace":
		return nil, nil
	case "textDocument/hover":
		var p textDocumentPositionParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.hover(ctx, p), nil
	case "textDocument/codeAction":
		var p codeActionParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.codeActions(p), nil
	case "workspace/executeCommand":
		var p executeCommandParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.executeCommand(ctx, sessionCtx, p)
	case "hibou/status":
		return s.statuses(), nil
	case "hibou/findings":
		var p struct {
			URI string `json:"uri"`
		}
		_ = decode(params, &p)
		return s.findingsFor(ctx, p.URI), nil
	case "hibou/refresh":
		s.refreshAll(sessionCtx, true)
		return s.statuses(), nil
	case "hibou/login/start":
		return s.loginStart(ctx)
	case "hibou/login/wait":
		return s.loginWait(ctx, sessionCtx)
	case "hibou/login/cancel":
		s.loginCancel()
		return nil, nil
	case "hibou/logout":
		return nil, s.logout(ctx, sessionCtx)
	case "hibou/setToken":
		var p struct {
			Token string `json:"token"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return nil, s.setToken(ctx, sessionCtx, p.Token, "client")
	case "hibou/suppressionEdit":
		var p suppressionEditParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.suppressionEdit(ctx, p)
	case "hibou/triage":
		var p triageParams
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.triage(ctx, sessionCtx, p)
	case "hibou/secretCheck":
		var p struct {
			Root string `json:"root"`
		}
		_ = decode(params, &p)
		return s.secretCheck(ctx, p.Root)
	case "hibou/coverage":
		var p struct {
			URI string `json:"uri"`
		}
		if err := decode(params, &p); err != nil {
			return nil, err
		}
		return s.coverage(ctx, p.URI)
	}
	if strings.HasPrefix(method, "$/") {
		return nil, nil
	}
	return nil, &rpcError{Code: codeMethodNotFound, Message: "method not found: " + method}
}

func decode(params json.RawMessage, out any) error {
	if len(params) == 0 {
		return nil
	}
	if err := json.Unmarshal(params, out); err != nil {
		return &rpcError{Code: codeInvalidParams, Message: err.Error()}
	}
	return nil
}

func (s *Server) initialize(params json.RawMessage) (any, error) {
	var p initializeParams
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	var opts Options
	if len(p.InitializationOptions) > 0 && string(p.InitializationOptions) != "null" {
		if err := json.Unmarshal(p.InitializationOptions, &opts); err != nil {
			return nil, &rpcError{Code: codeInvalidParams, Message: "initializationOptions: " + err.Error()}
		}
	}

	var roots []string
	for _, f := range p.WorkspaceFolders {
		if path, ok := uriToPath(f.URI); ok {
			roots = append(roots, path)
		}
	}
	if len(roots) == 0 {
		if path, ok := uriToPath(p.RootURI); ok {
			roots = append(roots, path)
		}
	}

	server, token, source := resolveCredentials(opts.Server)

	s.mu.Lock()
	s.caps = p.Capabilities
	s.opts = opts
	s.server = server
	s.token = token
	s.tokenSource = source
	s.roots = roots
	s.initialized = true
	s.mu.Unlock()

	return map[string]any{
		"capabilities": map[string]any{
			"positionEncoding": "utf-16",
			"textDocumentSync": map[string]any{
				"openClose": true,
				"change":    1, // full
			},
			"hoverProvider": true,
			"codeActionProvider": map[string]any{
				"codeActionKinds": []string{"quickfix"},
			},
			"executeCommandProvider": map[string]any{
				"commands": []string{cmdOpenFinding, cmdRefresh},
			},
			"experimental": map[string]any{
				"hibou": map[string]any{
					"protocol": protocolVersion,
					"requests": hibouRequests,
				},
			},
		},
		"serverInfo": map[string]any{"name": agentProduct, "version": s.cfg.Version},
	}, nil
}

// resolveCredentials picks the server and token. The token comes from the
// HIBOU_TOKEN environment variable the IDE sets when spawning the server
// (ADR-042 §3: never a command-line argument), else from the CLI's saved
// login when it is for the same server.
func resolveCredentials(serverOpt string) (server, token, source string) {
	cfg, _ := cliconfig.Load()
	server = normalizeServer(serverOpt)
	if server == "" {
		server = normalizeServer(os.Getenv("HIBOU_SERVER"))
	}
	if server == "" {
		server = normalizeServer(cfg.Server)
	}
	if t := strings.TrimSpace(os.Getenv("HIBOU_TOKEN")); t != "" {
		return server, t, "env"
	}
	if server != "" && normalizeServer(cfg.Server) == server && strings.TrimSpace(cfg.Token) != "" {
		return server, strings.TrimSpace(cfg.Token), "cli-config"
	}
	return server, "", ""
}

// normalizeServer applies ADR-043's URL rules: default to https, drop the
// trailing slash.
func normalizeServer(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return strings.TrimRight(raw, "/")
}

func (s *Server) api() (*apiClient, error) {
	s.mu.Lock()
	server, token := s.server, s.token
	s.mu.Unlock()
	if server == "" {
		return nil, errUnconfigured
	}
	if err := cliclient.CheckServerURL(server, os.Getenv(cliclient.InsecureHTTPEnv) == "1"); err != nil {
		return nil, err
	}
	return &apiClient{
		server: server,
		token:  token,
		http:   &http.Client{Timeout: 30 * time.Second},
		agent:  agentProduct + "/" + s.cfg.Version,
	}, nil
}

var errUnconfigured = errors.New("no hibou server configured")

func (s *Server) pollInterval() time.Duration {
	s.mu.Lock()
	secs := s.opts.PollSeconds
	s.mu.Unlock()
	if secs <= 0 {
		return defaultPoll
	}
	if d := time.Duration(secs) * time.Second; d > minPoll {
		return d
	}
	return minPoll
}

func (s *Server) showSuppressed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts.ShowSuppressed != nil && *s.opts.ShowSuppressed
}

// startLoops discovers the workspace folders' repositories and starts the
// refresh loop: a cheap local HEAD check every few seconds and a server poll
// at the configured interval. /api/v1/ws only accepts browser sessions, so
// polling is the way a token client learns about new snapshots.
func (s *Server) startLoops(ctx context.Context) {
	loopCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancelLoops = cancel
	roots := append([]string(nil), s.roots...)
	s.mu.Unlock()

	go func() {
		for _, root := range roots {
			s.workspaceFor(loopCtx, root)
		}
		s.refreshAll(loopCtx, true)

		heads := time.NewTicker(headCheck)
		defer heads.Stop()
		lastPoll := time.Now()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-heads.C:
				remote := time.Since(lastPoll) >= s.pollInterval()
				if remote {
					lastPoll = time.Now()
				}
				for _, ws := range s.allWorkspaces() {
					if remote || ws.headMoved(loopCtx) {
						s.refreshWorkspace(loopCtx, ws, remote)
					}
				}
			}
		}
	}()
}

func (s *Server) allWorkspaces() []*workspace {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*workspace, 0, len(s.workspaces))
	for _, ws := range s.workspaces {
		out = append(out, ws)
	}
	return out
}

func (s *Server) refreshAll(ctx context.Context, remote bool) {
	for _, ws := range s.allWorkspaces() {
		s.refreshWorkspace(ctx, ws, remote)
	}
}

// workspaceFor returns the workspace of the git work tree containing path,
// creating it on first use. It returns nil outside a git repository.
func (s *Server) workspaceFor(ctx context.Context, path string) *workspace {
	dir := path
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		dir = filepath.Dir(path)
	}
	s.mu.Lock()
	root, known := s.rootOfDir[dir]
	s.mu.Unlock()
	if !known {
		found, err := findRepoRoot(ctx, dir)
		if err != nil {
			found = ""
		} else {
			found = filepath.Clean(filepath.FromSlash(found))
		}
		root = found
		s.mu.Lock()
		s.rootOfDir[dir] = root
		s.mu.Unlock()
	}
	if root == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ws := s.workspaces[root]; ws != nil {
		return ws
	}
	ws := newWorkspace(s, root)
	s.workspaces[root] = ws
	return ws
}

func (s *Server) didOpen(ctx context.Context, p didOpenParams) {
	path, ok := uriToPath(p.TextDocument.URI)
	if !ok {
		return
	}
	doc := &document{uri: p.TextDocument.URI, path: path, version: p.TextDocument.Version}
	doc.setText(p.TextDocument.Text)
	s.mu.Lock()
	s.docs[doc.uri] = doc
	s.mu.Unlock()

	// Workspace discovery runs git; keep it off the notification path so the
	// next document sync is not delayed.
	go func() {
		ws := s.workspaceFor(ctx, path)
		if ws == nil {
			return
		}
		rel, err := filepath.Rel(ws.root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return
		}
		s.mu.Lock()
		doc.ws, doc.rel = ws, filepath.ToSlash(rel)
		s.mu.Unlock()
		if ws.isNew() {
			s.refreshWorkspace(ctx, ws, true)
			return
		}
		s.publish(ctx, doc)
	}()
}

func (s *Server) didChange(p didChangeParams) {
	if len(p.ContentChanges) == 0 {
		return
	}
	s.mu.Lock()
	doc := s.docs[p.TextDocument.URI]
	if doc != nil {
		doc.version = p.TextDocument.Version
		doc.setText(p.ContentChanges[len(p.ContentChanges)-1].Text)
	}
	s.mu.Unlock()
	if doc != nil {
		s.schedulePublish(doc)
	}
}

func (s *Server) didClose(p didCloseParams) {
	s.mu.Lock()
	delete(s.docs, p.TextDocument.URI)
	s.mu.Unlock()
	_ = s.conn.notify("textDocument/publishDiagnostics", publishDiagnosticsParams{URI: p.TextDocument.URI, Diagnostics: []diagnostic{}})
}

func (d *document) setText(text string) {
	d.text = text
	d.lines = splitLines(text)
}

// debounce for republishing diagnostics while the user types.
var (
	publishTimersMu sync.Mutex
	publishTimers   = map[string]*time.Timer{}
)

const publishDebounce = 300 * time.Millisecond

func (s *Server) schedulePublish(doc *document) {
	publishTimersMu.Lock()
	defer publishTimersMu.Unlock()
	if t := publishTimers[doc.uri]; t != nil {
		t.Stop()
	}
	publishTimers[doc.uri] = time.AfterFunc(publishDebounce, func() {
		publishTimersMu.Lock()
		delete(publishTimers, doc.uri)
		publishTimersMu.Unlock()
		s.publish(context.Background(), doc)
	})
}

func (s *Server) docsOf(ws *workspace) []*document {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*document
	for _, d := range s.docs {
		if d.ws == ws {
			out = append(out, d)
		}
	}
	return out
}

func (s *Server) doc(uri string) *document {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.docs[uri]
}

// snapshotDoc copies the fields a reader needs, so it can work without
// holding the server lock while the user keeps typing.
func (s *Server) snapshotDoc(d *document) document {
	s.mu.Lock()
	defer s.mu.Unlock()
	return document{uri: d.uri, path: d.path, version: d.version, text: d.text, lines: d.lines, ws: d.ws, rel: d.rel}
}

var windowsDrivePath = regexp.MustCompile(`^/[A-Za-z]:`)

// uriToPath converts a file:// URI to an OS path.
func uriToPath(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" {
		return "", false
	}
	p := u.Path
	if windowsDrivePath.MatchString(p) {
		p = p[1:]
	}
	if p == "" {
		return "", false
	}
	return filepath.Clean(filepath.FromSlash(p)), true
}

// pathToURI is the inverse of uriToPath.
func pathToURI(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

func (s *Server) showMessage(kind int, msg string) {
	_ = s.conn.notify("window/showMessage", showMessageParams{Type: kind, Message: msg})
}

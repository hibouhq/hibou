package lsp

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/devicelogin"
)

// Login runs the ADR-043 device flow in the language server, so the polling
// logic exists once (internal/devicelogin). The client only shows the code,
// opens the browser and stores the token it receives in the IDE's secret
// store.

type pendingLogin struct {
	auth   *devicelogin.Authorization
	client *devicelogin.Client
	cancel context.CancelFunc
	ctx    context.Context
	once   sync.Once
}

type loginStartResult struct {
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
}

type loginResult struct {
	Token     string `json:"token"`
	TokenName string `json:"tokenName,omitempty"`
	User      string `json:"user,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	// Preset is the access approved in the browser ("read-only", "triage").
	Preset string `json:"preset,omitempty"`
}

// errorUnsupported tells the client to fall back to pasting a token.
const codeLoginUnsupported = -32901

func (s *Server) loginStart(ctx context.Context) (*loginStartResult, error) {
	s.mu.Lock()
	server, opts := s.server, s.opts
	s.mu.Unlock()
	if server == "" {
		return nil, &rpcError{Code: codeInvalidRequest, Message: errUnconfigured.Error()}
	}
	clientID := opts.ClientID
	switch clientID {
	case devicelogin.ClientVSCode, devicelogin.ClientIntelliJ:
	default:
		clientID = devicelogin.ClientVSCode
	}
	name := strings.TrimSpace(opts.ClientName)
	if name == "" {
		name, _ = os.Hostname()
	}

	dc := &devicelogin.Client{Server: server, HTTPClient: &http.Client{Timeout: 15 * time.Second}}
	// Ask for triage: the approval page preselects read-only for IDEs, so the
	// user opts in to triage there. A server older than the triage preset
	// answers invalid_scope; read-only is what those servers offer IDEs.
	req := devicelogin.Request{ClientID: clientID, ClientName: name, Preset: string(apitoken.PresetTriage)}
	auth, err := dc.RequestCode(ctx, req)
	if errors.Is(err, devicelogin.ErrInvalidScope) {
		req.Preset = string(apitoken.PresetReadOnly)
		auth, err = dc.RequestCode(ctx, req)
	}
	if errors.Is(err, devicelogin.ErrUnsupported) {
		return nil, &rpcError{Code: codeLoginUnsupported, Message: err.Error()}
	}
	if err != nil {
		return nil, err
	}

	s.loginCancel()
	// #nosec G118 -- cancel is kept in pendingLogin and called by loginWait or loginCancel.
	loginCtx, cancel := context.WithTimeout(context.Background(), time.Duration(auth.ExpiresIn+30)*time.Second)
	s.mu.Lock()
	s.login = &pendingLogin{auth: auth, client: dc, cancel: cancel, ctx: loginCtx}
	s.mu.Unlock()
	return &loginStartResult{UserCode: auth.UserCode, VerificationURI: auth.VerificationURI, VerificationURIComplete: auth.VerificationURIComplete, ExpiresIn: auth.ExpiresIn}, nil
}

// loginWait blocks until the browser approval, denial or expiry. The token is
// returned once, for the client to store; the server keeps it in memory.
func (s *Server) loginWait(reqCtx, sessionCtx context.Context) (*loginResult, error) {
	s.mu.Lock()
	pl := s.login
	s.mu.Unlock()
	if pl == nil {
		return nil, &rpcError{Code: codeInvalidRequest, Message: "no login in progress"}
	}
	ctx, cancel := context.WithCancel(pl.ctx)
	defer cancel()
	go func() {
		select {
		case <-reqCtx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()

	tok, err := pl.client.Poll(ctx, pl.auth)
	s.mu.Lock()
	if s.login == pl {
		s.login = nil
	}
	s.mu.Unlock()
	pl.once.Do(pl.cancel)
	switch {
	case errors.Is(err, devicelogin.ErrDenied):
		return nil, &rpcError{Code: codeInvalidRequest, Message: "The login was denied in the browser."}
	case errors.Is(err, devicelogin.ErrExpired):
		return nil, &rpcError{Code: codeInvalidRequest, Message: "The login code expired. Start again."}
	case err != nil:
		return nil, err
	}

	s.mu.Lock()
	s.token, s.tokenSource, s.user = tok.AccessToken, "login", tok.User
	s.mu.Unlock()
	s.resetWorkspaces()
	go s.refreshAll(sessionCtx, true)

	res := &loginResult{Token: tok.AccessToken, TokenName: tok.TokenName, User: tok.User, Preset: tok.Preset}
	if tok.ExpiresIn > 0 {
		res.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	return res, nil
}

func (s *Server) loginCancel() {
	s.mu.Lock()
	pl := s.login
	s.login = nil
	s.mu.Unlock()
	if pl != nil {
		pl.once.Do(pl.cancel)
	}
}

// setToken installs a token the user pasted (servers older than ADR-043).
// It is verified before it replaces the current one.
func (s *Server) setToken(ctx, sessionCtx context.Context, token, source string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return &rpcError{Code: codeInvalidParams, Message: "empty token"}
	}
	client, err := s.api()
	if err != nil {
		return err
	}
	client.token = token
	u, err := client.me(ctx)
	if isStatus(err, http.StatusUnauthorized) {
		return &rpcError{Code: codeInvalidParams, Message: "hibou refused this token (invalid, expired or revoked)"}
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.token, s.tokenSource, s.user = token, source, u.label()
	s.mu.Unlock()
	s.resetWorkspaces()
	go s.refreshAll(sessionCtx, true)
	return nil
}

// logout revokes a token this IDE obtained (device login or pasted) and
// forgets it. A token borrowed from the CLI's config or the environment is
// only forgotten: the CLI may still be using it.
func (s *Server) logout(ctx, sessionCtx context.Context) error {
	s.mu.Lock()
	source := s.tokenSource
	s.mu.Unlock()
	if source == "login" || source == "client" {
		if client, err := s.api(); err == nil && client.token != "" {
			if err := client.revokeCurrentToken(ctx); err != nil && !isStatus(err, http.StatusUnauthorized) {
				s.showMessage(messageWarning, "hibou could not revoke the token on the server ("+err.Error()+"). Revoke it under Settings › API Keys.")
			}
		}
	}
	s.mu.Lock()
	s.token, s.tokenSource, s.user = "", "", ""
	s.mu.Unlock()
	s.resetWorkspaces()
	s.refreshAll(sessionCtx, true)
	return nil
}

// resetWorkspaces drops server-derived state after the identity changed: a
// different user may see different repositories and findings.
func (s *Server) resetWorkspaces() {
	for _, ws := range s.allWorkspaces() {
		ws.mu.Lock()
		ws.repo, ws.repoInfo, ws.snapshot, ws.findings, ws.byPath, ws.byAbsPath = nil, apiRepo{}, nil, nil, nil, nil
		ws.refs, ws.pr, ws.gate = nil, "", nil
		ws.coverage = map[string]*apiCoverageSource{}
		ws.mu.Unlock()
	}
}

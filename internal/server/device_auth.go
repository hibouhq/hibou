package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/devicelogin"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/store"
)

// Device login (ADR-043): RFC 8628 device authorization grant minting a
// membership-wide, user-owned token. The code and token endpoints are
// unauthenticated and speak RFC 8628's JSON (no api.Response envelope) so a
// standard OAuth client can drive them; the lookup, approve and deny endpoints
// back the SPA's /device page and are session-only.

const (
	deviceCodeLifetime    = 10 * time.Minute
	devicePollInterval    = 5 * time.Second
	deviceMaxPendingPerIP = 10
	deviceClientNameMax   = 64
	// deviceDefaultTokenLifetime is the expiry preselected on the approval
	// page; the user may pick up to maxTokenLifetime.
	deviceDefaultTokenLifetime = 90 * 24 * time.Hour
)

// deviceClients maps the accepted client_id values to the label shown on the
// approval page and the preset each defaults to.
var deviceClients = map[string]struct {
	label  string
	preset apitoken.Preset
}{
	devicelogin.ClientCLI:      {label: "hibou CLI", preset: apitoken.PresetCLI},
	devicelogin.ClientVSCode:   {label: "VS Code extension", preset: apitoken.PresetReadOnly},
	devicelogin.ClientIntelliJ: {label: "IntelliJ plugin", preset: apitoken.PresetReadOnly},
}

// deviceTokenName names the minted key after the client and the machine, so
// Settings › API Keys reads like a device list.
func deviceTokenName(clientID, clientName string) string {
	host := clientName
	if host == "" {
		host = "unknown device"
	}
	switch clientID {
	case devicelogin.ClientVSCode:
		return "IDE — VS Code on " + host
	case devicelogin.ClientIntelliJ:
		return "IDE — IntelliJ on " + host
	default:
		return "CLI — " + host
	}
}

// sanitizeClientName keeps a client-supplied device name printable and short.
// It is shown on the approval page (escaped by the SPA) and used in the token
// name, so control characters and over-long values are dropped here.
func sanitizeClientName(raw string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(raw) {
		if n >= deviceClientNameMax {
			break
		}
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func writeOAuthJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	// RFC 6749 §5.1: token responses must not be cached.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeOAuthJSON(w, status, devicelogin.ErrorResponse{Error: code, ErrorDescription: description})
}

// deviceVerificationURI is the approval page URL. It comes from
// HIBOU_BASE_URL, never from request headers, so a spoofed Host cannot send a
// user to another site. Development without a base URL falls back to the
// request host.
func (s *Server) deviceVerificationURI(r *http.Request) (string, bool) {
	base := strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")
	if base == "" {
		if !s.cfg.IsDevelopment() {
			return "", false
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	return base + "/device", true
}

// @Summary      Start a device login
// @Description  RFC 8628 device authorization request (ADR-043). Returns a device code for the client to poll with and a user code to approve at verification_uri. Unauthenticated; the response is RFC 8628 JSON, not the api.Response envelope.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        payload  body      devicelogin.CodeRequest  true  "Client and requested preset"
// @Success      200      {object}  devicelogin.Authorization
// @Failure      400      {object}  devicelogin.ErrorResponse
// @Failure      429      {object}  devicelogin.ErrorResponse
// @Router       /auth/device/code [post]
func (s *Server) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	var input devicelogin.CodeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&input); err != nil {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeInvalid, "invalid JSON body")
		return
	}
	client, ok := deviceClients[input.ClientID]
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeInvalidClient, "unknown client_id")
		return
	}
	preset := client.preset
	if requested := strings.TrimSpace(input.Scope); requested != "" {
		preset = apitoken.Preset(requested)
		if _, ok := preset.Permissions(); !ok {
			writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "scope must be cli or read-only")
			return
		}
	}
	verificationURI, ok := s.deviceVerificationURI(r)
	if !ok {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "the server has no base URL configured")
		return
	}

	ip := requestClientIP(r)
	pending, err := s.queries.CountPendingDeviceAuthorizationsByIP(r.Context(), ip)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if pending >= deviceMaxPendingPerIP {
		writeOAuthError(w, http.StatusTooManyRequests, "slow_down", "too many pending logins from this address; finish or let one expire")
		return
	}

	deviceCode, userCode, err := s.createDeviceAuthorization(r.Context(), store.NewDeviceAuthorization{
		ClientID:           input.ClientID,
		ClientName:         sanitizeClientName(input.ClientName),
		RequestedPreset:    string(preset),
		RequesterIP:        ip,
		RequesterUserAgent: truncateRunes(r.UserAgent(), 256),
		PollInterval:       devicePollInterval,
		ExpiresAt:          time.Now().Add(deviceCodeLifetime),
	})
	if err != nil {
		s.log.Error().Err(err).Msg("create device authorization")
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	formatted := apitoken.FormatUserCode(userCode)
	writeOAuthJSON(w, http.StatusOK, devicelogin.Authorization{
		DeviceCode:              deviceCode,
		UserCode:                formatted,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURI + "?user_code=" + url.QueryEscape(formatted),
		ExpiresIn:               int(deviceCodeLifetime / time.Second),
		Interval:                int(devicePollInterval / time.Second),
	})
}

// createDeviceAuthorization stores a new request, retrying the rare user-code
// collision with a live request.
func (s *Server) createDeviceAuthorization(ctx context.Context, in store.NewDeviceAuthorization) (string, string, error) {
	for attempt := 0; ; attempt++ {
		deviceCode, err := apitoken.GenerateDeviceCode()
		if err != nil {
			return "", "", err
		}
		userCode, err := apitoken.GenerateUserCode()
		if err != nil {
			return "", "", err
		}
		in.DeviceCodeHash = store.HashAPIKey(deviceCode)
		in.UserCodeHash = store.HashAPIKey(userCode)
		_, err = s.queries.CreateDeviceAuthorization(ctx, in)
		if err == nil {
			return deviceCode, userCode, nil
		}
		var pqErr *pq.Error
		if attempt < 3 && errors.As(err, &pqErr) && pqErr.Code == "23505" {
			continue
		}
		return "", "", err
	}
}

// @Summary      Poll a device login
// @Description  RFC 8628 device access token request (ADR-043). Answers authorization_pending until the user approves, then returns a membership-wide API token exactly once. Unauthenticated; RFC 8628 JSON.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        payload  body      devicelogin.TokenRequest  true  "Device code"
// @Success      200      {object}  devicelogin.Token
// @Failure      400      {object}  devicelogin.ErrorResponse
// @Router       /auth/device/token [post]
func (s *Server) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	var input devicelogin.TokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&input); err != nil {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeInvalid, "invalid JSON body")
		return
	}
	if input.GrantType != devicelogin.GrantType {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeUnsupported, "")
		return
	}
	if strings.TrimSpace(input.DeviceCode) == "" {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeInvalid, "device_code is required")
		return
	}

	poll, err := s.queries.PollDeviceAuthorization(r.Context(), store.HashAPIKey(input.DeviceCode))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if poll == nil {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeInvalidGrant, "unknown device_code")
		return
	}
	if input.ClientID != poll.ClientID {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeInvalidClient, "client_id does not match the device code")
		return
	}
	if time.Now().After(poll.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeExpired, "")
		return
	}

	switch poll.Status {
	case store.DeviceAuthPending:
		if poll.SlowDown {
			writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeSlowDown, "")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodePending, "")
	case store.DeviceAuthDenied:
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeAccessDenied, "")
	case store.DeviceAuthApproved:
		s.issueDeviceToken(w, r, &poll.DeviceAuthorization)
	default:
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeExpired, "")
	}
}

// issueDeviceToken mints the key for an approved request. The raw token exists
// only in this response: the request row moves to consumed in the same
// transaction that stores the key's hash, so a replayed device code gets
// expired_token and a failed mint leaves the request approved for the next
// poll.
func (s *Server) issueDeviceToken(w http.ResponseWriter, r *http.Request, request *store.DeviceAuthorization) {
	ctx := r.Context()
	if request.ApprovedBy == nil || request.TokenExpiresAt == nil {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeAccessDenied, "")
		return
	}
	user, err := s.queries.GetUserByID(ctx, *request.ApprovedBy)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if user == nil {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeAccessDenied, "")
		return
	}
	preset := apitoken.Preset(request.ApprovedPreset)
	scope, ok := apitoken.MembershipScope(user.ID.String(), preset)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeAccessDenied, "")
		return
	}
	scopes, err := json.Marshal(scope)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	name := deviceTokenName(request.ClientID, request.ClientName)
	description := "Device login from " + request.RequesterIP + ", approved " + time.Now().UTC().Format(time.RFC3339)

	tx, err := s.queries.BeginTx(ctx)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	defer func() { _ = tx.Rollback() }()
	qtx := s.queries.WithTx(tx)

	consumed, err := qtx.ConsumeDeviceAuthorization(ctx, request.ID)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if consumed == nil {
		// A concurrent poll collected it first.
		writeOAuthError(w, http.StatusBadRequest, devicelogin.ErrCodeExpired, "")
		return
	}
	rawKey, apiKey, err := mintUserAPIKey(ctx, qtx, user.ID, name, description, scopes, request.TokenExpiresAt)
	if err != nil {
		s.log.Error().Err(err).Str("device_authorization", request.ID.String()).Msg("mint device login token")
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if err := qtx.SetDeviceAuthorizationAPIKey(ctx, request.ID, apiKey.ID); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if err := tx.Commit(); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	s.writeTokenAuditLog(r, user, uuid.NullUUID{}, apiKey, audit.ActionTokenCreate, map[string]any{
		"via":          "device_flow",
		"client_id":    request.ClientID,
		"client_name":  request.ClientName,
		"requester_ip": request.RequesterIP,
		"preset":       string(preset),
	})

	writeOAuthJSON(w, http.StatusOK, devicelogin.Token{
		AccessToken: rawKey,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(*request.TokenExpiresAt) / time.Second),
		TokenID:     apiKey.ID.String(),
		TokenName:   apiKey.Name,
		Orgs:        string(apitoken.OrgMemberships),
		Preset:      string(preset),
		User:        deviceUserLabel(user),
	})
}

func deviceUserLabel(user *store.User) string {
	if user.ForgeLogin != "" {
		return user.ForgeLogin
	}
	return actorDisplay(user)
}

// deviceRequestView is what the approval page shows about a pending login.
type deviceRequestView struct {
	UserCode        string               `json:"user_code"`
	ClientID        string               `json:"client_id"`
	ClientLabel     string               `json:"client_label"`
	ClientName      string               `json:"client_name"`
	RequesterIP     string               `json:"requester_ip"`
	CreatedAt       time.Time            `json:"created_at"`
	ExpiresAt       time.Time            `json:"expires_at"`
	RequestedPreset string               `json:"requested_preset"`
	Presets         []devicePresetView   `json:"presets"`
	Orgs            []deviceOrgReachView `json:"orgs"`
	DefaultExpiry   time.Time            `json:"default_expires_at"`
	MaxExpiry       time.Time            `json:"max_expires_at"`
}

type devicePresetView struct {
	Key         string                                       `json:"key"`
	Permissions map[apitoken.Capability]apitoken.AccessLevel `json:"permissions"`
}

// deviceOrgReachView is one org the token will reach, and how the org's
// login-token policy bounds it there.
type deviceOrgReachView struct {
	Provider      string `json:"provider"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	Role          string `json:"role"`
	Policy        string `json:"policy"`
	EffectiveRole string `json:"effective_role"`
}

type deviceDecisionRequest struct {
	UserCode  string     `json:"user_code"`
	Preset    string     `json:"preset,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// requireDeviceSession answers for the approval endpoints: a signed-in
// browser session, never a token (a token must not approve a token).
func (s *Server) requireDeviceSession(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	if auth.TokenAuthFromContext(r.Context()) != nil {
		api.JSONError(w, http.StatusForbidden, "device logins can only be approved from a browser session")
		return nil, false
	}
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	return user, true
}

// loadLiveDeviceRequest resolves a typed user code to a pending request. A
// malformed, unknown, expired or already-decided code all get the same 404.
func (s *Server) loadLiveDeviceRequest(w http.ResponseWriter, r *http.Request, rawCode string) (*store.DeviceAuthorization, string, bool) {
	code, ok := apitoken.NormalizeUserCode(rawCode)
	if !ok {
		api.JSONError(w, http.StatusNotFound, "this code is invalid or has expired")
		return nil, "", false
	}
	request, err := s.queries.GetLiveDeviceAuthorizationByUserCode(r.Context(), store.HashAPIKey(code))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load login request")
		return nil, "", false
	}
	if request == nil {
		api.JSONError(w, http.StatusNotFound, "this code is invalid or has expired")
		return nil, "", false
	}
	return request, code, true
}

// @Summary      Look up a device login
// @Description  Show a pending device login to the signed-in user before they approve it (ADR-043). Browser session only.
// @Tags         auth
// @Produce      json
// @Param        user_code  query     string  true  "Code shown in the terminal (XXXX-XXXX)"
// @Success      200        {object}  api.Response{data=server.deviceRequestView}
// @Failure      404        {object}  api.Response
// @Router       /auth/device [get]
func (s *Server) handleDeviceLookup(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDeviceSession(w, r)
	if !ok {
		return
	}
	request, code, ok := s.loadLiveDeviceRequest(w, r, r.URL.Query().Get("user_code"))
	if !ok {
		return
	}

	orgs, _, err := s.queries.ListOrganizationsByUser(r.Context(), user.ID, 500, 0)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list organizations")
		return
	}
	reach := make([]deviceOrgReachView, 0, len(orgs))
	for i := range orgs {
		role, err := s.queries.GetOrgMemberRole(r.Context(), orgs[i].ID, user.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to list organizations")
			return
		}
		policy := rbac.LoginTokensPolicy(orgs[i].Settings)
		name := orgs[i].DisplayName
		if name == "" {
			name = orgs[i].Name
		}
		reach = append(reach, deviceOrgReachView{
			Provider:      orgs[i].Provider,
			Slug:          orgs[i].Slug,
			Name:          name,
			Role:          role,
			Policy:        policy,
			EffectiveRole: rbac.CapRoleForLoginToken(role, policy),
		})
	}

	presets := make([]devicePresetView, 0, 2)
	for _, preset := range []apitoken.Preset{apitoken.PresetCLI, apitoken.PresetReadOnly} {
		permissions, _ := preset.Permissions()
		presets = append(presets, devicePresetView{Key: string(preset), Permissions: permissions})
	}
	now := time.Now()
	label := request.ClientID
	if client, ok := deviceClients[request.ClientID]; ok {
		label = client.label
	}
	api.JSON(w, http.StatusOK, deviceRequestView{
		UserCode:        apitoken.FormatUserCode(code),
		ClientID:        request.ClientID,
		ClientLabel:     label,
		ClientName:      request.ClientName,
		RequesterIP:     request.RequesterIP,
		CreatedAt:       request.CreatedAt,
		ExpiresAt:       request.ExpiresAt,
		RequestedPreset: request.RequestedPreset,
		Presets:         presets,
		Orgs:            reach,
		DefaultExpiry:   now.Add(deviceDefaultTokenLifetime),
		MaxExpiry:       now.Add(maxTokenLifetime),
	})
}

// @Summary      Approve a device login
// @Description  Approve a pending device login with a preset and expiry (ADR-043). The client's next poll receives a membership-wide token. Browser session only.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        payload  body      server.deviceDecisionRequest  true  "Code, preset and expiry"
// @Success      200      {object}  api.Response
// @Failure      400      {object}  api.Response
// @Failure      404      {object}  api.Response
// @Router       /auth/device/approve [post]
func (s *Server) handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDeviceSession(w, r)
	if !ok {
		return
	}
	var input deviceDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	preset := apitoken.Preset(input.Preset)
	if _, ok := preset.Permissions(); !ok {
		api.JSONError(w, http.StatusBadRequest, "preset must be cli or read-only")
		return
	}
	expiresAt := time.Now().Add(deviceDefaultTokenLifetime)
	if input.ExpiresAt != nil {
		expiresAt = *input.ExpiresAt
	}
	if err := validateScopedExpiry(true, &expiresAt); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	request, _, ok := s.loadLiveDeviceRequest(w, r, input.UserCode)
	if !ok {
		return
	}
	if !s.checkAPIKeyQuota(w, r, user.ID) {
		return
	}

	approved, err := s.queries.ApproveDeviceAuthorization(r.Context(), request.ID, user.ID, string(preset), expiresAt)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to approve login")
		return
	}
	if approved == nil {
		api.JSONError(w, http.StatusNotFound, "this code is invalid or has expired")
		return
	}
	s.writeDeviceAuditLog(r, user, approved, audit.ActionDeviceApprove, map[string]any{
		"preset":           string(preset),
		"token_expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	api.JSON(w, http.StatusOK, map[string]any{
		"status":     store.DeviceAuthApproved,
		"token_name": deviceTokenName(approved.ClientID, approved.ClientName),
	})
}

// @Summary      Deny a device login
// @Description  Deny a pending device login (ADR-043). The client's next poll gets access_denied. Browser session only.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        payload  body      server.deviceDecisionRequest  true  "Code"
// @Success      200      {object}  api.Response
// @Failure      404      {object}  api.Response
// @Router       /auth/device/deny [post]
func (s *Server) handleDeviceDeny(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireDeviceSession(w, r)
	if !ok {
		return
	}
	var input deviceDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	request, _, ok := s.loadLiveDeviceRequest(w, r, input.UserCode)
	if !ok {
		return
	}
	denied, err := s.queries.DenyDeviceAuthorization(r.Context(), request.ID, user.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to deny login")
		return
	}
	if denied == nil {
		api.JSONError(w, http.StatusNotFound, "this code is invalid or has expired")
		return
	}
	s.writeDeviceAuditLog(r, user, denied, audit.ActionDeviceDeny, nil)
	api.JSON(w, http.StatusOK, map[string]any{"status": store.DeviceAuthDenied})
}

func (s *Server) writeDeviceAuditLog(r *http.Request, user *store.User, request *store.DeviceAuthorization, action string, extra map[string]any) {
	entryContext := map[string]any{
		"client_id":    request.ClientID,
		"client_name":  request.ClientName,
		"requester_ip": request.RequesterIP,
	}
	for key, value := range extra {
		entryContext[key] = value
	}
	s.writeAuditLog(r, user, uuid.NullUUID{}, auditEntry{
		Action:       action,
		ResourceType: "device_authorization",
		ResourceID:   request.ID.String(),
		Context:      entryContext,
	})
}

// @Summary      Revoke the calling token
// @Description  Delete the user-owned API key that authenticates this request (ADR-043 §6, used by `hibou logout`). The only key-management action allowed with token auth; it can reach no other key.
// @Tags         api-keys
// @Produce      json
// @Success      200  {object}  api.Response
// @Failure      400  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/api-keys/current [delete]
func (s *Server) handleRevokeCurrentAPIKey(w http.ResponseWriter, r *http.Request) {
	tokenAuth := auth.TokenAuthFromContext(r.Context())
	if tokenAuth == nil {
		api.JSONError(w, http.StatusBadRequest, "this endpoint revokes the API token that calls it; a browser session has none")
		return
	}
	if tokenAuth.IsServicePrincipal() {
		api.JSONError(w, http.StatusForbidden, "an org-owned token is revoked by an org admin")
		return
	}
	deleted, err := s.queries.DeleteAPIKeyByID(r.Context(), tokenAuth.KeyID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to revoke API key")
		return
	}
	if deleted == nil {
		api.JSONError(w, http.StatusNotFound, "API key not found")
		return
	}
	s.writeTokenAuditLog(r, UserFromContext(r.Context()), uuid.NullUUID{}, deleted, audit.ActionTokenRevoke, map[string]any{"via": "self"})
	api.JSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// mintUserAPIKey creates a user-owned key and returns its raw value, shown
// once. Both the settings page and the device flow mint through it, so a key
// is generated, hashed and stored the same way everywhere.
func mintUserAPIKey(ctx context.Context, q *store.Queries, userID uuid.UUID, name, description string, scopes json.RawMessage, expiresAt *time.Time) (string, *store.APIKey, error) {
	rawKey, err := apitoken.Generate()
	if err != nil {
		return "", nil, err
	}
	apiKey, err := q.CreateAPIKey(ctx, userID, name, store.HashAPIKey(rawKey), scopes, expiresAt, "user", &userID, description)
	if err != nil {
		return "", nil, err
	}
	return rawKey, apiKey, nil
}

// runDeviceAuthCleanupLoop deletes device logins an hour past expiry.
func (s *Server) runDeviceAuthCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ran, err := store.WithLeaderLock(ctx, s.db, store.LockDeviceAuthCleanup, func(ctx context.Context) error {
				n, err := s.queries.DeleteExpiredDeviceAuthorizations(ctx)
				if err == nil && n > 0 {
					s.log.Debug().Int64("deleted", n).Msg("expired device logins removed")
				}
				return err
			})
			switch {
			case err != nil && ctx.Err() == nil:
				s.log.Warn().Err(err).Msg("device login cleanup failed")
			case err == nil && !ran:
				s.log.Debug().Msg("another replica is cleaning device logins")
			}
		}
	}
}

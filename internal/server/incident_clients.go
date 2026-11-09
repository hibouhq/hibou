package server

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/notify"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Client-side incident endpoints (ADR-053 §5, §11): how a client is reached,
// its portal tokens, what it received, and the portal itself.

type clientDeliveryResponse struct {
	SecurityContacts []securityContact `json:"security_contacts"`
	Channel          string            `json:"channel"`
	WebhookURL       string            `json:"webhook_url,omitempty"`
	WebhookSecretSet bool              `json:"webhook_secret_set"`
	EffectiveChannel string            `json:"effective_channel"`
}

type clientDeliveryRequest struct {
	SecurityContacts []securityContact `json:"security_contacts"`
	Channel          string            `json:"channel"`
	WebhookURL       string            `json:"webhook_url,omitempty"`
	// WebhookSecret replaces the stored secret when set; empty keeps it.
	WebhookSecret string `json:"webhook_secret,omitempty"`
}

func (s *Server) loadClientRow(w http.ResponseWriter, r *http.Request, mutate bool) (dbgen.Client, bool) {
	org, client, ok := s.loadAuthorizedClient(r, w)
	if !ok {
		return dbgen.Client{}, false
	}
	if mutate && !s.requireOrgAdmin(r, w, org.ID) {
		return dbgen.Client{}, false
	}
	row, err := s.queries.Incidents().GetClientRow(r.Context(), client.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load client")
		return dbgen.Client{}, false
	}
	return row, true
}

func clientDeliveryView(client dbgen.Client) (clientDeliveryResponse, error) {
	cfg, err := openClientDeliveryConfig(client)
	if err != nil {
		return clientDeliveryResponse{}, err
	}
	var contacts []securityContact
	_ = json.Unmarshal(client.SecurityContacts, &contacts)
	if contacts == nil {
		contacts = []securityContact{}
	}
	return clientDeliveryResponse{
		SecurityContacts: contacts, Channel: cfg.Channel, WebhookURL: cfg.WebhookURL,
		WebhookSecretSet: cfg.Secret != "", EffectiveChannel: defaultChannel(client, cfg),
	}, nil
}

func (s *Server) handleGetClientDelivery(w http.ResponseWriter, r *http.Request) {
	client, ok := s.loadClientRow(w, r, false)
	if !ok {
		return
	}
	view, err := clientDeliveryView(client)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to open delivery settings")
		return
	}
	api.JSON(w, http.StatusOK, view)
}

func (s *Server) handlePutClientDelivery(w http.ResponseWriter, r *http.Request) {
	client, ok := s.loadClientRow(w, r, true)
	if !ok {
		return
	}
	var input clientDeliveryRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	contacts := []securityContact{}
	for _, contact := range input.SecurityContacts {
		email := strings.TrimSpace(contact.Email)
		if email == "" {
			continue
		}
		if _, err := mail.ParseAddress(email); err != nil || strings.ContainsAny(email, "\r\n,") {
			api.JSONError(w, http.StatusBadRequest, "invalid security contact address: "+email)
			return
		}
		contacts = append(contacts, securityContact{Name: strings.TrimSpace(contact.Name), Email: email, Role: strings.TrimSpace(contact.Role)})
	}
	channel := strings.TrimSpace(input.Channel)
	switch channel {
	case "", channelEmail, channelWebhook, channelPortal, channelManual:
	default:
		api.JSONError(w, http.StatusBadRequest, "channel must be email, webhook, portal or manual")
		return
	}
	current, err := openClientDeliveryConfig(client)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to open delivery settings")
		return
	}
	next := clientDeliveryConfig{Channel: channel, WebhookURL: strings.TrimSpace(input.WebhookURL), Secret: current.Secret}
	if next.WebhookURL != "" {
		parsed, err := url.Parse(next.WebhookURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			api.JSONError(w, http.StatusBadRequest, "the webhook URL must be https")
			return
		}
		if current.WebhookURL != "" && current.WebhookURL != next.WebhookURL && input.WebhookSecret == "" && current.Secret != "" {
			api.JSONError(w, http.StatusBadRequest, "re-enter the webhook secret when changing the webhook URL")
			return
		}
	}
	if input.WebhookSecret != "" {
		next.Secret = input.WebhookSecret
	}
	if channel == channelWebhook && next.WebhookURL == "" {
		api.JSONError(w, http.StatusBadRequest, "the webhook channel needs a webhook URL")
		return
	}
	raw, _ := json.Marshal(next) // #nosec G117 -- the secret is sealed by SealConfig before it is stored
	sealed, err := notify.Secrets().SealConfig(clientSealContext(client), raw)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to seal delivery settings")
		return
	}
	contactsJSON, _ := json.Marshal(contacts)
	updated, err := s.queries.Incidents().UpdateClientDelivery(r.Context(), dbgen.UpdateClientDeliveryParams{ID: client.ID, SecurityContacts: contactsJSON, DeliveryConfig: sealed})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to save delivery settings")
		return
	}
	s.auditOrgConfig(r, client.OrgID, audit.ActionClientUpdate, "client", client.ID.String(), map[string]any{
		"delivery_channel": channel, "security_contacts": len(contacts), "webhook_url_set": next.WebhookURL != "", "webhook_secret_changed": input.WebhookSecret != "",
	})
	view, err := clientDeliveryView(updated)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to open delivery settings")
		return
	}
	api.JSON(w, http.StatusOK, view)
}

func (s *Server) handleListClientIncidentDeliveries(w http.ResponseWriter, r *http.Request) {
	client, ok := s.loadClientRow(w, r, false)
	if !ok {
		return
	}
	rows, err := s.queries.Incidents().ListDeliveriesByClient(r.Context(), dbgen.ListDeliveriesByClientParams{ClientID: uuid.NullUUID{UUID: client.ID, Valid: true}, Limit: 200})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list deliveries")
		return
	}
	api.JSON(w, http.StatusOK, rows)
}

type portalTokenRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleCreatePortalToken(w http.ResponseWriter, r *http.Request) {
	client, ok := s.loadClientRow(w, r, true)
	if !ok {
		return
	}
	var input portalTokenRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		api.JSONError(w, http.StatusBadRequest, "a portal token needs a name")
		return
	}
	token, hash, err := newPortalToken()
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create token")
		return
	}
	user := UserFromContext(r.Context())
	createdBy := uuid.NullUUID{}
	if user != nil {
		createdBy = uuid.NullUUID{UUID: user.ID, Valid: true}
	}
	row, err := s.queries.Incidents().CreateClientPortalToken(r.Context(), dbgen.CreateClientPortalTokenParams{OrgID: client.OrgID, ClientID: client.ID, Name: name, TokenHash: hash, CreatedBy: createdBy})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create token")
		return
	}
	s.auditOrgConfig(r, client.OrgID, audit.ActionPortalToken, "client", client.ID.String(), map[string]any{"action": "create", "token_id": row.ID, "name": name})
	api.JSON(w, http.StatusCreated, map[string]any{"token": token, "id": row.ID, "name": row.Name, "created_at": row.CreatedAt})
}

func (s *Server) handleListPortalTokens(w http.ResponseWriter, r *http.Request) {
	client, ok := s.loadClientRow(w, r, true)
	if !ok {
		return
	}
	rows, err := s.queries.Incidents().ListClientPortalTokens(r.Context(), client.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}
	type tokenView struct {
		ID         uuid.UUID `json:"id"`
		Name       string    `json:"name"`
		CreatedAt  string    `json:"created_at"`
		LastUsedAt string    `json:"last_used_at,omitempty"`
		Revoked    bool      `json:"revoked"`
	}
	out := []tokenView{}
	for _, row := range rows {
		view := tokenView{ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), Revoked: row.RevokedAt.Valid}
		if row.LastUsedAt.Valid {
			view.LastUsedAt = row.LastUsedAt.Time.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, view)
	}
	api.JSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokePortalToken(w http.ResponseWriter, r *http.Request) {
	client, ok := s.loadClientRow(w, r, true)
	if !ok {
		return
	}
	tokenID, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	if count, err := s.queries.Incidents().RevokeClientPortalToken(r.Context(), dbgen.RevokeClientPortalTokenParams{ID: tokenID, ClientID: client.ID}); err != nil || count == 0 {
		api.JSONError(w, http.StatusNotFound, "token not found")
		return
	}
	s.auditOrgConfig(r, client.OrgID, audit.ActionPortalToken, "client", client.ID.String(), map[string]any{"action": "revoke", "token_id": tokenID})
	w.WriteHeader(http.StatusNoContent)
}

// handlePortalList is the client portal: a client-bound token lists the
// notices its client received through the portal channel.
func (s *Server) handlePortalList(w http.ResponseWriter, r *http.Request) {
	token, ok := s.portalTokenFromRequest(r)
	if !ok {
		api.JSONError(w, http.StatusUnauthorized, "a client portal token is required")
		return
	}
	rows, err := s.queries.Incidents().ListPortalDeliveriesForClient(r.Context(), uuid.NullUUID{UUID: token.ClientID, Valid: true})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list notices")
		return
	}
	type notice struct {
		DeliveryID     uuid.UUID     `json:"delivery_id"`
		IncidentNumber int32         `json:"incident_number"`
		Title          string        `json:"title"`
		SentAt         string        `json:"sent_at"`
		Documents      []documentRef `json:"documents"`
	}
	out := []notice{}
	for _, row := range rows {
		var refs []documentRef
		_ = json.Unmarshal(row.Documents, &refs)
		sent := ""
		if row.SentAt.Valid {
			sent = row.SentAt.Time.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, notice{DeliveryID: row.ID, IncidentNumber: row.IncidentNumber, Title: row.IncidentTitle, SentAt: sent, Documents: refs})
	}
	api.JSON(w, http.StatusOK, out)
}

// handlePortalDocument downloads one document of one of the client's portal
// notices; the first download acknowledges the delivery.
func (s *Server) handlePortalDocument(w http.ResponseWriter, r *http.Request) {
	token, ok := s.portalTokenFromRequest(r)
	if !ok {
		api.JSONError(w, http.StatusUnauthorized, "a client portal token is required")
		return
	}
	deliveryID, err := uuid.Parse(chi.URLParam(r, "deliveryID"))
	if err != nil {
		api.JSONError(w, http.StatusNotFound, "not found")
		return
	}
	sum := strings.ToLower(chi.URLParam(r, "sha256"))
	delivery, err := s.queries.Incidents().GetIncidentDelivery(r.Context(), deliveryID)
	if err != nil || !delivery.ClientID.Valid || delivery.ClientID.UUID != token.ClientID || delivery.Channel != channelPortal || (delivery.Status != "sent" && delivery.Status != "acknowledged") {
		api.JSONError(w, http.StatusNotFound, "not found")
		return
	}
	var refs []documentRef
	_ = json.Unmarshal(delivery.Documents, &refs)
	found := false
	for _, ref := range refs {
		found = found || ref.SHA256 == sum
	}
	if !found {
		api.JSONError(w, http.StatusNotFound, "not found")
		return
	}
	row, body, err := s.loadIncidentDocument(r.Context(), token.OrgID, sum)
	if err != nil {
		api.JSONError(w, http.StatusNotFound, "not found")
		return
	}
	if delivery.Status == "sent" {
		evidence, _ := json.Marshal(map[string]any{"method": "portal", "token_id": token.ID, "sha256": sum})
		if _, err := s.queries.Incidents().AcknowledgeIncidentDelivery(r.Context(), dbgen.AcknowledgeIncidentDeliveryParams{ID: delivery.ID, AckEvidence: evidence}); err == nil {
			s.appendIncidentEvent(r.Context(), s.queries.Incidents(), delivery.IncidentID, incidentActor{Type: "client", Display: "client portal: " + token.Name}, "delivery.acknowledged", map[string]any{"delivery_id": delivery.ID, "method": "portal"})
			s.queueIncidentReconcile(delivery.IncidentID)
		}
	}
	w.Header().Set("Content-Type", row.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox")
	_, _ = w.Write(body) // #nosec G705 -- a stored document served with nosniff and a sandbox CSP
}

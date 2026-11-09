package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/notify"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Client delivery (ADR-053 §5): a client's document set goes out through the
// client's channel; every delivery records what was sent (digests), to whom,
// when, and an audit entry. Hibou proves handing-over, and records an
// acknowledgement when it gets one; it cannot prove a notice was read.

// Delivery channels.
const (
	channelEmail   = "email"
	channelWebhook = "webhook"
	channelPortal  = "portal"
	channelManual  = "manual"
)

// clientDeliveryConfig is clients.delivery_config, opened.
type clientDeliveryConfig struct {
	Channel    string `json:"channel,omitempty"`
	WebhookURL string `json:"webhook_url,omitempty"`
	Secret     string `json:"secret,omitempty"`
}

func clientSealContext(client dbgen.Client) notify.SealContext {
	return notify.SealContext{OrgID: client.OrgID, Table: notify.SealTableClients, RowID: client.ID}
}

func openClientDeliveryConfig(client dbgen.Client) (clientDeliveryConfig, error) {
	var out clientDeliveryConfig
	if len(client.DeliveryConfig) == 0 {
		return out, nil
	}
	opened, err := notify.Secrets().OpenConfig(clientSealContext(client), client.DeliveryConfig)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(opened, &out)
	return out, err
}

// defaultChannel is the client's configured channel, else email when the
// client has an address, else manual.
func defaultChannel(client dbgen.Client, cfg clientDeliveryConfig) string {
	if cfg.Channel != "" {
		return cfg.Channel
	}
	if len(securityContactEmails(client)) > 0 {
		return channelEmail
	}
	return channelManual
}

type deliverRequest struct {
	ClientIDs []string `json:"client_ids"`
	// Channel overrides the client's channel for this delivery.
	Channel string `json:"channel,omitempty"`
	// Measures is what clients should do: the workaround or the fix.
	Measures string `json:"measures,omitempty"`
	// Evidence records how a manual delivery happened.
	Evidence  string `json:"evidence,omitempty"`
	Recipient string `json:"recipient,omitempty"`
}

// deliverIncidentNotices renders and sends (or queues for approval) a
// notice to each client.
func (s *Server) deliverIncidentNotices(ctx context.Context, inc dbgen.Incident, org *store.Organization, actor incidentActor, req deliverRequest) ([]dbgen.IncidentDelivery, error) {
	if !incident.Open(string(inc.State)) && inc.State != dbgen.IncidentStateClosed {
		return nil, errIncidentConflict
	}
	if len(req.ClientIDs) == 0 {
		return nil, errIncidentInput("client_ids is required")
	}
	settings, err := s.loadIncidentSettings(ctx, inc.OrgID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	out := []dbgen.IncidentDelivery{}
	for _, raw := range req.ClientIDs {
		clientID, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			return out, errIncidentInput("invalid client id %q", raw)
		}
		client, err := s.queries.Incidents().GetClientRow(ctx, clientID)
		if err != nil || client.OrgID != inc.OrgID {
			return out, errIncidentInput("client %s not found in this organisation", raw)
		}
		cfg, err := openClientDeliveryConfig(client)
		if err != nil {
			return out, fmt.Errorf("open client delivery config: %w", err)
		}
		channel := strings.TrimSpace(req.Channel)
		if channel == "" {
			channel = defaultChannel(client, cfg)
		}
		recipient, err := deliveryRecipient(channel, client, cfg, req)
		if err != nil {
			return out, err
		}
		inputs, err := s.clientDocumentSet(ctx, inc, org, client, req.Measures, now)
		if err != nil {
			return out, err
		}
		refs := make([]documentRef, 0, len(inputs))
		for _, in := range inputs {
			ref, _, err := s.storeIncidentDocument(ctx, inc.OrgID, in)
			if err != nil {
				return out, err
			}
			refs = append(refs, ref)
		}
		documents, _ := json.Marshal(refs)
		status := "sent"
		if settings.Row.RequireNoticeApproval {
			status = "pending_approval"
		}
		actionID := uuid.NullUUID{}
		if actions, err := s.queries.Incidents().ListIncidentActions(ctx, inc.ID); err == nil {
			for _, action := range actions {
				if action.Kind == incident.ActionClientNotice && action.SubjectID == client.ID.String() {
					actionID = uuid.NullUUID{UUID: action.ID, Valid: true}
				}
			}
		}
		createStatus := status
		if status == "sent" {
			// Recorded as pending until the channel confirms the hand-over.
			createStatus = "pending_approval"
		}
		delivery, err := s.queries.Incidents().CreateIncidentDelivery(ctx, dbgen.CreateIncidentDeliveryParams{
			IncidentID: inc.ID, ClientID: uuid.NullUUID{UUID: client.ID, Valid: true}, ActionID: actionID,
			Channel: channel, Recipient: recipient, Documents: documents, Status: createStatus, CreatedBy: actor.userID(),
		})
		if err != nil {
			return out, err
		}
		s.appendIncidentEvent(ctx, s.queries.Incidents(), inc.ID, actor, "delivery.prepared", map[string]any{
			"delivery_id": delivery.ID, "client": client.Name, "channel": channel, "documents": refs, "awaiting_approval": status == "pending_approval",
		})
		if status == "sent" {
			delivery, err = s.sendIncidentDelivery(ctx, inc, org, client, cfg, delivery, actor, req.Evidence)
			if err != nil {
				s.log.Warn().Err(err).Str("delivery_id", delivery.ID.String()).Msg("incident delivery failed")
			}
		}
		out = append(out, delivery)
	}
	_, _ = s.reconcileIncident(ctx, inc.ID)
	return out, nil
}

func deliveryRecipient(channel string, client dbgen.Client, cfg clientDeliveryConfig, req deliverRequest) (string, error) {
	switch channel {
	case channelEmail:
		contacts := securityContactEmails(client)
		if len(contacts) == 0 {
			return "", errIncidentInput("%s has no security contact; add one or use another channel", client.Name)
		}
		return strings.Join(contacts, ", "), nil
	case channelWebhook:
		if strings.TrimSpace(cfg.WebhookURL) == "" {
			return "", errIncidentInput("%s has no webhook configured", client.Name)
		}
		parsed, err := url.Parse(cfg.WebhookURL)
		if err != nil || parsed.Host == "" {
			return "", errIncidentInput("%s's webhook URL is invalid", client.Name)
		}
		return parsed.Scheme + "://" + parsed.Host, nil
	case channelPortal:
		return "client portal", nil
	case channelManual:
		if strings.TrimSpace(req.Evidence) == "" {
			return "", errIncidentInput("a manual delivery records how it was sent (evidence)")
		}
		return firstNonEmptyString(req.Recipient, "recorded by hand"), nil
	}
	return "", errIncidentInput("channel must be email, webhook, portal or manual")
}

// approveIncidentDelivery lets a designated approver release a delivery the
// organisation holds for sign-off; the approver is not its author.
func (s *Server) approveIncidentDelivery(ctx context.Context, inc dbgen.Incident, org *store.Organization, actor incidentActor, deliveryID uuid.UUID, evidence string) (dbgen.IncidentDelivery, error) {
	delivery, err := s.queries.Incidents().GetIncidentDelivery(ctx, deliveryID)
	if err != nil || delivery.IncidentID != inc.ID {
		return delivery, errIncidentInput("delivery not found on this incident")
	}
	if delivery.Status != "pending_approval" {
		return delivery, errIncidentInput("this delivery is not waiting for approval")
	}
	if actor.Type != audit.ActorUser || (delivery.CreatedBy.Valid && delivery.CreatedBy.UUID == actor.ID.UUID) {
		return delivery, errIncidentInput("a notice is approved by someone other than its author")
	}
	delivery, err = s.queries.Incidents().ApproveIncidentDelivery(ctx, dbgen.ApproveIncidentDeliveryParams{ID: deliveryID, ApprovedBy: actor.userID()})
	if err != nil {
		return delivery, err
	}
	s.appendIncidentEvent(ctx, s.queries.Incidents(), inc.ID, actor, "delivery.approved", map[string]any{"delivery_id": deliveryID})
	if !delivery.ClientID.Valid {
		return delivery, nil
	}
	client, err := s.queries.Incidents().GetClientRow(ctx, delivery.ClientID.UUID)
	if err != nil {
		return delivery, err
	}
	cfg, err := openClientDeliveryConfig(client)
	if err != nil {
		return delivery, err
	}
	delivery, err = s.sendIncidentDelivery(ctx, inc, org, client, cfg, delivery, actor, evidence)
	_, _ = s.reconcileIncident(ctx, inc.ID)
	return delivery, err
}

// sendIncidentDelivery hands the documents to the channel and records the
// outcome with an audit entry carrying the digests.
func (s *Server) sendIncidentDelivery(ctx context.Context, inc dbgen.Incident, org *store.Organization, client dbgen.Client, cfg clientDeliveryConfig, delivery dbgen.IncidentDelivery, actor incidentActor, evidence string) (dbgen.IncidentDelivery, error) {
	var refs []documentRef
	_ = json.Unmarshal(delivery.Documents, &refs)
	sentAt := time.Now().UTC()
	providerRef := ""
	var sendErr error
	switch delivery.Channel {
	case channelEmail:
		providerRef, sendErr = s.sendDeliveryEmail(ctx, inc, org, client, delivery, refs)
	case channelWebhook:
		providerRef, sendErr = s.sendDeliveryWebhook(ctx, inc, org, client, cfg, delivery, refs)
	case channelPortal:
		providerRef = "available in the client portal"
	case channelManual:
		providerRef = strings.TrimSpace(evidence)
		if providerRef == "" {
			sendErr = errors.New("a manual delivery records how it was sent")
		}
	default:
		sendErr = fmt.Errorf("unknown channel %q", delivery.Channel)
	}
	status := "sent"
	errText := ""
	if sendErr != nil {
		status, errText = "failed", sendErr.Error()
	}
	auditID := s.writeDeliveryAudit(ctx, actor, inc, delivery, refs, status, errText, providerRef)
	updated, err := s.queries.Incidents().MarkIncidentDeliverySent(ctx, dbgen.MarkIncidentDeliverySentParams{
		ID: delivery.ID, Status: status, Error: errText, ProviderRef: truncateRunes(providerRef, 500),
		SentAt: sql.NullTime{Time: sentAt, Valid: status == "sent"}, AuditLogID: auditID,
	})
	if err != nil {
		return delivery, err
	}
	detail := map[string]any{"delivery_id": delivery.ID, "client": client.Name, "channel": delivery.Channel, "recipient": delivery.Recipient, "status": status, "documents": refs}
	if providerRef != "" {
		detail["provider_ref"] = providerRef
	}
	if errText != "" {
		detail["error"] = errText
	}
	s.appendIncidentEvent(ctx, s.queries.Incidents(), inc.ID, actor, "delivery."+status, detail)
	if sendErr != nil {
		s.publishIncidentEvent(ctx, events.IncidentDeliveryFailed, inc, fmt.Sprintf("Incident #%d: notice to %s failed", inc.Number, client.Name), errText)
	}
	if sendErr == nil && delivery.Channel == channelWebhook {
		// A 2xx from the client's own endpoint is its acknowledgement.
		evidence, _ := json.Marshal(map[string]any{"method": "webhook", "response": providerRef})
		if acknowledged, err := s.queries.Incidents().AcknowledgeIncidentDelivery(ctx, dbgen.AcknowledgeIncidentDeliveryParams{ID: delivery.ID, AckEvidence: evidence}); err == nil {
			updated = acknowledged
			s.appendIncidentEvent(ctx, s.queries.Incidents(), inc.ID, incidentSystemActor, "delivery.acknowledged", map[string]any{"delivery_id": delivery.ID, "method": "webhook"})
		}
	}
	return updated, sendErr
}

func (s *Server) writeDeliveryAudit(ctx context.Context, actor incidentActor, inc dbgen.Incident, delivery dbgen.IncidentDelivery, refs []documentRef, status, errText, providerRef string) uuid.NullUUID {
	digests := make([]string, 0, len(refs))
	for _, ref := range refs {
		digests = append(digests, ref.Kind+":"+ref.SHA256)
	}
	body, _ := json.Marshal(map[string]any{
		"incident_id": inc.ID, "number": inc.Number, "delivery_id": delivery.ID, "client_id": delivery.ClientID,
		"channel": delivery.Channel, "recipient": delivery.Recipient, "status": status, "error": errText,
		"provider_ref": providerRef, "documents": digests,
	})
	actorType := actor.Type
	if actorType == "" {
		actorType = audit.ActorSystem
	}
	row, err := s.queries.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorID: actor.ID, ActorType: actorType, ActorDisplay: actor.Display, Action: audit.ActionIncidentDelivery,
		ResourceType: "incident_delivery", ResourceID: delivery.ID.String(), OrgID: orgAuditID(inc.OrgID), Context: body,
	})
	if err != nil {
		s.log.Warn().Err(err).Msg("delivery audit write failed")
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: row.ID, Valid: true}
}

func (s *Server) sendDeliveryEmail(ctx context.Context, inc dbgen.Incident, org *store.Organization, client dbgen.Client, delivery dbgen.IncidentDelivery, refs []documentRef) (string, error) {
	integration, err := s.queries.Incidents().GetOrgEmailIntegration(ctx, inc.OrgID)
	if err != nil {
		return "", errors.New("the organisation has no enabled email integration to send from")
	}
	config, err := notify.Secrets().OpenConfig(notify.IntegrationSealContext(integration), integration.Config)
	if err != nil {
		return "", err
	}
	msg := notify.EmailMessage{
		To:      securityContactEmails(client),
		Subject: fmt.Sprintf("[%s] Security notice: %s (ref. #%d)", firstNonEmptyString(org.DisplayName, org.Name), inc.Title, inc.Number),
		Headers: map[string]string{"X-Hibou-Delivery": delivery.ID.String()},
	}
	ackURL := s.deliveryAckURL(delivery.ID)
	for _, ref := range refs {
		_, body, err := s.loadIncidentDocument(ctx, inc.OrgID, ref.SHA256)
		if err != nil {
			return "", err
		}
		switch ref.Kind {
		case docNoticeText:
			msg.Text = string(body)
			if ackURL != "" {
				msg.Text += "\nPlease confirm receipt: " + ackURL + "\n"
			}
		case docNoticeHTML:
			msg.HTML = string(body)
			if ackURL != "" {
				msg.HTML = strings.Replace(msg.HTML, "</body>", `<p><a href="`+ackURL+`">Confirm receipt</a></p></body>`, 1)
			}
			msg.Attachments = append(msg.Attachments, notify.EmailAttachment{Filename: ref.Filename, ContentType: "text/html", Data: body})
		default:
			msg.Attachments = append(msg.Attachments, notify.EmailAttachment{Filename: ref.Filename, ContentType: "application/json", Data: body})
		}
	}
	return notify.SendIntegrationEmail(ctx, config, msg)
}

func (s *Server) sendDeliveryWebhook(ctx context.Context, inc dbgen.Incident, org *store.Organization, client dbgen.Client, cfg clientDeliveryConfig, delivery dbgen.IncidentDelivery, refs []documentRef) (string, error) {
	type documentOut struct {
		documentRef
		Content json.RawMessage `json:"content,omitempty"`
		Text    string          `json:"text,omitempty"`
	}
	payload := struct {
		Event       string        `json:"event"`
		DeliveryID  string        `json:"delivery_id"`
		Publisher   string        `json:"publisher"`
		Incident    int32         `json:"incident"`
		Title       string        `json:"title"`
		Client      string        `json:"client"`
		AckURL      string        `json:"ack_url,omitempty"`
		Documents   []documentOut `json:"documents"`
		GeneratedAt string        `json:"generated_at"`
	}{Event: "security_notice", DeliveryID: delivery.ID.String(), Publisher: firstNonEmptyString(org.DisplayName, org.Name), Incident: inc.Number, Title: inc.Title, Client: client.Name, AckURL: s.deliveryAckURL(delivery.ID), GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, ref := range refs {
		_, body, err := s.loadIncidentDocument(ctx, inc.OrgID, ref.SHA256)
		if err != nil {
			return "", err
		}
		out := documentOut{documentRef: ref}
		if json.Valid(body) && strings.HasPrefix(ref.ContentType, "application/") {
			out.Content = body
		} else {
			out.Text = string(body)
		}
		payload.Documents = append(payload.Documents, out)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Secret != "" {
		notify.SignWebhookRequest(req, []byte(cfg.Secret), body, time.Now())
	}
	resp, err := notify.GuardedHTTPClient(20 * time.Second).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	digest := sha256.Sum256(responseBody)
	ref := fmt.Sprintf("HTTP %d, response sha256 %s", resp.StatusCode, hex.EncodeToString(digest[:]))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ref, fmt.Errorf("client webhook answered HTTP %d", resp.StatusCode)
	}
	return ref, nil
}

// deliveryAckSignature binds an acknowledgement link to one delivery; the key
// derives from the session secret with a purpose label, so a link cannot be
// forged for another delivery.
func (s *Server) deliveryAckSignature(deliveryID uuid.UUID) string {
	mac := hmac.New(sha256.New, []byte("hibou/incident-ack/v1\x00"+s.cfg.SessionSecret))
	_, _ = mac.Write([]byte(deliveryID.String()))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) deliveryAckURL(deliveryID uuid.UUID) string {
	base := strings.TrimRight(strings.TrimSpace(s.cfg.BaseURL), "/")
	if base == "" {
		return ""
	}
	return base + "/api/v1/incident-ack/" + deliveryID.String() + "?sig=" + s.deliveryAckSignature(deliveryID)
}

// handleIncidentAck records an acknowledgement from a signed link. Public by
// design: the signature is the authorisation, and the page reveals nothing.
func (s *Server) handleIncidentAck(w http.ResponseWriter, r *http.Request) {
	deliveryID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "deliveryID")))
	if err != nil || !hmac.Equal([]byte(r.URL.Query().Get("sig")), []byte(s.deliveryAckSignature(deliveryID))) {
		http.Error(w, "This confirmation link is not valid.", http.StatusNotFound)
		return
	}
	ip, userAgent := audit.RequestContext(r)
	evidence, _ := json.Marshal(map[string]any{"method": "link", "ip": ip, "user_agent": userAgent, "at": time.Now().UTC()})
	delivery, err := s.queries.Incidents().AcknowledgeIncidentDelivery(r.Context(), dbgen.AcknowledgeIncidentDeliveryParams{ID: deliveryID, AckEvidence: evidence})
	if err == nil {
		s.appendIncidentEvent(r.Context(), s.queries.Incidents(), delivery.IncidentID, incidentActor{Type: "client", Display: "client acknowledgement"}, "delivery.acknowledged", map[string]any{"delivery_id": deliveryID, "method": "link"})
		s.queueIncidentReconcile(delivery.IncidentID)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Receipt confirmed</title></head><body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>Thank you</h1><p>Receipt of the security notice is recorded.</p></body></html>`)
}

// Client portal tokens (§5 `portal` channel): bound to one client, they list
// and download that client's documents and nothing else.
const portalTokenPrefix = "hcp_"

func newPortalToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := portalTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return token, hashPortalToken(token), nil
}

func hashPortalToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func (s *Server) portalTokenFromRequest(r *http.Request) (dbgen.ClientPortalToken, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || !strings.HasPrefix(token, portalTokenPrefix) {
		return dbgen.ClientPortalToken{}, false
	}
	row, err := s.queries.Incidents().GetClientPortalTokenByHash(r.Context(), hashPortalToken(token))
	if err != nil {
		return row, false
	}
	_ = s.queries.Incidents().TouchClientPortalToken(r.Context(), row.ID)
	return row, true
}

package server

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// auditActor is the principal an audited action is attributed to. A request
// made with an API token is attributed to the token, not to its owner's user
// account (ADR-020): "a gate overridden via a token is traceable to that token
// and the human/org behind it". The human stays on the record in the context.
type auditActor struct {
	ID      uuid.NullUUID
	Type    string
	Display string
	Extra   map[string]any
}

func requestAuditActor(r *http.Request, user *store.User) auditActor {
	tokenAuth := auth.TokenAuthFromContext(r.Context())
	if tokenAuth == nil {
		actor := auditActor{Type: audit.ActorUser, Display: actorDisplay(user)}
		if user != nil {
			actor.ID = uuid.NullUUID{UUID: user.ID, Valid: true}
		}
		return actor
	}

	actor := auditActor{
		ID:      uuid.NullUUID{UUID: tokenAuth.KeyID, Valid: true},
		Type:    audit.ActorAPIKey,
		Display: tokenAuditDisplay(tokenAuth),
		Extra: map[string]any{
			"token_id":         tokenAuth.KeyID.String(),
			"token_name":       tokenAuth.Name,
			"token_scoped":     tokenAuth.Scoped,
			"token_owner_type": tokenAuth.OwnerType,
		},
	}
	if tokenAuth.OwnerID != uuid.Nil {
		actor.Extra["token_owner_id"] = tokenAuth.OwnerID.String()
	}
	if user != nil {
		actor.Extra["acting_user_id"] = user.ID.String()
		actor.Extra["acting_user"] = actorDisplay(user)
	}
	return actor
}

func tokenAuditDisplay(tokenAuth *auth.TokenAuth) string {
	if tokenAuth.Name != "" {
		return "token: " + tokenAuth.Name
	}
	return "token: " + tokenAuth.KeyID.String()
}

// writeAuditLog is the single request-scoped audit writer. Every handler goes
// through it so token attribution can never be forgotten at one call site.
func (s *Server) writeAuditLog(r *http.Request, user *store.User, orgID uuid.NullUUID, entry auditEntry) {
	actor := requestAuditActor(r, user)
	ipAddress, userAgent := audit.RequestContext(r)
	// The request must not fail on an audit-write error, but the error must not
	// vanish either: a silent drop here is how the actor_id FK bug went
	// unnoticed. Ops can alert on this line.
	if _, err := s.queries.CreateAuditLog(r.Context(), dbgen.CreateAuditLogParams{
		ActorID:      actor.ID,
		ActorType:    actor.Type,
		ActorDisplay: actor.Display,
		Action:       entry.Action,
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		OrgID:        orgID,
		Context:      auditContextJSON(entry.Context, actor.Extra),
		IpAddress:    ipAddress,
		UserAgent:    userAgent,
	}); err != nil {
		s.log.Warn().Err(err).
			Str("action", entry.Action).
			Str("actor_type", actor.Type).
			Str("resource", entry.ResourceType+"/"+entry.ResourceID).
			Msg("audit log write failed; the action itself succeeded")
	}
}

func auditContextJSON(base, extra map[string]any) json.RawMessage {
	if len(extra) > 0 {
		merged := make(map[string]any, len(base)+len(extra))
		for key, value := range base {
			merged[key] = value
		}
		for key, value := range extra {
			merged[key] = value
		}
		base = merged
	}

	body, err := json.Marshal(base)
	if err != nil {
		return json.RawMessage(`{"status":"marshal_error"}`)
	}
	return body
}

func orgAuditID(orgID uuid.UUID) uuid.NullUUID {
	return uuid.NullUUID{UUID: orgID, Valid: true}
}

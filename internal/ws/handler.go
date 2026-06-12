package ws

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/coder/websocket"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

type subscriptionPayload struct {
	Topics []string `json:"topics"`
}

func (h *Hub) HTTPHandler(authMgr *auth.Manager, queries *store.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authMgr == nil {
			http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			return
		}

		user, err := authMgr.AuthenticateRequest(r, queries)
		if err != nil || user == nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		conn.SetReadLimit(4096)

		client := h.Register(conn, user.ID)
		defer h.Unregister(client)

		ctx := r.Context()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}

			var msg Message
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}

			h.handleClientMessage(ctx, client, msg)
		}
	}
}

func (h *Hub) handleClientMessage(_ context.Context, c *client, msg Message) {
	var payload subscriptionPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return
	}

	switch msg.Type {
	case "topic.subscribe":
		c.topicsMu.Lock()
		for _, topic := range payload.Topics {
			if topic != "" {
				c.topics[topic] = true
			}
		}
		c.topicsMu.Unlock()
	case "topic.unsubscribe":
		c.topicsMu.Lock()
		for _, topic := range payload.Topics {
			delete(c.topics, topic)
		}
		c.topicsMu.Unlock()
	}
}

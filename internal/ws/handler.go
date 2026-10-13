package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

type subscriptionPayload struct {
	Topics []string `json:"topics"`
}

// Limits on what one browser, and one user, may hold open (§6 D9). The SPA
// opens one socket per tab and subscribes to three topics; these leave room for
// that many times over while bounding what a hostile client can pin in memory.
const (
	maxTopicsPerClient    = 64
	maxTopicLength        = 128
	maxConnectionsPerUser = 10
	// pingInterval keeps idle connections alive through proxies and detects
	// dead peers; a peer that does not answer within pongTimeout is dropped.
	pingInterval = 30 * time.Second
	pongTimeout  = 10 * time.Second
	// sessionRecheckInterval bounds how long a socket outlives its session
	// (logout or revocation on another replica, allowlist removal).
	sessionRecheckInterval = time.Minute
)

// HTTPHandler serves the websocket endpoint.
//
// Session cookies only. A bearer token is refused: an org-owned key is a
// service principal with no user behind it, and accepting it ran the socket as
// the key's creator with the token's scope ignored (A7). Live updates are a
// browser feature; machine clients poll the REST API under their token scope.
func (h *Hub) HTTPHandler(authMgr *auth.Manager, queries *store.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.IsDraining() {
			http.Error(w, "server draining", http.StatusServiceUnavailable)
			return
		}

		if authMgr == nil {
			http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			return
		}

		if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
			http.Error(w, "websocket requires a browser session; API tokens are not accepted", http.StatusUnauthorized)
			return
		}
		user, err := authMgr.GetSessionUser(r, queries)
		if err != nil || user == nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		// The sign-in allowlist governs sockets like every other request:
		// without this, a user it no longer admits kept a live socket until
		// the first session re-check.
		if !authMgr.UserAllowed(r.Context(), user) {
			http.Error(w, "account is not allowed to sign in", http.StatusForbidden)
			return
		}
		// Checked again atomically on registration; this one answers with a
		// plain HTTP status before the upgrade in the common case.
		if h.userConnectionCount(user.ID) >= maxConnectionsPerUser {
			http.Error(w, "too many websocket connections", http.StatusTooManyRequests)
			return
		}

		// Only now, with the session validated, may the connection outlive
		// the server-wide read/write timeouts: the hijacked connection keeps
		// whatever deadline is set at Accept. Liveness is keepAlive's job.
		liftDeadlines(w)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		conn.SetReadLimit(4096)

		client, ok := h.registerLimited(conn, user.ID, maxConnectionsPerUser)
		if !ok {
			_ = conn.Close(websocket.StatusPolicyViolation, "too many websocket connections")
			return
		}
		defer h.Unregister(client)

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		go keepAlive(ctx, conn, pingInterval, pongTimeout)
		go watchSession(ctx, conn, sessionRecheckInterval, func(ctx context.Context) bool {
			return sessionStillValid(ctx, authMgr, queries, user)
		})

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

// liftDeadlines clears the connection's read and write deadlines. Errors are
// ignored: a writer without deadlines (tests, HTTP/2 without support) has
// nothing to lift.
func liftDeadlines(w http.ResponseWriter) {
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Time{})
	_ = controller.SetWriteDeadline(time.Time{})
}

// sessionStillValid re-reads the user: a bumped session epoch means the
// session that opened this socket was revoked. A failed read keeps the socket
// (the next check retries); a missing user or an allowlist refusal closes it.
func sessionStillValid(ctx context.Context, authMgr *auth.Manager, queries *store.Queries, opened *store.User) bool {
	if queries == nil {
		return true
	}
	current, err := queries.GetUserByID(ctx, opened.ID)
	if err != nil {
		return true
	}
	if current == nil || current.SessionEpoch != opened.SessionEpoch {
		return false
	}
	return authMgr.UserAllowed(ctx, current)
}

// closer is the part of *websocket.Conn watchSession uses.
type closer interface {
	Close(code websocket.StatusCode, reason string) error
}

// watchSession closes the connection once valid reports false.
func watchSession(ctx context.Context, conn closer, interval time.Duration, valid func(context.Context) bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !valid(ctx) {
				if ctx.Err() == nil {
					_ = conn.Close(websocket.StatusPolicyViolation, "session revoked")
				}
				return
			}
		}
	}
}

// pinger is the part of *websocket.Conn keepAlive uses.
type pinger interface {
	Ping(ctx context.Context) error
	Close(code websocket.StatusCode, reason string) error
}

// keepAlive pings the peer every interval and closes the connection when a
// pong does not arrive within timeout. Closing unblocks the handler's Read, so
// a dead peer releases its slot instead of holding it until TCP gives up.
func keepAlive(ctx context.Context, conn pinger, interval, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, timeout)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					_ = conn.Close(websocket.StatusPolicyViolation, "ping timeout")
				}
				return
			}
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
			if topic == "" || len(topic) > maxTopicLength {
				continue
			}
			if !c.topics[topic] && len(c.topics) >= maxTopicsPerClient {
				break
			}
			c.topics[topic] = true
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

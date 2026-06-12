package ws

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/metrics"
)

const writeTimeout = 10 * time.Second

type Message struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type client struct {
	conn     *websocket.Conn
	userID   uuid.UUID
	topics   map[string]bool
	topicsMu sync.RWMutex
	send     chan []byte
	sendMu   sync.RWMutex
	closed   atomic.Bool
	once     sync.Once
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*client]bool
	byUser  map[uuid.UUID]map[*client]bool
	log     zerolog.Logger
}

func NewHub(log zerolog.Logger) *Hub {
	return &Hub{
		clients: map[*client]bool{},
		byUser:  map[uuid.UUID]map[*client]bool{},
		log:     log.With().Str("component", "ws.hub").Logger(),
	}
}

func (h *Hub) Register(conn *websocket.Conn, userID uuid.UUID) *client {
	c := &client{
		conn:   conn,
		userID: userID,
		topics: map[string]bool{},
		send:   make(chan []byte, 32),
	}

	h.mu.Lock()
	h.clients[c] = true
	if h.byUser[userID] == nil {
		h.byUser[userID] = map[*client]bool{}
	}
	h.byUser[userID][c] = true
	h.mu.Unlock()
	metrics.WebSocketConnections.Inc()

	go h.writePump(c)
	return c
}

func (h *Hub) Unregister(c *client) {
	if c == nil {
		return
	}

	h.mu.Lock()
	removed := h.clients[c]
	delete(h.clients, c)
	if clients := h.byUser[c.userID]; clients != nil {
		delete(clients, c)
		if len(clients) == 0 {
			delete(h.byUser, c.userID)
		}
	}
	h.mu.Unlock()
	if removed {
		metrics.WebSocketConnections.Dec()
	}

	c.once.Do(func() {
		c.sendMu.Lock()
		c.closed.Store(true)
		close(c.send)
		c.sendMu.Unlock()
	})
}

func (h *Hub) SendToUser(userID uuid.UUID, msg Message) {
	payload, err := json.Marshal(msg)
	if err != nil {
		h.log.Error().Err(err).Str("user_id", userID.String()).Msg("marshal websocket message")
		return
	}

	h.mu.RLock()
	clients := make([]*client, 0, len(h.byUser[userID]))
	for c := range h.byUser[userID] {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		h.enqueue(c, msg.Type, payload)
	}
}

func (h *Hub) Broadcast(msg Message) {
	payload, err := json.Marshal(msg)
	if err != nil {
		h.log.Error().Err(err).Msg("marshal broadcast websocket message")
		return
	}

	h.mu.RLock()
	clients := make([]*client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		h.enqueue(c, msg.Type, payload)
	}
}

func (h *Hub) enqueue(c *client, topic string, payload []byte) {
	if c == nil || !allowsTopic(c, topic) {
		return
	}

	c.sendMu.RLock()
	if c.closed.Load() {
		c.sendMu.RUnlock()
		return
	}

	select {
	case c.send <- payload:
	default:
		h.log.Warn().Str("user_id", c.userID.String()).Str("topic", topic).Msg("dropping websocket message for slow client")
	}
	c.sendMu.RUnlock()
}

func (h *Hub) writePump(c *client) {
	for msg := range c.send {
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		err := c.conn.Write(ctx, websocket.MessageText, msg)
		cancel()
		if err != nil {
			h.log.Debug().Err(err).Str("user_id", c.userID.String()).Msg("websocket write failed")
			h.Unregister(c)
			_ = c.conn.Close(websocket.StatusInternalError, "write failed")
			return
		}
	}

	_ = c.conn.Close(websocket.StatusNormalClosure, "closed")
}

func allowsTopic(c *client, topic string) bool {
	if c == nil {
		return true
	}

	c.topicsMu.RLock()
	defer c.topicsMu.RUnlock()

	if len(c.topics) == 0 {
		return true
	}
	return c.topics[topic] || c.topics["*"]
}

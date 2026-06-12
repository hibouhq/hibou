package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/auth"
)

func TestSendToUserDeliversToMatchingClients(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	userID := uuid.New()
	c := &client{userID: userID, send: make(chan []byte, 1), topics: map[string]bool{}}
	hub.clients[c] = true
	hub.byUser[userID] = map[*client]bool{c: true}

	hub.SendToUser(userID, Message{Type: "notification.new", Payload: json.RawMessage(`{"id":"1"}`)})

	select {
	case msg := <-c.send:
		var decoded Message
		if err := json.Unmarshal(msg, &decoded); err != nil {
			t.Fatalf("unmarshal message: %v", err)
		}
		if decoded.Type != "notification.new" {
			t.Fatalf("expected notification.new, got %q", decoded.Type)
		}
	default:
		t.Fatalf("expected message to be delivered")
	}
}

func TestTopicSubscriptionFiltersMessages(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	userID := uuid.New()
	c := &client{userID: userID, send: make(chan []byte, 1), topics: map[string]bool{"notification.new": true}}
	hub.clients[c] = true
	hub.byUser[userID] = map[*client]bool{c: true}

	hub.SendToUser(userID, Message{Type: "scan.status", Payload: json.RawMessage(`{}`)})
	select {
	case <-c.send:
		t.Fatalf("did not expect message for unsubscribed topic")
	default:
	}
}

func TestEnqueueDropsClosedClientWithoutPanic(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	c := &client{userID: uuid.New(), send: make(chan []byte, 1), topics: map[string]bool{}}

	hub.Unregister(c)
	hub.enqueue(c, "notification.new", []byte(`{"type":"notification.new"}`))
}

func TestHubConcurrentFanoutAndMutation(t *testing.T) {
	t.Run("concurrent_send_during_unregister", func(t *testing.T) {
		hub := NewHub(zerolog.Nop())
		userID := uuid.New()
		c := &client{userID: userID, send: make(chan []byte, 256), topics: map[string]bool{}}
		hub.clients[c] = true
		hub.byUser[userID] = map[*client]bool{c: true}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond)
			hub.Unregister(c)
		}()

		for range 100 {
			hub.SendToUser(userID, Message{Type: "notification.new", Payload: json.RawMessage(`{"id":"1"}`)})
		}

		wg.Wait()
	})

	t.Run("concurrent_broadcast_during_unregister", func(t *testing.T) {
		hub := NewHub(zerolog.Nop())
		userID := uuid.New()
		c := &client{userID: userID, send: make(chan []byte, 256), topics: map[string]bool{}}
		hub.clients[c] = true

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond)
			hub.Unregister(c)
		}()

		for range 100 {
			hub.Broadcast(Message{Type: "notification.new", Payload: json.RawMessage(`{"id":"1"}`)})
		}

		wg.Wait()
	})

	t.Run("concurrent_topic_mutation_during_send", func(t *testing.T) {
		hub := NewHub(zerolog.Nop())
		userID := uuid.New()
		c := &client{userID: userID, send: make(chan []byte, 256), topics: map[string]bool{}}
		hub.clients[c] = true
		hub.byUser[userID] = map[*client]bool{c: true}

		subscribe := Message{Type: "topic.subscribe", Payload: json.RawMessage(`{"topics":["notification.new"]}`)}
		unsubscribe := Message{Type: "topic.unsubscribe", Payload: json.RawMessage(`{"topics":["notification.new"]}`)}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				hub.handleClientMessage(context.Background(), c, subscribe)
				hub.handleClientMessage(context.Background(), c, unsubscribe)
			}
		}()

		for range 100 {
			hub.SendToUser(userID, Message{Type: "notification.new", Payload: json.RawMessage(`{"id":"1"}`)})
		}

		wg.Wait()
	})
}

func TestHTTPHandlerRejectsUnauthorizedBeforeUpgrade(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	server := httptest.NewServer(hub.HTTPHandler(auth.New(auth.Config{}, nil), nil))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err == nil {
		_ = conn.Close(websocket.StatusNormalClosure, "test complete")
		t.Fatal("expected unauthorized websocket dial to fail")
		return
	}
	if resp == nil {
		t.Fatal("expected HTTP response from failed websocket dial")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
		return
	}
}

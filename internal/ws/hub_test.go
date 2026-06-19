package ws

import (
	"context"
	"encoding/json"
	"errors"
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

type inMemoryTransport struct {
	subscribers []func(Envelope)
	err         error
}

type countingPublisher struct {
	err   error
	calls int
}

func (t *inMemoryTransport) Publish(_ context.Context, envelope Envelope) error {
	if t.err != nil {
		return t.err
	}
	for _, subscriber := range t.subscribers {
		subscriber(envelope)
	}
	return nil
}

func (p *countingPublisher) Publish(_ context.Context, _ Envelope) error {
	p.calls++
	return p.err
}

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

func TestHTTPHandlerRejectsUpgradeWhileDraining(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	hub.BeginDrain()
	server := httptest.NewServer(hub.HTTPHandler(auth.New(auth.Config{}, nil), nil))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err == nil {
		_ = conn.Close(websocket.StatusNormalClosure, "test complete")
		t.Fatal("expected draining websocket dial to fail")
	}
	if resp == nil {
		t.Fatal("expected HTTP response from failed websocket dial")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, resp.StatusCode)
	}
}

func TestWaitForZeroReturnsImmediatelyWhenNoClients(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := hub.WaitForZero(ctx); err != nil {
		t.Fatalf("WaitForZero() error = %v", err)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	envelope := Envelope{
		Type:    "notification.new",
		Payload: json.RawMessage(`{"id":"1"}`),
		UserIDs: []uuid.UUID{uuid.New()},
	}

	payload, err := MarshalEnvelope(envelope)
	if err != nil {
		t.Fatalf("MarshalEnvelope() error = %v", err)
	}

	decoded, err := UnmarshalEnvelope(payload)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope() error = %v", err)
	}

	if decoded.Type != envelope.Type {
		t.Fatalf("decoded type = %q, want %q", decoded.Type, envelope.Type)
	}
	if string(decoded.Payload) != string(envelope.Payload) {
		t.Fatalf("decoded payload = %s, want %s", decoded.Payload, envelope.Payload)
	}
	if len(decoded.UserIDs) != 1 || decoded.UserIDs[0] != envelope.UserIDs[0] {
		t.Fatalf("decoded userIDs = %#v, want %#v", decoded.UserIDs, envelope.UserIDs)
	}
}

func TestFanoutRoutesPublishedNotificationToReplicaHub(t *testing.T) {
	userID := uuid.New()
	otherUserID := uuid.New()
	transport := &inMemoryTransport{}

	originHub := NewHub(zerolog.Nop())
	originClient := &client{userID: userID, send: make(chan []byte, 1), topics: map[string]bool{"notification.new": true}}
	originHub.clients[originClient] = true
	originHub.byUser[userID] = map[*client]bool{originClient: true}
	originDispatch := NewDispatcher(originHub, zerolog.Nop())

	remoteHub := NewHub(zerolog.Nop())
	targetClient := &client{userID: userID, send: make(chan []byte, 1), topics: map[string]bool{"notification.new": true}}
	otherClient := &client{userID: otherUserID, send: make(chan []byte, 1), topics: map[string]bool{"notification.new": true}}
	remoteHub.clients[targetClient] = true
	remoteHub.clients[otherClient] = true
	remoteHub.byUser[userID] = map[*client]bool{targetClient: true}
	remoteHub.byUser[otherUserID] = map[*client]bool{otherClient: true}
	remoteDispatch := NewDispatcher(remoteHub, zerolog.Nop())

	transport.subscribers = []func(Envelope){originDispatch.Dispatch, remoteDispatch.Dispatch}
	fanout := NewFanout(transport, originDispatch, true, zerolog.Nop())

	fanout.PublishToUsers(context.Background(), []uuid.UUID{userID}, Message{Type: "notification.new", Payload: json.RawMessage(`{"id":"1"}`)})

	select {
	case msg := <-targetClient.send:
		var decoded Message
		if err := json.Unmarshal(msg, &decoded); err != nil {
			t.Fatalf("unmarshal remote message: %v", err)
		}
		if decoded.Type != "notification.new" {
			t.Fatalf("decoded remote type = %q, want notification.new", decoded.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("expected remote replica client to receive notification")
	}

	select {
	case <-otherClient.send:
		t.Fatal("unexpected notification for non-target user")
	default:
	}

	select {
	case <-originClient.send:
		// origin replica also receives the notification through the shared transport.
	case <-time.After(time.Second):
		t.Fatal("expected origin replica client to receive notification via shared transport")
	}
}

func TestFanoutDeliversLocallyWhenBridgeInactive(t *testing.T) {
	userID := uuid.New()
	hub := NewHub(zerolog.Nop())
	testClient := &client{userID: userID, send: make(chan []byte, 1), topics: map[string]bool{"notification.new": true}}
	hub.clients[testClient] = true
	hub.byUser[userID] = map[*client]bool{testClient: true}

	publisher := &countingPublisher{err: errors.New("boom")}
	fanout := NewFanout(publisher, NewDispatcher(hub, zerolog.Nop()), false, zerolog.Nop())
	fanout.PublishToUsers(context.Background(), []uuid.UUID{userID}, Message{Type: "notification.new", Payload: json.RawMessage(`{"id":"1"}`)})

	select {
	case <-testClient.send:
	case <-time.After(time.Second):
		t.Fatal("expected local delivery when bridge is inactive")
	}

	if publisher.calls != 0 {
		t.Fatalf("publisher called %d times, want 0 when bridge is inactive", publisher.calls)
	}
}

func TestFanoutBridgeActiveDoesNotFallbackToLocalDeliveryOnPublishError(t *testing.T) {
	userID := uuid.New()
	hub := NewHub(zerolog.Nop())
	testClient := &client{userID: userID, send: make(chan []byte, 1), topics: map[string]bool{"notification.new": true}}
	hub.clients[testClient] = true
	hub.byUser[userID] = map[*client]bool{testClient: true}

	publisher := &countingPublisher{err: errors.New("ambiguous publish error")}
	fanout := NewFanout(publisher, NewDispatcher(hub, zerolog.Nop()), true, zerolog.Nop())
	fanout.PublishToUsers(context.Background(), []uuid.UUID{userID}, Message{Type: "notification.new", Payload: json.RawMessage(`{"id":"1"}`)})

	if publisher.calls != 1 {
		t.Fatalf("publisher called %d times, want 1", publisher.calls)
	}

	select {
	case <-testClient.send:
		t.Fatal("did not expect local fallback delivery while bridge is active")
	case <-time.After(150 * time.Millisecond):
	}
}

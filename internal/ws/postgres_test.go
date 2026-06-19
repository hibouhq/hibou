package ws

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store"
)

const testDatabaseURL = "postgres://hibou:hibou@localhost:5432/hibou_test?sslmode=disable"

func TestPostgresPublishAndListen(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}

	db, err := openTestDB(databaseURL)
	if err != nil {
		t.Skipf("database not available for websocket LISTEN/NOTIFY test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	channel := "hibou_ws_events_" + uuid.NewString()
	received := make(chan Envelope, 1)
	listener, err := NewPostgresListener(databaseURL, channel, func(envelope Envelope) {
		received <- envelope
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewPostgresListener() error = %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	publisher := NewPostgresPublisher(db, channel)
	envelope := Envelope{
		Type:    "notification.new",
		Payload: []byte(`{"id":"1"}`),
		UserIDs: []uuid.UUID{uuid.New()},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := publisher.Publish(ctx, envelope); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	select {
	case got := <-received:
		if got.Type != envelope.Type {
			t.Fatalf("received type = %q, want %q", got.Type, envelope.Type)
		}
		if len(got.UserIDs) != 1 || got.UserIDs[0] != envelope.UserIDs[0] {
			t.Fatalf("received userIDs = %#v, want %#v", got.UserIDs, envelope.UserIDs)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for postgres notification")
	}
}

func TestPostgresTwoReplicaFanout(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}

	db, err := openTestDB(databaseURL)
	if err != nil {
		t.Skipf("database not available for websocket LISTEN/NOTIFY test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	channel := "hibou_ws_events_" + uuid.NewString()
	userID := uuid.New()
	envelope := Envelope{
		Type:    "notification.new",
		Payload: []byte(`{"id":"1"}`),
		UserIDs: []uuid.UUID{userID},
	}

	hubA := NewHub(zerolog.Nop())
	clientA := &client{userID: userID, send: make(chan []byte, 1), topics: map[string]bool{"notification.new": true}}
	hubA.clients[clientA] = true
	hubA.byUser[userID] = map[*client]bool{clientA: true}
	dispatcherA := NewDispatcher(hubA, zerolog.Nop())

	hubB := NewHub(zerolog.Nop())
	clientB := &client{userID: userID, send: make(chan []byte, 1), topics: map[string]bool{"notification.new": true}}
	hubB.clients[clientB] = true
	hubB.byUser[userID] = map[*client]bool{clientB: true}
	dispatcherB := NewDispatcher(hubB, zerolog.Nop())

	listenerA, err := NewPostgresListener(databaseURL, channel, dispatcherA.Dispatch, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewPostgresListener() replica A error = %v", err)
	}
	t.Cleanup(func() {
		_ = listenerA.Close()
	})

	listenerB, err := NewPostgresListener(databaseURL, channel, dispatcherB.Dispatch, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewPostgresListener() replica B error = %v", err)
	}
	t.Cleanup(func() {
		_ = listenerB.Close()
	})

	publisher := NewPostgresPublisher(db, channel)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := publisher.Publish(ctx, envelope); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	assertClientReceivesMessage(t, ctx, clientA.send, "replica A")
	assertClientReceivesMessage(t, ctx, clientB.send, "replica B")
}

func TestPostgresBridgeDeliversToOriginExactlyOnce(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}

	db, err := openTestDB(databaseURL)
	if err != nil {
		t.Skipf("database not available for websocket LISTEN/NOTIFY test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	channel := "hibou_ws_events_" + uuid.NewString()
	userID := uuid.New()
	hub := NewHub(zerolog.Nop())
	testClient := &client{userID: userID, send: make(chan []byte, 2), topics: map[string]bool{"notification.new": true}}
	hub.clients[testClient] = true
	hub.byUser[userID] = map[*client]bool{testClient: true}
	dispatcher := NewDispatcher(hub, zerolog.Nop())

	listener, err := NewPostgresListener(databaseURL, channel, dispatcher.Dispatch, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewPostgresListener() error = %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	fanout := NewFanout(NewPostgresPublisher(db, channel), dispatcher, true, zerolog.Nop())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fanout.PublishToUsers(ctx, []uuid.UUID{userID}, Message{Type: "notification.new", Payload: json.RawMessage(`{"id":"1"}`)})

	assertClientReceivesMessage(t, ctx, testClient.send, "origin replica")

	select {
	case msg := <-testClient.send:
		var decoded Message
		if err := json.Unmarshal(msg, &decoded); err != nil {
			t.Fatalf("unmarshal duplicate origin message: %v", err)
		}
		t.Fatalf("unexpected duplicate origin delivery: %#v", decoded)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPostgresPublisherRejectsOversizedPayload(t *testing.T) {
	publisher := NewPostgresPublisher(&sql.DB{}, DefaultChannel)
	userID := uuid.New()
	payload := json.RawMessage(`"` + strings.Repeat("a", maxNotifyPayloadSize) + `"`)

	err := publisher.Publish(context.Background(), Envelope{
		Type:    "notification.new",
		Payload: payload,
		UserIDs: []uuid.UUID{userID},
	})
	if err == nil {
		t.Fatal("Publish() error = nil, want oversized payload error")
	}
	if !errors.Is(err, ErrNotifyPayloadTooLarge) {
		t.Fatalf("Publish() error = %v, want ErrNotifyPayloadTooLarge", err)
	}
}

func assertClientReceivesMessage(t *testing.T, ctx context.Context, messages <-chan []byte, label string) {
	t.Helper()

	select {
	case msg := <-messages:
		var decoded Message
		if err := json.Unmarshal(msg, &decoded); err != nil {
			t.Fatalf("unmarshal %s message: %v", label, err)
		}
		if decoded.Type != "notification.new" {
			t.Fatalf("%s type = %q, want notification.new", label, decoded.Type)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s delivery", label)
	}
}

func openTestDB(databaseURL string) (*sql.DB, error) {
	var (
		db  *sql.DB
		err error
	)
	for range 10 {
		db, err = store.New(databaseURL)
		if err == nil {
			return db, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil, err
}

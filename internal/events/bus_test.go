package events

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSubscribeAndPublish(t *testing.T) {
	bus := New(zerolog.Nop())
	received := make(chan Event, 1)
	ctx := context.Background()
	want := Event{Type: ScanCompleted, Payload: "done"}

	bus.Subscribe(ScanCompleted, func(_ context.Context, event Event) {
		received <- event
	})

	bus.Publish(ctx, want)

	select {
	case got := <-received:
		if got.Type != want.Type {
			t.Fatalf("event type = %q, want %q", got.Type, want.Type)
		}
		if got.Payload != want.Payload {
			t.Fatalf("payload = %#v, want %#v", got.Payload, want.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestPublishNoSubscribers(t *testing.T) {
	bus := New(zerolog.Nop())

	bus.Publish(context.Background(), Event{Type: ScanCompleted, Payload: "done"})
}

func TestMultipleSubscribers(t *testing.T) {
	bus := New(zerolog.Nop())
	called := make(chan struct{}, 3)

	for range 3 {
		bus.Subscribe(ScanCompleted, func(_ context.Context, event Event) {
			if event.Type != ScanCompleted {
				t.Errorf("event type = %q, want %q", event.Type, ScanCompleted)
			}
			called <- struct{}{}
		})
	}

	bus.Publish(context.Background(), Event{Type: ScanCompleted})

	for i := 0; i < 3; i++ {
		select {
		case <-called:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for subscriber %d", i+1)
		}
	}
}

func TestSubscribeNilHandler(t *testing.T) {
	bus := New(zerolog.Nop())
	bus.Subscribe(ScanCompleted, nil)

	if got := len(bus.handlers[ScanCompleted]); got != 0 {
		t.Fatalf("handler count = %d, want 0", got)
	}

	bus.Publish(context.Background(), Event{Type: ScanCompleted})
}

func TestPublishSetsTimestamp(t *testing.T) {
	bus := New(zerolog.Nop())
	received := make(chan Event, 1)

	bus.Subscribe(ScanCompleted, func(_ context.Context, event Event) {
		received <- event
	})

	bus.Publish(context.Background(), Event{Type: ScanCompleted})

	select {
	case got := <-received:
		if got.Timestamp.IsZero() {
			t.Fatal("expected publish to set timestamp")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestHandlerPanicRecovery(t *testing.T) {
	bus := New(zerolog.Nop())
	panicked := make(chan struct{}, 1)
	recoveredPath := make(chan Event, 1)
	var panicCalls atomic.Int32

	bus.Subscribe(ScanCompleted, func(_ context.Context, event Event) {
		panicCalls.Add(1)
		panicked <- struct{}{}
		panic("boom")
	})

	bus.Publish(context.Background(), Event{Type: ScanCompleted, Payload: "bad"})

	select {
	case <-panicked:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for panic handler")
	}

	bus.Subscribe(ScanRequested, func(_ context.Context, event Event) {
		recoveredPath <- event
	})

	bus.Publish(context.Background(), Event{Type: ScanRequested, Payload: "ok"})

	select {
	case got := <-recoveredPath:
		if got.Type != ScanRequested {
			t.Fatalf("event type = %q, want %q", got.Type, ScanRequested)
		}
		if got.Payload != "ok" {
			t.Fatalf("payload = %#v, want %#v", got.Payload, "ok")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for recovery path event")
	}

	if got := panicCalls.Load(); got != 1 {
		t.Fatalf("panic handler calls = %d, want 1", got)
	}
}

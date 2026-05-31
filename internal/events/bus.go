package events

import (
	"context"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type Type string

const (
	ScanRequested       Type = "scan.requested"
	ScanCompleted       Type = "scan.completed"
	ScanFailed          Type = "scan.failed"
	ScanStale           Type = "scan.stale"
	VulnDiscovered      Type = "vuln.discovered"
	FindingCreated      Type = "finding.created"
	SecretScanCompleted Type = "secret.scan.completed"
	SecretScanFailed    Type = "secret.scan.failed"
	SecretDiscovered    Type = "secret.discovered"
	GatePassed          Type = "gate.passed"
	GateFailed          Type = "gate.failed"
	NotificationNew     Type = "notification.new"
)

type Event struct {
	Type      Type
	Payload   any
	Timestamp time.Time
}

type Handler func(ctx context.Context, event Event)

type Bus struct {
	mu       sync.RWMutex
	handlers map[Type][]Handler
	log      zerolog.Logger
}

func New(log zerolog.Logger) *Bus {
	return &Bus{
		handlers: make(map[Type][]Handler),
		log:      log.With().Str("component", "events.bus").Logger(),
	}
}

func (b *Bus) Publish(ctx context.Context, evt Event) {
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}

	b.mu.RLock()
	handlers := append([]Handler(nil), b.handlers[evt.Type]...)
	b.mu.RUnlock()

	for _, handler := range handlers {
		go func(handler Handler) {
			defer func() {
				if recovered := recover(); recovered != nil {
					b.log.Error().
						Any("panic", recovered).
						Str("event_type", string(evt.Type)).
						Bytes("stack", debug.Stack()).
						Msg("event handler panicked")
				}
			}()
			handler(ctx, evt)
		}(handler)
	}
}

func (b *Bus) Subscribe(eventType Type, handler Handler) {
	if handler == nil {
		return
	}

	b.mu.Lock()
	b.handlers[eventType] = append(b.handlers[eventType], handler)
	b.mu.Unlock()
}

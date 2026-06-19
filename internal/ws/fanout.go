package ws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

const (
	DefaultChannel       = "hibou_ws_events"
	maxNotifyPayloadSize = 7900
)

var ErrNotifyPayloadTooLarge = errors.New("websocket notify payload exceeds postgres limit")

type Envelope struct {
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	UserIDs   []uuid.UUID     `json:"user_ids,omitempty"`
	Broadcast bool            `json:"broadcast,omitempty"`
}

func (e Envelope) Message() Message {
	return Message{Type: e.Type, Payload: append(json.RawMessage(nil), e.Payload...)}
}

func (e Envelope) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	type alias Envelope
	return json.Marshal(alias(e))
}

func (e *Envelope) UnmarshalJSON(data []byte) error {
	type alias Envelope
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	decoded.Payload = append(json.RawMessage(nil), decoded.Payload...)
	*e = Envelope(decoded)
	return e.Validate()
}

func (e Envelope) Validate() error {
	if e.Type == "" {
		return errors.New("websocket envelope type is required")
	}
	if e.Broadcast {
		if len(e.UserIDs) > 0 {
			return errors.New("websocket envelope cannot target users and broadcast")
		}
		return nil
	}
	if len(e.UserIDs) == 0 {
		return errors.New("websocket envelope requires at least one user or broadcast")
	}
	for _, userID := range e.UserIDs {
		if userID == uuid.Nil {
			return errors.New("websocket envelope user_id cannot be empty")
		}
	}
	return nil
}

func MarshalEnvelope(e Envelope) ([]byte, error) {
	return json.Marshal(e)
}

func UnmarshalEnvelope(data []byte) (Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

type hubDispatcher interface {
	SendToUser(userID uuid.UUID, msg Message)
	Broadcast(msg Message)
}

type Publisher interface {
	Publish(ctx context.Context, envelope Envelope) error
}

type LiveDelivery interface {
	PublishToUsers(ctx context.Context, userIDs []uuid.UUID, msg Message)
	PublishBroadcast(ctx context.Context, msg Message)
}

type Dispatcher struct {
	hub hubDispatcher
	log zerolog.Logger
}

func NewDispatcher(hub hubDispatcher, log zerolog.Logger) *Dispatcher {
	return &Dispatcher{hub: hub, log: log.With().Str("component", "ws.dispatcher").Logger()}
}

func (d *Dispatcher) Dispatch(envelope Envelope) {
	if d == nil || d.hub == nil {
		return
	}
	if err := envelope.Validate(); err != nil {
		d.log.Warn().Err(err).Msg("drop invalid websocket envelope")
		return
	}

	message := envelope.Message()
	if envelope.Broadcast {
		d.hub.Broadcast(message)
		return
	}

	for _, userID := range slices.Clone(envelope.UserIDs) {
		d.hub.SendToUser(userID, message)
	}
}

type Fanout struct {
	publisher    Publisher
	dispatcher   *Dispatcher
	bridgeActive bool
	log          zerolog.Logger
}

func NewFanout(publisher Publisher, dispatcher *Dispatcher, bridgeActive bool, log zerolog.Logger) *Fanout {
	return &Fanout{
		publisher:    publisher,
		dispatcher:   dispatcher,
		bridgeActive: bridgeActive,
		log:          log.With().Str("component", "ws.fanout").Logger(),
	}
}

func (f *Fanout) PublishToUsers(ctx context.Context, userIDs []uuid.UUID, msg Message) {
	f.publish(ctx, Envelope{
		Type:    msg.Type,
		Payload: append(json.RawMessage(nil), msg.Payload...),
		UserIDs: compactUserIDs(userIDs),
	})
}

func (f *Fanout) PublishBroadcast(ctx context.Context, msg Message) {
	f.publish(ctx, Envelope{
		Type:      msg.Type,
		Payload:   append(json.RawMessage(nil), msg.Payload...),
		Broadcast: true,
	})
}

func (f *Fanout) publish(ctx context.Context, envelope Envelope) {
	if f == nil {
		return
	}
	if err := envelope.Validate(); err != nil {
		f.log.Warn().Err(err).Msg("drop invalid websocket fanout event")
		return
	}
	// Invariant: local hub dispatch happens iff the Postgres bridge is inactive;
	// when the bridge is active, delivery is exclusively via the listener to
	// guarantee exactly-once live pushes on the origin replica and peers.
	if !f.bridgeActive {
		f.dispatch(envelope)
		return
	}
	if f.publisher == nil {
		f.log.Warn().Msg("websocket bridge active without publisher; skipping local dispatch to preserve exactly-once")
		return
	}
	if err := f.publisher.Publish(ctx, envelope); err != nil {
		f.log.Warn().Err(err).Msg("websocket fanout publish failed; skipping local dispatch and relying on persisted notifications plus polling fallback")
	}
}

func (f *Fanout) dispatch(envelope Envelope) {
	if f.dispatcher == nil {
		return
	}
	f.dispatcher.Dispatch(envelope)
}

func compactUserIDs(userIDs []uuid.UUID) []uuid.UUID {
	if len(userIDs) == 0 {
		return nil
	}
	result := make([]uuid.UUID, 0, len(userIDs))
	seen := make(map[uuid.UUID]struct{}, len(userIDs))
	for _, userID := range userIDs {
		if userID == uuid.Nil {
			continue
		}
		if _, ok := seen[userID]; ok {
			continue
		}
		seen[userID] = struct{}{}
		result = append(result, userID)
	}
	return result
}

func checkNotifyPayloadSize(payload []byte) error {
	if len(payload) > maxNotifyPayloadSize {
		return fmt.Errorf("%w: %d bytes > %d", ErrNotifyPayloadTooLarge, len(payload), maxNotifyPayloadSize)
	}
	return nil
}

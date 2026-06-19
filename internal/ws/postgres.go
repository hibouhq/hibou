package ws

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/rs/zerolog"
)

const (
	listenerMinReconnect = 250 * time.Millisecond
	listenerMaxReconnect = 30 * time.Second
)

type PostgresPublisher struct {
	db      *sql.DB
	channel string
}

func NewPostgresPublisher(db *sql.DB, channel string) *PostgresPublisher {
	if db == nil {
		return nil
	}
	if channel == "" {
		channel = DefaultChannel
	}
	return &PostgresPublisher{db: db, channel: channel}
}

func (p *PostgresPublisher) Publish(ctx context.Context, envelope Envelope) error {
	if p == nil || p.db == nil {
		return errors.New("postgres websocket publisher unavailable")
	}
	payload, err := MarshalEnvelope(envelope)
	if err != nil {
		return fmt.Errorf("marshal websocket envelope: %w", err)
	}
	if err := checkNotifyPayloadSize(payload); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `SELECT pg_notify($1, $2)`, p.channel, string(payload)); err != nil {
		return fmt.Errorf("publish websocket envelope: %w", err)
	}
	return nil
}

type PostgresListener struct {
	listener *pq.Listener
	log      zerolog.Logger
	handler  func(Envelope)
	done     chan struct{}
}

func NewPostgresListener(databaseURL, channel string, handler func(Envelope), log zerolog.Logger) (*PostgresListener, error) {
	if databaseURL == "" {
		return nil, errors.New("database url is required")
	}
	if handler == nil {
		return nil, errors.New("websocket listener handler is required")
	}
	if channel == "" {
		channel = DefaultChannel
	}

	listener := pq.NewListener(databaseURL, listenerMinReconnect, listenerMaxReconnect, nil)
	if err := listener.Listen(channel); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("listen on %s: %w", channel, err)
	}

	pl := &PostgresListener{
		listener: listener,
		log:      log.With().Str("component", "ws.pg_listener").Str("channel", channel).Logger(),
		handler:  handler,
		done:     make(chan struct{}),
	}
	go pl.run()
	return pl, nil
}

func (l *PostgresListener) run() {
	for {
		select {
		case <-l.done:
			return
		case notification, ok := <-l.listener.Notify:
			if !ok {
				return
			}
			if notification == nil {
				continue
			}
			envelope, err := UnmarshalEnvelope([]byte(notification.Extra))
			if err != nil {
				l.log.Warn().Err(err).Msg("drop invalid postgres websocket notification")
				continue
			}
			l.handler(envelope)
		}
	}
}

func (l *PostgresListener) Close() error {
	if l == nil || l.listener == nil {
		return nil
	}
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return l.listener.Close()
}

package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Session defaults applied to every pooled connection unless the database URL
// sets them itself (e.g. "?statement_timeout=0" opts out). A runaway query or
// a transaction left open by a stuck request otherwise holds a backend, and
// its locks, indefinitely. Migrate clears the statement timeout on its own
// connection, so schema changes are not bound by it.
const (
	DefaultStatementTimeout         = 60 * time.Second
	DefaultIdleInTransactionTimeout = 60 * time.Second
)

// PoolConfig bounds the connection pool. Zero fields keep the defaults.
type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// DefaultPoolConfig keeps a burst of requests from opening more backends than
// a small Postgres allows (max_connections is 100 by default).
var DefaultPoolConfig = PoolConfig{
	MaxOpenConns:    40,
	MaxIdleConns:    10,
	ConnMaxLifetime: 30 * time.Minute,
	ConnMaxIdleTime: 5 * time.Minute,
}

// ConfigurePool applies pool limits; zero fields fall back to DefaultPoolConfig.
func ConfigurePool(db *sql.DB, cfg PoolConfig) {
	if db == nil {
		return
	}
	if cfg.MaxOpenConns <= 0 {
		cfg.MaxOpenConns = DefaultPoolConfig.MaxOpenConns
	}
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = DefaultPoolConfig.MaxIdleConns
	}
	if cfg.MaxIdleConns > cfg.MaxOpenConns {
		cfg.MaxIdleConns = cfg.MaxOpenConns
	}
	if cfg.ConnMaxLifetime <= 0 {
		cfg.ConnMaxLifetime = DefaultPoolConfig.ConnMaxLifetime
	}
	if cfg.ConnMaxIdleTime <= 0 {
		cfg.ConnMaxIdleTime = DefaultPoolConfig.ConnMaxIdleTime
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
}

// connectorWithSessionDefaults parses the URL and adds the default session
// timeouts as startup parameters where the URL does not set them.
func connectorWithSessionDefaults(databaseURL string) (*pq.Connector, error) {
	cfg, err := pq.NewConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	runtime := make(map[string]string, len(cfg.Runtime)+2)
	for key, value := range cfg.Runtime {
		runtime[key] = value
	}
	setDefault := func(key string, value time.Duration) {
		if _, ok := runtime[key]; ok || strings.Contains(cfg.Options, key) {
			return
		}
		runtime[key] = strconv.FormatInt(value.Milliseconds(), 10)
	}
	setDefault("statement_timeout", DefaultStatementTimeout)
	setDefault("idle_in_transaction_session_timeout", DefaultIdleInTransactionTimeout)
	cfg.Runtime = runtime
	return pq.NewConnectorConfig(cfg)
}

func New(databaseURL string) (*sql.DB, error) {
	connector, err := connectorWithSessionDefaults(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	db := sql.OpenDB(connector)
	ConfigurePool(db, DefaultPoolConfig)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return db, nil
}

func Migrate(db *sql.DB) error {
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("creating migration source: %w", err)
	}

	// A dedicated connection without the pool's statement timeout: a
	// migration rewriting a large table must not be cut off halfway.
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquiring migration connection: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `SET statement_timeout = 0`); err != nil {
		_ = conn.Close()
		return fmt.Errorf("clearing migration statement timeout: %w", err)
	}
	driver, err := postgres.WithConnection(ctx, conn, &postgres.Config{})
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("creating migration driver: %w", err)
	}
	defer func() {
		// The connection returns to the pool on Close: restore the session
		// default (the startup parameter) before anything else reuses it.
		_, _ = conn.ExecContext(ctx, `RESET statement_timeout`)
		_ = driver.Close()
	}()

	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}

	return nil
}

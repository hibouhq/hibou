package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/store"
)

func TestInstanceStorage(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	db, err := store.New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	queries := store.NewQueries(db)
	ctx := context.Background()

	// The key is instance-wide: put back whatever a running dev instance had.
	previous, err := queries.GetInstanceSettingValue(ctx, storageUsageSampleKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if previous != nil {
			_ = queries.SetInstanceSettingValue(context.Background(), storageUsageSampleKey, previous)
		} else {
			_, _ = db.Exec(`DELETE FROM instance_settings WHERE key = $1`, storageUsageSampleKey)
		}
	})
	if err := queries.SetInstanceSettingValue(ctx, storageUsageSampleKey,
		json.RawMessage(`{"postgres":{"collected_at":"2026-10-10T00:00:00Z","duration_seconds":0.1,"database_bytes":4096,"tables":[]}}`)); err != nil {
		t.Fatal(err)
	}

	srv := &Server{
		cfg: config.Config{
			InstanceAdmins:  []string{"admin@example.com"},
			ArtifactBackend: "filesystem",
			Metrics:         config.MetricsConfig{Enabled: true, BearerToken: "t"},
			StorageUsage:    config.StorageUsageConfig{Enabled: true, Interval: 15 * time.Minute},
		},
		log:     zerolog.Nop(),
		db:      db,
		queries: queries,
	}
	request := func(email string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/instance/storage", nil)
		if email != "" {
			req = req.WithContext(auth.WithUser(req.Context(), &store.User{Email: email}))
		}
		rec := httptest.NewRecorder()
		srv.handleInstanceStorage(rec, req)
		return rec
	}

	if code := request("").Code; code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", code)
	}
	if code := request("dev@example.com").Code; code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", code)
	}
	rec := request("admin@example.com")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data instanceStorageResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	got := body.Data
	if got.Sample == nil || got.Sample.Postgres == nil || got.Sample.Postgres.DatabaseBytes != 4096 {
		t.Fatalf("sample = %+v", got.Sample)
	}
	if got.IntervalSeconds != 900 || got.ArtifactBackend != "filesystem" || got.MetricsExposure != "token" {
		t.Fatalf("response = %+v", got)
	}
}

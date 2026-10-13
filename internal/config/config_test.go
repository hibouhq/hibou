package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/retention"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Port != 8585 {
		t.Errorf("expected default port 8585, got %d", cfg.Port)
	}
	if cfg.Development {
		t.Fatal("expected development mode disabled by default")
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("expected default host 0.0.0.0, got %s", cfg.Host)
	}
	if cfg.ListenAddr() != "0.0.0.0:8585" {
		t.Errorf("expected listen addr 0.0.0.0:8585, got %s", cfg.ListenAddr())
	}
	if cfg.OSVURL != "https://api.osv.dev" {
		t.Errorf("expected default OSV URL, got %s", cfg.OSVURL)
	}
	if cfg.CacheTTL != 6*time.Hour {
		t.Errorf("expected default cache ttl 6h, got %s", cfg.CacheTTL)
	}
	if cfg.AdvisoryScan.Interval != 6*time.Hour {
		t.Errorf("expected default advisory scan interval 6h, got %s", cfg.AdvisoryScan.Interval)
	}
	if len(cfg.AdvisoryScan.Providers) != 2 || cfg.AdvisoryScan.Providers[0] != "osv" || cfg.AdvisoryScan.Providers[1] != "trivy" {
		t.Fatalf("expected default advisory scan providers [osv trivy], got %v", cfg.AdvisoryScan.Providers)
	}
	if cfg.ArtifactBackend != "filesystem" {
		t.Errorf("expected default artifact backend filesystem, got %s", cfg.ArtifactBackend)
	}
	if cfg.ArtifactPath != "/data/artifacts" {
		t.Errorf("expected default artifact path /data/artifacts, got %s", cfg.ArtifactPath)
	}
	if cfg.ArtifactS3.UsePathStyle != true {
		t.Fatal("expected default artifact.s3.use_path_style enabled")
	}
	if cfg.ArtifactS3.UseSSL != true {
		t.Fatal("expected default artifact.s3.use_ssl enabled")
	}
	if cfg.UploadWindow != 10*time.Minute {
		t.Errorf("expected default upload window 10m, got %s", cfg.UploadWindow)
	}
	if cfg.Worker.LeaseDuration != 5*time.Minute {
		t.Errorf("expected default worker lease duration 5m, got %s", cfg.Worker.LeaseDuration)
	}
	if cfg.Worker.HeartbeatInterval != 100*time.Second {
		t.Errorf("expected default worker heartbeat interval 100s, got %s", cfg.Worker.HeartbeatInterval)
	}
	if cfg.SecretScan.Enabled {
		t.Fatal("expected secret scanning disabled by default")
	}
	if !cfg.Background.ArtifactProcessingEnabled || !cfg.Background.RetentionEnabled || !cfg.Background.StaleScanEnabled || !cfg.Background.StalePendingEnabled {
		t.Fatalf("expected background loops enabled by default, got %#v", cfg.Background)
	}
	// Unlike its siblings this one is off by default: it clones repositories, so
	// an upgrade must not start putting clone load on a single API pod.
	if cfg.Background.SecretScanEnabled {
		t.Fatal("expected the secret scan worker loop disabled by default")
	}
	if cfg.SecretScan.MaxConcurrency != 1 {
		t.Errorf("expected default secret scan concurrency 1, got %d", cfg.SecretScan.MaxConcurrency)
	}
	if cfg.SecretScan.Timeout != 5*time.Minute {
		t.Errorf("expected default secret scan timeout 5m, got %s", cfg.SecretScan.Timeout)
	}
	if cfg.SecretScan.PollInterval != 15*time.Second {
		t.Errorf("expected default secret scan poll interval 15s, got %s", cfg.SecretScan.PollInterval)
	}
	if cfg.SecretScan.MaxRepoMB != 2048 {
		t.Errorf("expected default secret scan max repo size 2048MB, got %d", cfg.SecretScan.MaxRepoMB)
	}
	if cfg.SecretScan.MaxAttempts != 3 {
		t.Errorf("expected default secret scan max attempts 3, got %d", cfg.SecretScan.MaxAttempts)
	}
	if cfg.RetentionPolicy.Storage.Budget == 0 {
		t.Fatal("expected default retention budget from envelope preset")
	}
	if cfg.RetentionPolicy.AutoPurge {
		t.Fatal("expected retention auto_purge disabled by default")
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("HIBOU_PORT", "9090")
	t.Setenv("HIBOU_METRICS_PORT", "9091") // the default 9090 would clash
	t.Setenv("HIBOU_HOST", "127.0.0.1")
	t.Setenv("HIBOU_DEVELOPMENT", "true")
	t.Setenv("HIBOU_LOG_LEVEL", "debug")
	t.Setenv("HIBOU_OSV_URL", "http://osv.internal")
	t.Setenv("HIBOU_CACHE_TTL", "30m")
	t.Setenv("HIBOU_ADVISORY_SCAN_INTERVAL", "45m") // TODO must be per provider (to do later.)
	t.Setenv("HIBOU_ADVISORY_SCAN_PROVIDERS", "osv,nvd,osv")
	t.Setenv("HIBOU_ARTIFACT_BACKEND", "s3")
	t.Setenv("HIBOU_ARTIFACT_PATH", "/tmp/hibou-artifacts")
	t.Setenv("HIBOU_ARTIFACT_S3_ENDPOINT", "s3.internal:9000")
	t.Setenv("HIBOU_ARTIFACT_S3_REGION", "us-east-1")
	t.Setenv("HIBOU_ARTIFACT_S3_BUCKET", "hibou-artifacts")
	t.Setenv("HIBOU_ARTIFACT_S3_ACCESS_KEY_ID", "access")
	t.Setenv("HIBOU_ARTIFACT_S3_SECRET_ACCESS_KEY", "secret")
	t.Setenv("HIBOU_ARTIFACT_S3_USE_PATH_STYLE", "false")
	t.Setenv("HIBOU_ARTIFACT_S3_USE_SSL", "false")
	t.Setenv("HIBOU_UPLOAD_WINDOW", "25m")
	t.Setenv("HIBOU_WORKER_LEASE_DURATION", "9m")
	t.Setenv("HIBOU_WORKER_HEARTBEAT_INTERVAL", "3m")
	t.Setenv("HIBOU_SECRET_SCAN_ENABLED", "true")
	t.Setenv("HIBOU_SECRET_SCAN_PROVIDERS", "gitleaks,github")
	t.Setenv("HIBOU_SECRET_SCAN_TEMP_DIR", "/tmp/hibou-secrets")
	t.Setenv("HIBOU_SECRET_SCAN_ON_PUSH", "true")
	t.Setenv("HIBOU_SECRET_SCAN_MAX_CONCURRENCY", "2")
	t.Setenv("HIBOU_SECRET_SCAN_TIMEOUT", "12m")
	t.Setenv("HIBOU_SECRET_SCAN_MAX_REPO_MB", "512")
	t.Setenv("HIBOU_SECRET_SCAN_MAX_ATTEMPTS", "5")
	t.Setenv("HIBOU_SECRET_SCAN_POLL_INTERVAL", "45s")
	t.Setenv("HIBOU_BACKGROUND_SECRET_SCAN_ENABLED", "true")
	t.Setenv("HIBOU_BACKGROUND_ARTIFACT_PROCESSING_ENABLED", "false")
	t.Setenv("HIBOU_BACKGROUND_RETENTION_ENABLED", "false")
	t.Setenv("HIBOU_BACKGROUND_STALE_SCAN_ENABLED", "false")
	t.Setenv("HIBOU_BACKGROUND_STALE_PENDING_ENABLED", "true")
	t.Setenv("HIBOU_RETENTION_STORAGE_BUDGET", "2GB")
	t.Setenv("HIBOU_RETENTION_STORAGE_WARN_AT", "90%")
	t.Setenv("HIBOU_RETENTION_STORAGE_TARGET", "0.6")
	t.Setenv("HIBOU_RETENTION_STORAGE_EVICT_ORDER", "oldest")
	t.Setenv("HIBOU_RETENTION_TIERS_ENABLED", "true")
	t.Setenv("HIBOU_RETENTION_TIERS_WEEK_ANCHOR", "friday")
	t.Setenv("HIBOU_RETENTION_TIERS_REPRESENTATIVE", "worst")
	t.Setenv("HIBOU_RETENTION_TIERS_DAILY_KEEP", "10")
	t.Setenv("HIBOU_RETENTION_KEEP_ALL", "72h")
	t.Setenv("HIBOU_RETENTION_FAILED_RETENTION", "36h")
	t.Setenv("HIBOU_RETENTION_AUTO_PURGE", "true")
	t.Setenv("HIBOU_RETENTION_DRY_RUN", "true")
	t.Setenv("HIBOU_RETENTION_PIN_LABELS", "baseline,audit")
	t.Setenv("HIBOU_RETENTION_PR_AFTER_CLOSE", "purge")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Port)
	}
	if !cfg.Development {
		t.Fatal("expected development mode enabled from env")
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", cfg.Host)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected log level debug, got %s", cfg.LogLevel)
	}
	if cfg.OSVURL != "http://osv.internal" {
		t.Errorf("expected OSV URL override, got %s", cfg.OSVURL)
	}
	if cfg.CacheTTL != 30*time.Minute {
		t.Errorf("expected cache ttl override, got %s", cfg.CacheTTL)
	}
	if cfg.AdvisoryScan.Interval != 45*time.Minute {
		t.Fatalf("expected advisory scan interval override, got %s", cfg.AdvisoryScan.Interval)
	}
	if got := cfg.AdvisoryScan.Providers; len(got) != 2 || got[0] != "osv" || got[1] != "nvd" {
		t.Fatalf("expected advisory scan providers [osv nvd], got %v", got)
	}
	if cfg.ArtifactBackend != "s3" {
		t.Errorf("expected artifact backend override, got %s", cfg.ArtifactBackend)
	}
	if cfg.ArtifactPath != "/tmp/hibou-artifacts" {
		t.Errorf("expected artifact path override, got %s", cfg.ArtifactPath)
	}
	if cfg.ArtifactS3.Endpoint != "s3.internal:9000" {
		t.Fatalf("expected artifact s3 endpoint override, got %s", cfg.ArtifactS3.Endpoint)
	}
	if cfg.ArtifactS3.Region != "us-east-1" {
		t.Fatalf("expected artifact s3 region override, got %s", cfg.ArtifactS3.Region)
	}
	if cfg.ArtifactS3.Bucket != "hibou-artifacts" {
		t.Fatalf("expected artifact s3 bucket override, got %s", cfg.ArtifactS3.Bucket)
	}
	if cfg.ArtifactS3.AccessKeyID != "access" {
		t.Fatalf("expected artifact s3 access key override, got %s", cfg.ArtifactS3.AccessKeyID)
	}
	if cfg.ArtifactS3.SecretAccessKey != "secret" {
		t.Fatalf("expected artifact s3 secret key override, got %s", cfg.ArtifactS3.SecretAccessKey)
	}
	if cfg.ArtifactS3.UsePathStyle {
		t.Fatal("expected artifact s3 path style disabled from env")
	}
	if cfg.ArtifactS3.UseSSL {
		t.Fatal("expected artifact s3 ssl disabled from env")
	}
	if cfg.UploadWindow != 25*time.Minute {
		t.Errorf("expected upload window override, got %s", cfg.UploadWindow)
	}
	if cfg.Worker.LeaseDuration != 9*time.Minute {
		t.Fatalf("expected worker lease duration override, got %s", cfg.Worker.LeaseDuration)
	}
	if cfg.Worker.HeartbeatInterval != 3*time.Minute {
		t.Fatalf("expected worker heartbeat interval override, got %s", cfg.Worker.HeartbeatInterval)
	}
	if !cfg.SecretScan.Enabled {
		t.Fatal("expected secret scan enabled from env")
	}
	if got := len(cfg.SecretScan.Providers); got != 2 {
		t.Fatalf("expected 2 secret scan providers, got %d", got)
	}
	if cfg.SecretScan.TempDir != "/tmp/hibou-secrets" {
		t.Fatalf("expected secret scan temp dir override, got %s", cfg.SecretScan.TempDir)
	}
	if !cfg.SecretScan.OnPush {
		t.Fatal("expected secret scan on_push enabled")
	}
	if !cfg.Background.SecretScanEnabled {
		t.Fatal("expected the secret scan worker loop enabled from env")
	}
	if cfg.SecretScan.MaxConcurrency != 2 {
		t.Fatalf("expected secret scan concurrency override 2, got %d", cfg.SecretScan.MaxConcurrency)
	}
	// Deliberately longer than the 9m lease: the heartbeat extends the claim
	// while work runs, so a long scan is legal and must not be rejected.
	if cfg.SecretScan.Timeout != 12*time.Minute {
		t.Fatalf("expected secret scan timeout override 12m, got %s", cfg.SecretScan.Timeout)
	}
	if cfg.SecretScan.MaxRepoMB != 512 {
		t.Fatalf("expected secret scan max repo size override 512, got %d", cfg.SecretScan.MaxRepoMB)
	}
	if cfg.SecretScan.MaxAttempts != 5 {
		t.Fatalf("expected secret scan max attempts override 5, got %d", cfg.SecretScan.MaxAttempts)
	}
	if cfg.SecretScan.PollInterval != 45*time.Second {
		t.Fatalf("expected secret scan poll interval override 45s, got %s", cfg.SecretScan.PollInterval)
	}
	if cfg.Background.ArtifactProcessingEnabled {
		t.Fatal("expected artifact processing loop disabled from env")
	}
	if cfg.Background.RetentionEnabled {
		t.Fatal("expected retention loop disabled from env")
	}
	if cfg.Background.StaleScanEnabled {
		t.Fatal("expected stale scan loop disabled from env")
	}
	if !cfg.Background.StalePendingEnabled {
		t.Fatal("expected stale pending loop enabled from env")
	}
	if cfg.RetentionPolicy.Storage.Budget != 2*(1<<30) {
		t.Fatalf("expected retention budget override, got %d", cfg.RetentionPolicy.Storage.Budget)
	}
	if cfg.RetentionPolicy.Storage.WarnAt != 0.9 {
		t.Fatalf("expected retention warn_at 0.9, got %v", cfg.RetentionPolicy.Storage.WarnAt)
	}
	if cfg.RetentionPolicy.Storage.Target != 0.6 {
		t.Fatalf("expected retention target 0.6, got %v", cfg.RetentionPolicy.Storage.Target)
	}
	if cfg.RetentionPolicy.Storage.EvictOrder != retention.EvictOldest {
		t.Fatalf("expected evict order oldest, got %q", cfg.RetentionPolicy.Storage.EvictOrder)
	}
	if !cfg.RetentionPolicy.Tiers.Enabled {
		t.Fatal("expected tiers enabled from env")
	}
	if cfg.RetentionPolicy.Tiers.WeekAnchor != time.Friday {
		t.Fatalf("expected retention week anchor friday, got %s", cfg.RetentionPolicy.Tiers.WeekAnchor)
	}
	if cfg.RetentionPolicy.Tiers.Representative != retention.RepresentativeWorst {
		t.Fatalf("expected representative worst, got %q", cfg.RetentionPolicy.Tiers.Representative)
	}
	if cfg.RetentionPolicy.Tiers.Daily.Keep != 10 {
		t.Fatalf("expected daily keep 10, got %d", cfg.RetentionPolicy.Tiers.Daily.Keep)
	}
	if cfg.RetentionPolicy.KeepAll != 72*time.Hour {
		t.Fatalf("expected keep_all 72h, got %s", cfg.RetentionPolicy.KeepAll)
	}
	if cfg.RetentionPolicy.FailedRetention != 36*time.Hour {
		t.Fatalf("expected failed retention 36h, got %s", cfg.RetentionPolicy.FailedRetention)
	}
	if !cfg.RetentionPolicy.AutoPurge {
		t.Fatal("expected auto_purge enabled from env")
	}
	if !cfg.RetentionPolicy.DryRun {
		t.Fatal("expected dry_run enabled from env")
	}
	if len(cfg.RetentionPolicy.Pin.Labels) != 2 {
		t.Fatalf("expected 2 pin labels, got %d", len(cfg.RetentionPolicy.Pin.Labels))
	}
	if cfg.RetentionPolicy.PRSnapshots.AfterClose != retention.ThinPurge {
		t.Fatalf("expected pr.after_close purge, got %q", cfg.RetentionPolicy.PRSnapshots.AfterClose)
	}

	// Clean up is handled by t.Setenv automatically
	_ = os.Getenv("HIBOU_PORT") // suppress unused import
}

func TestLoadRetentionPolicyFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	configContent := `
retention:
  preset: minimal
  keep_all: 48h
  storage:
    budget: 3GB
    warn_at: 75%
    target: 0.5
    evict_order: worst-first
  tiers:
    enabled: true
    week_anchor: monday
    representative: first
    weekly:
      keep: 8
  pin:
    latest_per_ref: false
  failed_retention: 12h
  auto_purge: true
  dry_run: true
`

	if err := os.WriteFile(filepath.Join(dir, "hibou-server.yaml"), []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if chdirErr := os.Chdir(originalDir); chdirErr != nil {
			t.Fatalf("restoring working directory: %v", chdirErr)
		}
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.RetentionPolicy.Storage.Budget != 3*(1<<30) {
		t.Fatalf("expected file retention budget 3GB, got %d", cfg.RetentionPolicy.Storage.Budget)
	}
	if cfg.RetentionPolicy.Storage.WarnAt != 0.75 {
		t.Fatalf("expected file retention warn_at 0.75, got %v", cfg.RetentionPolicy.Storage.WarnAt)
	}
	if cfg.RetentionPolicy.Storage.EvictOrder != retention.EvictWorstFirst {
		t.Fatalf("expected worst-first evict order, got %q", cfg.RetentionPolicy.Storage.EvictOrder)
	}
	if !cfg.RetentionPolicy.Tiers.Enabled {
		t.Fatal("expected tiers enabled from file")
	}
	if cfg.RetentionPolicy.Tiers.Representative != retention.RepresentativeFirst {
		t.Fatalf("expected representative first, got %q", cfg.RetentionPolicy.Tiers.Representative)
	}
	if cfg.RetentionPolicy.Tiers.Weekly.Keep != 8 {
		t.Fatalf("expected weekly keep 8, got %d", cfg.RetentionPolicy.Tiers.Weekly.Keep)
	}
	if cfg.RetentionPolicy.Pin.LatestPerRef {
		t.Fatal("expected latest_per_ref disabled from file")
	}
	if cfg.RetentionPolicy.FailedRetention != 12*time.Hour {
		t.Fatalf("expected failed retention 12h, got %s", cfg.RetentionPolicy.FailedRetention)
	}
	if !cfg.RetentionPolicy.AutoPurge || !cfg.RetentionPolicy.DryRun {
		t.Fatalf("expected auto_purge and dry_run enabled from file, got auto_purge=%v dry_run=%v", cfg.RetentionPolicy.AutoPurge, cfg.RetentionPolicy.DryRun)
	}
}

func TestValidateStartupRejectsDefaultSecretOutsideDevelopment(t *testing.T) {
	var logBuffer bytes.Buffer
	log := zerolog.New(&logBuffer)

	cfg := Config{
		SessionSecret: DefaultSessionSecret,
	}

	err := cfg.ValidateStartup(log)
	if err == nil {
		t.Fatal("expected startup validation error for default secret outside development")
	}
	if !strings.Contains(err.Error(), "stable random value shared by every replica") {
		t.Fatalf("expected actionable validation error, got %v", err)
	}
	if logBuffer.Len() != 0 {
		t.Fatalf("expected no warning log on rejected config, got %q", logBuffer.String())
	}
}

func TestValidateStartupRejectsEmptySecretOutsideDevelopment(t *testing.T) {
	var logBuffer bytes.Buffer
	log := zerolog.New(&logBuffer)

	cfg := Config{
		SessionSecret: "",
	}

	err := cfg.ValidateStartup(log)
	if err == nil {
		t.Fatal("expected startup validation error for empty secret outside development")
	}
	if !strings.Contains(err.Error(), "stable random value shared by every replica") {
		t.Fatalf("expected actionable validation error, got %v", err)
	}
	if logBuffer.Len() != 0 {
		t.Fatalf("expected no warning log on rejected config, got %q", logBuffer.String())
	}
}

func TestValidateStartupWarnsButAllowsDefaultSecretInDevelopment(t *testing.T) {
	var logBuffer bytes.Buffer
	log := zerolog.New(&logBuffer)

	cfg := Config{
		Development:   true,
		SessionSecret: DefaultSessionSecret,
	}

	if err := cfg.ValidateStartup(log); err != nil {
		t.Fatalf("expected development config to pass validation, got %v", err)
	}
	logged := logBuffer.String()
	if !strings.Contains(logged, "empty or using the default development signing secret") {
		t.Fatalf("expected warning about empty/default development secret, got %q", logged)
	}
	if strings.Contains(logged, DefaultSessionSecret) {
		t.Fatalf("warning log must not include secret value, got %q", logged)
	}
}

func TestValidateStartupAcceptsCustomSecret(t *testing.T) {
	var logBuffer bytes.Buffer
	log := zerolog.New(&logBuffer)

	cfg := Config{
		SessionSecret: "0123456789abcdef0123456789abcdef",
	}

	if err := cfg.ValidateStartup(log); err != nil {
		t.Fatalf("expected custom secret to pass validation, got %v", err)
	}
	if logBuffer.Len() != 0 {
		t.Fatalf("expected no warning log for valid secret, got %q", logBuffer.String())
	}
}

func TestLoadRetentionPolicyAliasesFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	configContent := `
retention:
  pin:
    labeled: [baseline, audit]
  pr_snapshots:
    keep_all: 9d
    after_close: purge
`

	if err := os.WriteFile(filepath.Join(dir, "hibou-server.yaml"), []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if chdirErr := os.Chdir(originalDir); chdirErr != nil {
			t.Fatalf("restoring working directory: %v", chdirErr)
		}
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if got := len(cfg.RetentionPolicy.Pin.Labels); got != 2 {
		t.Fatalf("expected 2 pin labels from alias, got %d", got)
	}
	if cfg.RetentionPolicy.Pin.Labels[0] != "baseline" || cfg.RetentionPolicy.Pin.Labels[1] != "audit" {
		t.Fatalf("expected alias pin labels [baseline audit], got %v", cfg.RetentionPolicy.Pin.Labels)
	}
	if cfg.RetentionPolicy.PRSnapshots.KeepAll != 9*24*time.Hour {
		t.Fatalf("expected pr_snapshots.keep_all alias 9d, got %s", cfg.RetentionPolicy.PRSnapshots.KeepAll)
	}
	if cfg.RetentionPolicy.PRSnapshots.AfterClose != retention.ThinPurge {
		t.Fatalf("expected pr_snapshots.after_close purge, got %q", cfg.RetentionPolicy.PRSnapshots.AfterClose)
	}
}

func TestLoadRetentionPolicyCanonicalKeysOverrideAliases(t *testing.T) {
	t.Setenv("HIBOU_RETENTION_PIN_LABELS", "canonical")
	t.Setenv("HIBOU_RETENTION_PIN_LABELED", "alias")
	t.Setenv("HIBOU_RETENTION_PR_KEEP_ALL", "7d")
	t.Setenv("HIBOU_RETENTION_PR_SNAPSHOTS_KEEP_ALL", "9d")
	t.Setenv("HIBOU_RETENTION_PR_AFTER_CLOSE", "purge")
	t.Setenv("HIBOU_RETENTION_PR_SNAPSHOTS_AFTER_CLOSE", "keep")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if got := cfg.RetentionPolicy.Pin.Labels; len(got) != 1 || got[0] != "canonical" {
		t.Fatalf("expected canonical pin.labels to win over alias, got %v", got)
	}
	if cfg.RetentionPolicy.PRSnapshots.KeepAll != 7*24*time.Hour {
		t.Fatalf("expected canonical pr.keep_all to win over alias, got %s", cfg.RetentionPolicy.PRSnapshots.KeepAll)
	}
	if cfg.RetentionPolicy.PRSnapshots.AfterClose != retention.ThinPurge {
		t.Fatalf("expected canonical pr.after_close to win over alias, got %q", cfg.RetentionPolicy.PRSnapshots.AfterClose)
	}
}

func TestLoadDefaultsUploadWindowWhenNonPositive(t *testing.T) {
	t.Setenv("HIBOU_UPLOAD_WINDOW", "0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.UploadWindow != 10*time.Minute {
		t.Errorf("expected non-positive upload window to fall back to 10m, got %s", cfg.UploadWindow)
	}
}

func TestLoadRejectsWorkerHeartbeatNotShorterThanLease(t *testing.T) {
	t.Setenv("HIBOU_WORKER_LEASE_DURATION", "2m")
	t.Setenv("HIBOU_WORKER_HEARTBEAT_INTERVAL", "2m")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want validation failure")
	}
	if !strings.Contains(err.Error(), "worker.heartbeat.interval must be shorter than worker.lease.duration") {
		t.Fatalf("expected heartbeat/lease validation error, got %v", err)
	}
}

func TestLoadForgeConfigs(t *testing.T) {
	t.Setenv("HIBOU_FORGE_0_TYPE", "forgejo")
	t.Setenv("HIBOU_FORGE_0_ID", "dev-forgejo")
	t.Setenv("HIBOU_FORGE_0_URL", "http://localhost:3030")
	t.Setenv("HIBOU_FORGE_0_CLIENT_ID", "client-0")
	t.Setenv("HIBOU_FORGE_0_CLIENT_SECRET", "secret-0")
	t.Setenv("HIBOU_FORGE_0_WEBHOOK_SECRET", "hook-0")
	t.Setenv("HIBOU_FORGE_0_IP_ALLOWLIST", "true")
	t.Setenv("HIBOU_FORGE_0_RATE_LIMIT_RPS", "7.5")

	t.Setenv("HIBOU_FORGE_1_TYPE", "github")
	t.Setenv("HIBOU_FORGE_1_CLIENT_ID", "client-1")
	t.Setenv("HIBOU_FORGE_1_CLIENT_SECRET", "secret-1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.Forges) != 2 {
		t.Fatalf("expected 2 forge configs, got %d", len(cfg.Forges))
	}

	f0 := cfg.Forges[0]
	if f0.Type != "forgejo" {
		t.Errorf("forge 0: expected type forgejo, got %s", f0.Type)
	}
	if f0.ID != "dev-forgejo" {
		t.Errorf("forge 0: expected id dev-forgejo, got %s", f0.ID)
	}
	if f0.URL != "http://localhost:3030" {
		t.Errorf("forge 0: expected url http://localhost:3030, got %s", f0.URL)
	}
	if f0.ClientID != "client-0" {
		t.Errorf("forge 0: expected client_id client-0, got %s", f0.ClientID)
	}
	if !f0.IPAllowlist {
		t.Error("forge 0: expected ip allowlist enabled")
	}
	if f0.RateLimitRPS != 7.5 {
		t.Errorf("forge 0: expected rate limit 7.5, got %v", f0.RateLimitRPS)
	}

	f1 := cfg.Forges[1]
	if f1.Type != "github" {
		t.Errorf("forge 1: expected type github, got %s", f1.Type)
	}
	if f1.ID != "github" {
		t.Errorf("forge 1: expected default id github, got %s", f1.ID)
	}
}

func TestLoadForgeConfigsEmpty(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if len(cfg.Forges) != 0 {
		t.Errorf("expected 0 forge configs without env vars, got %d", len(cfg.Forges))
	}
}

func TestLoadFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	configContent := `
host: 10.0.0.1
port: 9999
log:
  level: trace
cache:
  ttl: "1h"
`

	err := os.WriteFile(filepath.Join(dir, "hibou-server.yaml"), []byte(configContent), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if chdirErr := os.Chdir(originalDir); chdirErr != nil {
			t.Fatalf("restoring working directory: %v", chdirErr)
		}
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Host != "10.0.0.1" {
		t.Errorf("expected host from file, got %s", cfg.Host)
	}
	if cfg.Port != 9999 {
		t.Errorf("expected port from file, got %d", cfg.Port)
	}
	if cfg.LogLevel != "trace" {
		t.Errorf("expected log level from file, got %s", cfg.LogLevel)
	}
}

func TestEnvOverridesConfigFile(t *testing.T) {
	dir := t.TempDir()
	configContent := `
port: 7777
`

	err := os.WriteFile(filepath.Join(dir, "hibou-server.yaml"), []byte(configContent), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if chdirErr := os.Chdir(originalDir); chdirErr != nil {
			t.Fatalf("restoring working directory: %v", chdirErr)
		}
	}()

	t.Setenv("HIBOU_PORT", "8888")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Port != 8888 {
		t.Errorf("expected env to override file, got %d", cfg.Port)
	}
}

func TestLoadMetricsAndStorageUsage(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HIBOU_METRICS_PORT", "9090")
	t.Setenv("HIBOU_METRICS_BEARER_TOKEN", "from-env")
	t.Setenv("HIBOU_METRICS_BEARER_TOKEN_FILE", tokenFile)
	t.Setenv("HIBOU_STORAGE_USAGE_INTERVAL", "5m")
	t.Setenv("HIBOU_STORAGE_USAGE_INVENTORY_ENABLED", "true")
	t.Setenv("HIBOU_STORAGE_USAGE_INVENTORY_MAX_OBJECTS", "500")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Metrics.Enabled || cfg.Metrics.Port != 9090 || cfg.Metrics.BearerToken != "from-file" {
		t.Fatalf("metrics = %+v, want port 9090 and the file token", cfg.Metrics)
	}
	su := cfg.StorageUsage
	if !su.Enabled || su.Interval != 5*time.Minute || !su.Inventory.Enabled || su.Inventory.Interval != 24*time.Hour || su.Inventory.MaxObjects != 500 {
		t.Fatalf("storage usage = %+v", su)
	}
}

func TestLoadMetricsRejectsInvalid(t *testing.T) {
	for name, env := range map[string][2]string{
		"port clash":         {"HIBOU_METRICS_PORT", "8585"},
		"empty token file":   {"HIBOU_METRICS_BEARER_TOKEN_FILE", "EMPTY"},
		"missing token file": {"HIBOU_METRICS_BEARER_TOKEN_FILE", "/nonexistent/token"},
		"interval too short": {"HIBOU_STORAGE_USAGE_INTERVAL", "10s"},
		"inventory too fast": {"HIBOU_STORAGE_USAGE_INVENTORY_INTERVAL", "5m"},
		"no objects":         {"HIBOU_STORAGE_USAGE_INVENTORY_MAX_OBJECTS", "0"},
	} {
		t.Run(name, func(t *testing.T) {
			value := env[1]
			if value == "EMPTY" {
				value = filepath.Join(t.TempDir(), "empty")
				if err := os.WriteFile(value, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv(env[0], value)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted %s=%s", env[0], value)
			}
		})
	}
}

// Disabled metrics never clash: the port is unused, so it is not validated
// against the application ports.
func TestLoadMetricsDisabledSkipsPortCheck(t *testing.T) {
	t.Setenv("HIBOU_METRICS_ENABLED", "false")
	t.Setenv("HIBOU_METRICS_PORT", "8585")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Metrics.Enabled {
		t.Fatal("metrics.enabled = true, want false")
	}
}

// A12: a short HMAC key is refused outside development.
func TestValidateStartupRejectsShortSecretOutsideDevelopment(t *testing.T) {
	cfg := Config{SessionSecret: "too-short-but-not-default"}
	err := cfg.ValidateStartup(zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("expected short-secret rejection, got %v", err)
	}

	cfg.Development = true
	if err := cfg.ValidateStartup(zerolog.Nop()); err != nil {
		t.Fatalf("development accepts a short secret, got %v", err)
	}
}

// §3.4 / A3: outside development a forge without a webhook secret or an
// OAuth client id refuses startup; development only warns.
func TestValidateStartupForgeSecrets(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	complete := ForgeConfig{Type: "github", ID: "github", ClientID: "cid", WebhookSecret: "hook"}

	if err := (Config{SessionSecret: secret, Forges: []ForgeConfig{complete}}).ValidateStartup(zerolog.Nop()); err != nil {
		t.Fatalf("complete forge: %v", err)
	}

	noHook := complete
	noHook.WebhookSecret = ""
	err := (Config{SessionSecret: secret, Forges: []ForgeConfig{noHook}}).ValidateStartup(zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "HIBOU_FORGE_0_WEBHOOK_SECRET") {
		t.Fatalf("missing webhook secret: got %v", err)
	}

	noClient := complete
	noClient.ClientID = ""
	err = (Config{SessionSecret: secret, Forges: []ForgeConfig{noClient}}).ValidateStartup(zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "HIBOU_FORGE_0_CLIENT_ID") {
		t.Fatalf("missing client id: got %v", err)
	}

	var logBuffer bytes.Buffer
	dev := Config{Development: true, SessionSecret: secret, Forges: []ForgeConfig{noHook}}
	if err := dev.ValidateStartup(zerolog.New(&logBuffer)); err != nil {
		t.Fatalf("development must start: %v", err)
	}
	if !strings.Contains(logBuffer.String(), "INSECURE") {
		t.Fatalf("development must warn loudly, got %q", logBuffer.String())
	}
}

func TestLoadAuthAllowlists(t *testing.T) {
	t.Setenv("HIBOU_AUTH_ALLOWED_ORGS", "HibouHQ, other-org")
	t.Setenv("HIBOU_AUTH_ALLOWED_USERS", "octocat")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := strings.Join(cfg.Auth.AllowedOrgs, ","); got != "hibouhq,other-org" {
		t.Fatalf("AllowedOrgs = %q", got)
	}
	if got := strings.Join(cfg.Auth.AllowedUsers, ","); got != "octocat" || !cfg.Auth.Restricted() {
		t.Fatalf("AllowedUsers = %q", got)
	}
}

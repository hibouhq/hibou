package config

import (
	"os"
	"testing"
)

// The mirror case depends entirely on this binding: an operator sets
// cve_feed.remote through the chart, which sets HIBOU_CVE_FEED_REMOTE. If the
// env name and the config key ever drift, an air-gapped instance silently falls
// back to the public list and fails to reach it.
func TestCVEFeedRemoteComesFromTheEnvironment(t *testing.T) {
	t.Setenv("HIBOU_CVE_FEED_REMOTE", "https://git.internal/mirrors/cvelistV5.git")
	t.Setenv("HIBOU_DATABASE_URL", "postgres://x/y?sslmode=disable")
	t.Setenv("HIBOU_SESSION_SECRET", "0123456789abcdef0123456789abcdef")
	_ = os.Unsetenv("HIBOU_CONFIG")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CVEFeed.Remote != "https://git.internal/mirrors/cvelistV5.git" {
		t.Fatalf("CVEFeed.Remote = %q, want the mirror", cfg.CVEFeed.Remote)
	}
}

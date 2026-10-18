// Package updatecheck reports whether a newer Hibou release is available.
//
// A background goroutine polls the GitHub "latest release" endpoint on an
// interval, caches the result, and compares the running version against it
// with semantic versioning. The cached comparison is served to the UI so no
// request ever blocks on GitHub.
package updatecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/mod/semver"
)

const (
	defaultInterval = 24 * time.Hour
	requestTimeout  = 10 * time.Second
	defaultEndpoint = "https://api.github.com/repos/hibouhq/hibou/releases/latest"
	releaseTagBase  = "https://github.com/hibouhq/hibou/releases/tag/"
)

// Result is the cached version comparison returned to callers.
type Result struct {
	Current         string    `json:"current"`
	CurrentURL      string    `json:"current_url,omitempty"`
	Latest          string    `json:"latest,omitempty"`
	UpdateAvailable bool      `json:"update_available"`
	ReleaseURL      string    `json:"release_url,omitempty"`
	CheckedAt       time.Time `json:"checked_at,omitempty"`
}

// Checker polls GitHub for the latest release and caches the comparison.
type Checker struct {
	current  string
	endpoint string
	interval time.Duration
	client   *http.Client
	log      zerolog.Logger

	mu         sync.RWMutex
	latest     string
	releaseURL string
	checkedAt  time.Time
}

// New builds a Checker for the given running version (e.g. "v0.1.0-alpha.30").
func New(current string, log zerolog.Logger) *Checker {
	return &Checker{
		current:  current,
		endpoint: defaultEndpoint,
		interval: defaultInterval,
		client:   &http.Client{Timeout: requestTimeout},
		log:      log.With().Str("component", "updatecheck").Logger(),
	}
}

// Result returns the latest cached comparison. Safe for concurrent use and
// never blocks on the network.
func (c *Checker) Result() Result {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Result{
		Current:         c.current,
		CurrentURL:      releaseTagURL(c.current),
		Latest:          c.latest,
		UpdateAvailable: isNewer(c.current, c.latest),
		ReleaseURL:      c.releaseURL,
		CheckedAt:       c.checkedAt,
	}
}

// Start performs an immediate check, then refreshes on the interval until ctx
// is cancelled. Intended to run in its own goroutine.
func (c *Checker) Start(ctx context.Context) {
	c.refresh(ctx)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.refresh(ctx)
		}
	}
}

func (c *Checker) refresh(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		c.log.Warn().Err(err).Msg("build update-check request")
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.client.Do(req)
	if err != nil {
		c.log.Warn().Err(err).Msg("fetch latest release")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		c.log.Warn().Int("status", resp.StatusCode).Msg("unexpected status from github releases")
		return
	}

	var payload struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		c.log.Warn().Err(err).Msg("decode latest release")
		return
	}

	c.mu.Lock()
	c.latest = payload.TagName
	c.releaseURL = payload.HTMLURL
	c.checkedAt = time.Now()
	c.mu.Unlock()

	c.log.Debug().Str("current", c.current).Str("latest", payload.TagName).Msg("update check refreshed")
}

// isNewer reports whether latest is a strictly higher semver than current.
// Non-semver values (e.g. "dev", "") yield false so dev builds never nag.
func isNewer(current, latest string) bool {
	cur := normalize(current)
	lat := normalize(latest)
	if !semver.IsValid(cur) || !semver.IsValid(lat) {
		return false
	}
	return semver.Compare(lat, cur) > 0
}

// releaseTagURL returns the GitHub release-notes page for a version, or "" when
// the version is not a valid release tag (e.g. "dev"), so such builds aren't
// linked to a non-existent page.
func releaseTagURL(version string) string {
	v := normalize(version)
	if !semver.IsValid(v) {
		return ""
	}
	return releaseTagBase + v
}

// normalize trims and ensures a leading "v" so x/mod/semver accepts the value.
func normalize(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

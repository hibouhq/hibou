package depsdev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/version"
)

// DefaultURL is the public API. An operator points URL at an egress proxy
// serving the same paths; there is no mirror to point at.
const DefaultURL = "https://api.deps.dev"

// MaxBatch is the API's hard limit per batch request ("Sending more than
// 5000 requests will result in a 400 error").
const MaxBatch = 5000

// maxResponseBytes bounds one batch response. 5,000 findings results are a
// few MB; 64 MiB is a broken upstream, not a large answer.
const maxResponseBytes = 64 << 20

// Client calls the deps.dev v3alpha API. v3alpha has no stability promise,
// so every decode here tolerates unknown fields and enum values.
type Client struct {
	baseURL    string
	httpClient *http.Client
	// batch is the request count per batch call, MaxBatch by default and
	// smaller in tests.
	batch int
	// sleep is replaced in tests.
	sleep func(context.Context, time.Duration) error
}

// New returns a client for baseURL (DefaultURL when empty).
func New(baseURL string, httpClient *http.Client) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = DefaultURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 2 * time.Minute}
	}
	return &Client{baseURL: baseURL, httpClient: httpClient, batch: MaxBatch, sleep: sleepContext}
}

// isJSONEmpty reports a missing, null or empty-object value: the shapes a
// batch answer uses for "nothing known".
func isJSONEmpty(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed == "" || trimmed == "null" || trimmed == "{}"
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Finding is one GOSSIP finding. Context fields are set per type; unknown
// types decode with Type set and nothing else, and are ignored by
// Normalize.
type Finding struct {
	Type              string             `json:"type"`
	Risk              string             `json:"risk,omitempty"`
	DeprecatedContext *DeprecatedContext `json:"deprecatedContext,omitempty"`
	CooldownContext   *CooldownContext   `json:"cooldownContext,omitempty"`
	LowUsageContext   *LowUsageContext   `json:"lowUsageContext,omitempty"`
}

type DeprecatedContext struct {
	Reason string `json:"reason"`
}

type CooldownContext struct {
	End string `json:"end"`
}

// LowUsageContext carries the alternatives deps.dev suggests. Their exact
// shape is not documented, so they are kept raw and parsed leniently.
type LowUsageContext struct {
	AlternativePackages []json.RawMessage `json:"alternativePackages"`
}

// VersionFindings is one version's findings block (requested, default or
// recommended).
type VersionFindings struct {
	VersionKey  VersionKey `json:"versionKey"`
	IsDefault   bool       `json:"isDefault"`
	Findings    []Finding  `json:"findings"`
	CooldownEnd string     `json:"cooldownEnd,omitempty"`
}

// Findings is one GetFindings response.
type Findings struct {
	PackageKey          *PackageKey       `json:"packageKey,omitempty"`
	VersionKey          *VersionKey       `json:"versionKey,omitempty"`
	RecommendedVersions []VersionFindings `json:"recommendedVersions"`
	RequestedVersion    *VersionFindings  `json:"requestedVersion,omitempty"`
	DefaultVersion      *VersionFindings  `json:"defaultVersion,omitempty"`
	PackageFindings     []Finding         `json:"packageFindings"`
}

type PackageKey struct {
	System string `json:"system"`
	Name   string `json:"name"`
}

type findingsBatchRequest struct {
	Requests  []findingsBatchItem `json:"requests"`
	PageToken string              `json:"pageToken,omitempty"`
}

type findingsBatchItem struct {
	VersionKey *VersionKey `json:"versionKey,omitempty"`
}

type findingsBatchResponse struct {
	Responses []struct {
		Request  findingsBatchItem `json:"request"`
		Findings json.RawMessage   `json:"findings"`
	} `json:"responses"`
	NextPageToken string `json:"nextPageToken"`
}

// FindingsResult pairs a decoded response with the bytes it came from, so
// the raw document can be stored for forward compatibility.
type FindingsResult struct {
	Findings Findings
	Raw      json.RawMessage
}

// FindingsBatch looks up findings for every key, in chunks of the batch
// size, following pagination. Keys the API did not answer are absent from
// the result; that is "unknown", not "clean".
func (c *Client) FindingsBatch(ctx context.Context, keys []VersionKey) (map[VersionKey]FindingsResult, error) {
	results := make(map[VersionKey]FindingsResult, len(keys))
	for start := 0; start < len(keys); start += c.batch {
		end := min(start+c.batch, len(keys))
		if err := c.findingsChunk(ctx, keys[start:end], results); err != nil {
			return results, err
		}
	}
	return results, nil
}

func (c *Client) findingsChunk(ctx context.Context, keys []VersionKey, results map[VersionKey]FindingsResult) error {
	items := make([]findingsBatchItem, 0, len(keys))
	for i := range keys {
		key := keys[i]
		items = append(items, findingsBatchItem{VersionKey: &key})
	}
	pageToken := ""
	for page := 0; page < 100; page++ {
		var decoded findingsBatchResponse
		if err := c.post(ctx, "/v3alpha/findingsbatch", findingsBatchRequest{Requests: items, PageToken: pageToken}, &decoded); err != nil {
			return err
		}
		for _, response := range decoded.Responses {
			if response.Request.VersionKey == nil || isJSONEmpty(response.Findings) {
				continue
			}
			var findings Findings
			if err := json.Unmarshal(response.Findings, &findings); err != nil {
				continue
			}
			if findings.VersionKey == nil && findings.PackageKey == nil {
				// An answer that names nothing is no answer.
				continue
			}
			results[*response.Request.VersionKey] = FindingsResult{Findings: findings, Raw: response.Findings}
		}
		if decoded.NextPageToken == "" {
			return nil
		}
		pageToken = decoded.NextPageToken
	}
	return errors.New("depsdev: findingsbatch pagination did not terminate")
}

// VersionInfo is the subset of a GetVersion / PurlLookup result the sync
// keeps: when the version was published and what the registry says about
// it.
type VersionInfo struct {
	PublishedAt      string `json:"publishedAt"`
	IsDeprecated     bool   `json:"isDeprecated"`
	DeprecatedReason string `json:"deprecatedReason"`
	Cooldown         *struct {
		End         string `json:"end"`
		Description string `json:"description"`
	} `json:"cooldown,omitempty"`
}

type purlBatchRequest struct {
	Requests  []purlBatchItem `json:"requests"`
	PageToken string          `json:"pageToken,omitempty"`
}

type purlBatchItem struct {
	Purl string `json:"purl"`
}

type purlBatchResponse struct {
	Responses []struct {
		Request purlBatchItem `json:"request"`
		Result  *struct {
			Version *VersionInfo `json:"version"`
		} `json:"result,omitempty"`
	} `json:"responses"`
	NextPageToken string `json:"nextPageToken"`
}

// VersionBatch looks up version metadata by canonical purl. A purl the
// registry does not know maps to a nil entry, which is how "not found" is
// told apart from "not answered".
func (c *Client) VersionBatch(ctx context.Context, purls []string) (map[string]*VersionInfo, error) {
	results := make(map[string]*VersionInfo, len(purls))
	for start := 0; start < len(purls); start += c.batch {
		end := min(start+c.batch, len(purls))
		if err := c.versionChunk(ctx, purls[start:end], results); err != nil {
			return results, err
		}
	}
	return results, nil
}

func (c *Client) versionChunk(ctx context.Context, purls []string, results map[string]*VersionInfo) error {
	items := make([]purlBatchItem, 0, len(purls))
	for _, purl := range purls {
		items = append(items, purlBatchItem{Purl: purl})
	}
	pageToken := ""
	for page := 0; page < 100; page++ {
		var decoded purlBatchResponse
		if err := c.post(ctx, "/v3alpha/purlbatch", purlBatchRequest{Requests: items, PageToken: pageToken}, &decoded); err != nil {
			return err
		}
		for _, response := range decoded.Responses {
			if response.Request.Purl == "" {
				continue
			}
			if response.Result == nil || response.Result.Version == nil {
				results[response.Request.Purl] = nil
				continue
			}
			info := *response.Result.Version
			results[response.Request.Purl] = &info
		}
		if decoded.NextPageToken == "" {
			return nil
		}
		pageToken = decoded.NextPageToken
	}
	return errors.New("depsdev: purlbatch pagination did not terminate")
}

// RetryableError marks an upstream answer worth retrying later (429, 5xx,
// transport failure), as opposed to a request the API rejects.
type RetryableError struct {
	Status int
	Err    error
}

func (e *RetryableError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("depsdev: upstream returned status %d", e.Status)
	}
	return "depsdev: " + e.Err.Error()
}

func (e *RetryableError) Unwrap() error { return e.Err }

// post sends one JSON request with bounded retries on 429 and 5xx. Rate
// limits are not published, so Retry-After is honoured when present and a
// short exponential wait is used otherwise.
func (c *Client) post(ctx context.Context, path string, body, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("depsdev: encode request: %w", err)
	}
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			wait := time.Duration(1<<uint(attempt-1)) * time.Second // #nosec G115 -- attempt is 1..3
			var retryable *RetryableError
			if errors.As(last, &retryable) && retryable.Status == http.StatusTooManyRequests {
				wait = max(wait, retryAfter(retryable))
			}
			if err := c.sleep(ctx, wait); err != nil {
				return err
			}
		}
		last = c.postOnce(ctx, path, encoded, out)
		if last == nil {
			return nil
		}
		var retryable *RetryableError
		if !errors.As(last, &retryable) {
			return last
		}
	}
	return last
}

func retryAfter(err *RetryableError) time.Duration {
	var hinted retryAfterError
	if errors.As(err.Err, &hinted) {
		return hinted.wait
	}
	return 0
}

type retryAfterError struct{ wait time.Duration }

func (e retryAfterError) Error() string { return "retry after " + e.wait.String() }

func (c *Client) postOnce(ctx context.Context, path string, encoded []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("depsdev: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "hibou/"+version.Version)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &RetryableError{Err: err}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		var inner error
		if seconds, parseErr := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); parseErr == nil && seconds > 0 {
			inner = retryAfterError{wait: time.Duration(min(seconds, 60)) * time.Second}
		}
		return &RetryableError{Status: resp.StatusCode, Err: inner}
	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("depsdev: %s returned status %d: %s", path, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("depsdev: decode %s response: %w", path, err)
	}
	return nil
}

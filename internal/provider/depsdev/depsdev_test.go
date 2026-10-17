package depsdev

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Fixtures are live API answers captured on 2026-10-15 (ADR-048 Context),
// plus one FUTURE_TYPE finding to check unknown types are ignored.
func loadFixtures(t *testing.T) (map[string]json.RawMessage, map[string]json.RawMessage) {
	t.Helper()
	var findings, versions map[string]json.RawMessage
	for file, target := range map[string]*map[string]json.RawMessage{"testdata/findings.json": &findings, "testdata/versions.json": &versions} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			t.Fatalf("decode %s: %v", file, err)
		}
	}
	return findings, versions
}

func fixtureServer(t *testing.T, findings, versions map[string]json.RawMessage, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/v3alpha/findingsbatch":
			var req findingsBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode findings request: %v", err)
			}
			var out findingsBatchResponse
			for _, item := range req.Requests {
				key := item.VersionKey
				entry := struct {
					Request  findingsBatchItem `json:"request"`
					Findings json.RawMessage   `json:"findings"`
				}{Request: item}
				if raw, ok := findings[key.System+"/"+key.Name+"/"+key.Version]; ok {
					entry.Findings = raw
				}
				out.Responses = append(out.Responses, entry)
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/v3alpha/purlbatch":
			var req purlBatchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode purl request: %v", err)
			}
			type result struct {
				Version json.RawMessage `json:"version"`
			}
			type response struct {
				Request purlBatchItem `json:"request"`
				Result  *result       `json:"result,omitempty"`
			}
			out := struct {
				Responses []response `json:"responses"`
			}{}
			for _, item := range req.Requests {
				entry := response{Request: item}
				if raw, ok := versions[item.Purl]; ok {
					entry.Result = &result{Version: raw}
				}
				out.Responses = append(out.Responses, entry)
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestParsePurl(t *testing.T) {
	cases := []struct {
		purl      string
		want      VersionKey
		canonical string
		ok        bool
	}{
		{"pkg:npm/lodash@4.17.20", VersionKey{SystemNPM, "lodash", "4.17.20"}, "pkg:npm/lodash@4.17.20", true},
		{"pkg:npm/%40ctrl/tinycolor@4.1.1", VersionKey{SystemNPM, "@ctrl/tinycolor", "4.1.1"}, "pkg:npm/@ctrl/tinycolor@4.1.1", true},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", VersionKey{SystemMaven, "org.apache.logging.log4j:log4j-core", "2.14.1"}, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", true},
		{"pkg:golang/github.com/golang/protobuf@v1.5.4", VersionKey{SystemGo, "github.com/golang/protobuf", "v1.5.4"}, "pkg:golang/github.com/golang/protobuf@v1.5.4", true},
		{"pkg:gomod/github.com/golang/protobuf@v1.5.4", VersionKey{SystemGo, "github.com/golang/protobuf", "v1.5.4"}, "pkg:golang/github.com/golang/protobuf@v1.5.4", true},
		{"pkg:pypi/Requests@2.32.3", VersionKey{SystemPyPI, "requests", "2.32.3"}, "pkg:pypi/requests@2.32.3", true},
		{"pkg:pypi/typing_extensions@4.12.2", VersionKey{SystemPyPI, "typing-extensions", "4.12.2"}, "pkg:pypi/typing-extensions@4.12.2", true},
		{"pkg:pypi/zope.interface@6.4", VersionKey{SystemPyPI, "zope-interface", "6.4"}, "pkg:pypi/zope-interface@6.4", true},
		{"pkg:cargo/serde@1.0.219", VersionKey{SystemCargo, "serde", "1.0.219"}, "pkg:cargo/serde@1.0.219", true},
		{"pkg:nuget/Castle.Core@5.1.1", VersionKey{SystemNuGet, "castle.core", "5.1.1"}, "pkg:nuget/Castle.Core@5.1.1", true},
		{"pkg:gem/rails@7.1.0", VersionKey{SystemRubyGems, "rails", "7.1.0"}, "pkg:gem/rails@7.1.0", true},
		{"pkg:deb/debian/curl@7.88.1", VersionKey{}, "", false},
		{"pkg:golang/stdlib@1.13.6", VersionKey{}, "", false},
		{"pkg:golang/toolchain@go1.24.2", VersionKey{}, "", false},
		{"pkg:npm/lodash", VersionKey{}, "", false},
		{"lodash@4.17.20", VersionKey{}, "", false},
		{"pkg:maven/log4j-core@2.14.1", VersionKey{}, "", false},
	}
	for _, tc := range cases {
		got, canonical, ok := ParsePurl(tc.purl)
		if ok != tc.ok || got != tc.want || canonical != tc.canonical {
			t.Errorf("ParsePurl(%q) = %+v, %q, %v; want %+v, %q, %v", tc.purl, got, canonical, ok, tc.want, tc.canonical, tc.ok)
		}
	}
}

func TestMatchesNamespace(t *testing.T) {
	cases := []struct {
		purl, pattern string
		want          bool
	}{
		{"pkg:npm/%40acme/billing@1.0.0", "pkg:npm/@acme/*", true},
		{"pkg:npm/%40acme-internal/billing@1.0.0", "pkg:npm/@acme/*", false},
		{"pkg:maven/com.acme.billing/core@1.0.0", "pkg:maven/com.acme.*", true},
		{"pkg:maven/com.acmecorp/core@1.0.0", "pkg:maven/com.acme.*", false},
		{"pkg:golang/git.acme.example/team/lib@v1.2.3", "pkg:golang/git.acme.example/*", true},
		{"pkg:npm/lodash@4.17.20", "pkg:npm/lodash", true},
		{"pkg:npm/lodash-es@4.17.20", "pkg:npm/lodash", false},
		{"pkg:npm/lodash@4.17.20", "*lodash*", true},
		{"pkg:npm/lodash@4.17.20", "", false},
	}
	for _, tc := range cases {
		if got := MatchesNamespace(tc.purl, tc.pattern); got != tc.want {
			t.Errorf("MatchesNamespace(%q, %q) = %v, want %v", tc.purl, tc.pattern, got, tc.want)
		}
	}
	if !IsPrivate("pkg:npm/%40acme/x@1", []string{"pkg:gem/*", "pkg:npm/@acme/*"}) {
		t.Error("IsPrivate should match the second pattern")
	}
}

func TestNormalizeFromFixtures(t *testing.T) {
	findings, versions := loadFixtures(t)
	server := fixtureServer(t, findings, versions, nil)
	defer server.Close()
	client := New(server.URL, server.Client())
	now := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)

	purls := []string{
		"pkg:npm/lodash@4.17.20",
		"pkg:npm/express@5.3.0",
		"pkg:npm/lodahs@0.0.1-security",
		"pkg:npm/request@2.88.2",
		"pkg:golang/github.com/golang/protobuf@v1.5.4",
		"pkg:npm/lodash-es-utils@2.0.9",
		"pkg:npm/%40ctrl/tinycolor@4.1.1",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
	}
	keys := make([]VersionKey, 0, len(purls))
	canonicals := make([]string, 0, len(purls))
	for _, purl := range purls {
		key, canonical, ok := ParsePurl(purl)
		if !ok {
			t.Fatalf("ParsePurl(%q) failed", purl)
		}
		keys = append(keys, key)
		canonicals = append(canonicals, canonical)
	}
	found, err := client.FindingsBatch(context.Background(), keys)
	if err != nil {
		t.Fatalf("FindingsBatch: %v", err)
	}
	infos, err := client.VersionBatch(context.Background(), canonicals)
	if err != nil {
		t.Fatalf("VersionBatch: %v", err)
	}
	signals := make(map[string]Signals, len(purls))
	for i, purl := range purls {
		var f *FindingsResult
		if result, ok := found[keys[i]]; ok {
			f = &result
		}
		signals[purl] = Normalize(purl, keys[i], f, infos[canonicals[i]], now)
	}

	lodash := signals["pkg:npm/lodash@4.17.20"]
	if lodash.InCooldown(now) || lodash.Deprecated || lodash.LowUsage || lodash.NotFound || lodash.Malicious || lodash.VulnerableCritical {
		t.Errorf("lodash: no signal expected, got %+v", lodash)
	}
	if lodash.PublishedAt == nil || lodash.PublishedAt.Year() != 2020 {
		t.Errorf("lodash: published_at from the version lookup, got %v", lodash.PublishedAt)
	}
	if lodash.RecommendedVersion != "4.18.1" {
		t.Errorf("lodash: recommended 4.18.1, got %q", lodash.RecommendedVersion)
	}

	express := signals["pkg:npm/express@5.3.0"]
	if !express.InCooldown(now) || express.CooldownEnd == nil || express.CooldownEnd.Format(time.RFC3339) != "2026-10-24T12:56:54Z" {
		t.Errorf("express: cooldown until 2026-10-24, got %+v", express.CooldownEnd)
	}
	if express.InCooldown(now.AddDate(0, 0, 10)) {
		t.Error("express: cooldown must have ended ten days later without a refresh")
	}
	if express.RecommendedVersion != "" {
		t.Errorf("express: no recommendation expected, got %q", express.RecommendedVersion)
	}

	lodahs := signals["pkg:npm/lodahs@0.0.1-security"]
	if !lodahs.Malicious || !lodahs.InCooldown(now.AddDate(100, 0, 0)) {
		t.Errorf("lodahs: malicious with an infinite cooldown, got %+v", lodahs)
	}

	request := signals["pkg:npm/request@2.88.2"]
	if !request.Deprecated || !strings.Contains(request.DeprecatedReason, "issues/3142") {
		t.Errorf("request: deprecated with the registry reason, got %+v", request)
	}
	if request.RecommendedVersion != "" {
		t.Errorf("request: the requested version itself is never recommended, got %q", request.RecommendedVersion)
	}

	protobuf := signals["pkg:golang/github.com/golang/protobuf@v1.5.4"]
	if !protobuf.Deprecated || !strings.Contains(protobuf.DeprecatedReason, "google.golang.org/protobuf") {
		t.Errorf("protobuf: Go module deprecation, got %+v", protobuf)
	}

	utils := signals["pkg:npm/lodash-es-utils@2.0.9"]
	if !utils.LowUsage || len(utils.Alternatives) != 1 || utils.Alternatives[0] != "lodash-es" {
		t.Errorf("lodash-es-utils: low usage with lodash-es as alternative, got %+v", utils)
	}

	tinycolor := signals["pkg:npm/%40ctrl/tinycolor@4.1.1"]
	if !tinycolor.NotFound {
		t.Errorf("tinycolor 4.1.1: unpublished from the NOT_FOUND finding, got %+v", tinycolor)
	}
	// An empty version lookup alone never means unpublished.
	onlyMissingLookup := Normalize("pkg:npm/lodash@4.17.20", keys[0], nil, nil, now)
	if onlyMissingLookup.NotFound {
		t.Error("a missing version lookup must not mark a version unpublished")
	}
	withFindingsNoLookup := Normalize("pkg:npm/lodash@4.17.20", keys[0], ptr(found[keys[0]]), nil, now)
	if withFindingsNoLookup.NotFound || withFindingsNoLookup.RecommendedVersion != "4.18.1" {
		t.Errorf("findings without a version lookup still normalise, got %+v", withFindingsNoLookup)
	}
	if tinycolor.PublishedAt != nil {
		t.Error("tinycolor 4.1.1: no publish date for a version the registry no longer has")
	}
	if tinycolor.RecommendedVersion != "4.2.1" {
		t.Errorf("tinycolor: recommended 4.2.1, got %q", tinycolor.RecommendedVersion)
	}

	log4j := signals["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar"]
	if !log4j.VulnerableCritical || log4j.Malicious {
		t.Errorf("log4j-core: vulnerable_critical only, got %+v", log4j)
	}
	if !strings.Contains(string(log4j.Raw), "FUTURE_TYPE") {
		t.Error("log4j-core: unknown finding types must be kept in raw")
	}
}

func TestFindingsBatchChunksAndMissingAnswers(t *testing.T) {
	findings, versions := loadFixtures(t)
	var calls atomic.Int32
	server := fixtureServer(t, findings, versions, &calls)
	defer server.Close()
	client := New(server.URL, server.Client())
	client.batch = 2
	keys := []VersionKey{
		{SystemNPM, "lodash", "4.17.20"},
		{SystemNPM, "nobody-knows-this", "1.0.0"},
		{SystemNPM, "express", "5.3.0"},
	}
	found, err := client.FindingsBatch(context.Background(), keys)
	if err != nil {
		t.Fatalf("FindingsBatch: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("expected 2 batch calls for 3 keys with batch=2, got %d", calls.Load())
	}
	if _, ok := found[keys[1]]; ok {
		t.Error("an unanswered key must be absent, not an empty answer")
	}
	if len(found) != 2 {
		t.Errorf("expected 2 answers, got %d", len(found))
	}
}

func TestPostRetriesOnRateLimitThenGivesUp(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	client := New(server.URL, server.Client())
	var waited []time.Duration
	client.sleep = func(_ context.Context, d time.Duration) error {
		waited = append(waited, d)
		return nil
	}
	_, err := client.FindingsBatch(context.Background(), []VersionKey{{SystemNPM, "lodash", "4.17.20"}})
	var retryable *RetryableError
	if err == nil || !errors.As(err, &retryable) || retryable.Status != http.StatusTooManyRequests {
		t.Fatalf("expected a retryable 429 error, got %v", err)
	}
	if calls.Load() != 4 {
		t.Errorf("expected 4 attempts, got %d", calls.Load())
	}
	if len(waited) != 3 || waited[0] < time.Second {
		t.Errorf("expected 3 waits honouring Retry-After, got %v", waited)
	}
}

func TestPostDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()
	client := New(server.URL, server.Client())
	_, err := client.VersionBatch(context.Background(), []string{"pkg:npm/lodash@4.17.20"})
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected a 400 error, got %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("a 400 must not be retried, got %d attempts", calls.Load())
	}
}

func ptr[T any](v T) *T { return &v }

func TestWithVersion(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/%40scope/name@1.0.0":        "pkg:npm/%40scope/name@4.19.2",
		"pkg:npm/lodash@4.17.20?foo=bar#sub": "pkg:npm/lodash@4.19.2",
		"pkg:maven/org.apache/commons@1.2":   "pkg:maven/org.apache/commons@4.19.2",
		"pkg:golang/github.com/x/y@v1.0.0":   "pkg:golang/github.com/x/y@4.19.2",
		"pkg:npm/lodash":                     "pkg:npm/lodash@4.19.2",
	}
	for in, want := range cases {
		if got := WithVersion(in, "4.19.2"); got != want {
			t.Errorf("WithVersion(%q) = %q, want %q", in, got, want)
		}
		if _, _, ok := ParsePurl(WithVersion(in, "4.19.2")); !ok {
			t.Errorf("WithVersion(%q) does not parse", in)
		}
	}
	if got := WithVersion("pkg:npm/lodash@1.0.0", "1.0.0+build"); got != "pkg:npm/lodash@1.0.0+build" {
		t.Errorf("build metadata: %q", got)
	}
}

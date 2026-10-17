package packagepolicy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/provider/depsdev"
	"github.com/hibouhq/hibou/internal/store"
)

type fakeStore struct {
	mu          sync.Mutex
	signals     map[string]store.PackageSignal
	acceptances []store.PackagePolicyAcceptance
}

func (f *fakeStore) GetPackageSignalsByPurls(_ context.Context, purls []string) (map[string]store.PackageSignal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]store.PackageSignal{}
	for _, purl := range purls {
		if row, ok := f.signals[purl]; ok {
			out[purl] = row
		}
	}
	return out, nil
}

func (f *fakeStore) UpsertPackageSignals(_ context.Context, signals []depsdev.Signals) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range signals {
		row := store.PackageSignal{Purl: s.Purl, Name: s.Key.Name, Version: s.Key.Version, Deprecated: s.Deprecated, DeprecatedReason: s.DeprecatedReason,
			LowUsage: s.LowUsage, NotFound: s.NotFound, Malicious: s.Malicious, RecommendedVersion: s.RecommendedVersion, FetchedAt: time.Now()}
		if s.PublishedAt != nil {
			row.PublishedAt = sql.NullTime{Time: *s.PublishedAt, Valid: true}
		}
		if s.CooldownEnd != nil {
			row.CooldownEnd = sql.NullTime{Time: *s.CooldownEnd, Valid: true}
		}
		row.Alternatives, _ = json.Marshal(s.Alternatives)
		f.signals[s.Purl] = row
	}
	return nil
}

func (f *fakeStore) ListPackagePolicyAcceptancesForPurls(_ context.Context, _ uuid.UUID, repoID *uuid.UUID, purls []string) ([]store.PackagePolicyAcceptance, error) {
	var out []store.PackagePolicyAcceptance
	for _, a := range f.acceptances {
		for _, purl := range purls {
			if a.Purl == purl && (a.RepoID == nil || (repoID != nil && *a.RepoID == *repoID)) {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

type fakeLookup struct {
	calls    atomic.Int32
	findings map[depsdev.VersionKey]depsdev.FindingsResult
	infos    map[string]*depsdev.VersionInfo
	err      error
	delay    time.Duration
}

func (f *fakeLookup) FindingsBatch(_ context.Context, keys []depsdev.VersionKey) (map[depsdev.VersionKey]depsdev.FindingsResult, error) {
	f.calls.Add(1)
	time.Sleep(f.delay)
	if f.err != nil {
		return nil, f.err
	}
	out := map[depsdev.VersionKey]depsdev.FindingsResult{}
	for _, key := range keys {
		if r, ok := f.findings[key]; ok {
			out[key] = r
		}
	}
	return out, nil
}

func (f *fakeLookup) VersionBatch(_ context.Context, purls []string) (map[string]*depsdev.VersionInfo, error) {
	out := map[string]*depsdev.VersionInfo{}
	for _, purl := range purls {
		if info, ok := f.infos[purl]; ok {
			out[purl] = info
		}
	}
	return out, nil
}

func row(purl string, published, cooldownEnd time.Time, mutate func(*store.PackageSignal)) store.PackageSignal {
	r := store.PackageSignal{Purl: purl, FetchedAt: time.Now(), Alternatives: json.RawMessage(`[]`)}
	if !published.IsZero() {
		r.PublishedAt = sql.NullTime{Time: published, Valid: true}
	}
	if !cooldownEnd.IsZero() {
		r.CooldownEnd = sql.NullTime{Time: cooldownEnd, Valid: true}
	}
	if mutate != nil {
		mutate(&r)
	}
	return r
}

func TestEvaluateDecisions(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	fs := &fakeStore{signals: map[string]store.PackageSignal{
		"pkg:npm/express@5.3.0":       row("pkg:npm/express@5.3.0", now.AddDate(0, 0, -3), now.AddDate(0, 0, 12), nil),
		"pkg:npm/lodash@4.17.21":      row("pkg:npm/lodash@4.17.21", now.AddDate(-2, 0, 0), now.AddDate(-2, 0, 15), nil),
		"pkg:npm/lodahs@0.0.1":        row("pkg:npm/lodahs@0.0.1", time.Time{}, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), func(r *store.PackageSignal) { r.Malicious = true }),
		"pkg:npm/request@2.88.2":      row("pkg:npm/request@2.88.2", now.AddDate(-6, 0, 0), now.AddDate(-6, 0, 15), func(r *store.PackageSignal) { r.Deprecated = true; r.DeprecatedReason = "see issue 3142" }),
		"pkg:npm/lodash-es-utils@2.0": row("pkg:npm/lodash-es-utils@2.0", now.AddDate(-1, 0, 0), now.AddDate(-1, 0, 15), func(r *store.PackageSignal) { r.LowUsage = true; r.Alternatives = json.RawMessage(`["lodash-es"]`) }),
	}}
	orgID := uuid.New()
	e := New(fs, Options{InstanceNamespaces: []string{"pkg:npm/@acme/*"}})

	decisions, err := e.Evaluate(context.Background(), Request{OrgID: orgID, Now: now, Policy: e.DefaultPolicy(), Purls: []string{
		"pkg:npm/express@5.3.0", "pkg:npm/lodash@4.17.21", "pkg:npm/lodahs@0.0.1", "pkg:npm/request@2.88.2", "pkg:npm/lodash-es-utils@2.0",
		"pkg:npm/%40acme/billing@1.0.0", "pkg:deb/debian/curl@7.88.1", "pkg:npm/unknown-thing@1.0.0",
	}})
	if err != nil {
		t.Fatal(err)
	}
	byPurl := map[string]Decision{}
	for _, d := range decisions {
		byPurl[d.Purl] = d
	}
	if d := byPurl["pkg:npm/express@5.3.0"]; d.Decision != DecisionHold || d.Until == nil || !d.Until.Equal(now.AddDate(0, 0, 12)) || !d.Evaluated {
		t.Errorf("express: want hold until deps.dev's end, got %+v", d)
	}
	if d := byPurl["pkg:npm/lodash@4.17.21"]; d.Decision != DecisionAllow || !d.Evaluated || len(d.Warnings) != 0 {
		t.Errorf("lodash: want plain allow, got %+v", d)
	}
	if d := byPurl["pkg:npm/lodahs@0.0.1"]; d.Decision != DecisionDeny {
		t.Errorf("lodahs: want deny, got %+v", d)
	}
	if d := byPurl["pkg:npm/request@2.88.2"]; d.Decision != DecisionAllow || len(d.Warnings) != 1 || d.Warnings[0] != "deprecated: see issue 3142" {
		t.Errorf("request: want allow with the deprecation warning, got %+v", d)
	}
	if d := byPurl["pkg:npm/lodash-es-utils@2.0"]; d.Decision != DecisionAllow || len(d.Warnings) != 1 || d.Warnings[0] != "low usage: did you mean lodash-es?" {
		t.Errorf("lodash-es-utils: want allow with the alternative, got %+v", d)
	}
	if d := byPurl["pkg:npm/%40acme/billing@1.0.0"]; d.Decision != DecisionAllow || d.Evaluated || d.Reason == "" {
		t.Errorf("private namespace must be allowed and not evaluated, got %+v", d)
	}
	if d := byPurl["pkg:deb/debian/curl@7.88.1"]; d.Decision != DecisionAllow || d.Evaluated {
		t.Errorf("uncovered ecosystem must be allowed and not evaluated, got %+v", d)
	}
	if d := byPurl["pkg:npm/unknown-thing@1.0.0"]; d.Decision != DecisionAllow || d.Evaluated || d.Reason == "" {
		t.Errorf("no signal and no lookup must be allowed and not evaluated, got %+v", d)
	}
}

func TestEvaluateFixedWindowAndAcceptance(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	orgID, repoID := uuid.New(), uuid.New()
	fs := &fakeStore{
		signals: map[string]store.PackageSignal{
			// deps.dev says the cooldown ended two days ago; a 7-day window says otherwise.
			"pkg:npm/express@5.3.0": row("pkg:npm/express@5.3.0", now.AddDate(0, 0, -5), now.AddDate(0, 0, -2), nil),
			"pkg:npm/lodahs@0.0.1":  row("pkg:npm/lodahs@0.0.1", time.Time{}, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), func(r *store.PackageSignal) { r.Malicious = true }),
		},
		acceptances: []store.PackagePolicyAcceptance{
			{OrgID: orgID, RepoID: &repoID, Purl: "pkg:npm/express@5.3.0", Reason: "security patch needed today"},
		},
	}
	e := New(fs, Options{})
	policy := e.PolicyWith("7d", nil)
	if policy.WindowMode != "duration" || policy.WindowDuration != 7*24*time.Hour {
		t.Fatalf("policy %+v", policy)
	}

	// Without the repository context the acceptance does not apply.
	decisions, err := e.Evaluate(context.Background(), Request{OrgID: orgID, Now: now, Policy: policy, Purls: []string{"pkg:npm/express@5.3.0", "pkg:npm/lodahs@0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if decisions[0].Decision != DecisionHold || decisions[0].Until == nil || !decisions[0].Until.Equal(now.AddDate(0, 0, 2)) {
		t.Errorf("7-day window from publish date must hold two more days, got %+v", decisions[0])
	}
	// With it, the hold is lifted and says so; a deny stays a deny unless accepted too.
	decisions, err = e.Evaluate(context.Background(), Request{OrgID: orgID, RepoID: &repoID, Now: now, Policy: policy, Purls: []string{"pkg:npm/express@5.3.0", "pkg:npm/lodahs@0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if decisions[0].Decision != DecisionAllow || !decisions[0].Accepted || decisions[0].Reason != "accepted for this repository: security patch needed today" {
		t.Errorf("acceptance must lift the hold with its reason, got %+v", decisions[0])
	}
	if decisions[1].Decision != DecisionDeny {
		t.Errorf("malicious stays denied without an acceptance, got %+v", decisions[1])
	}

	// Window off: nothing holds.
	off := e.PolicyWith("off", nil)
	decisions, _ = e.Evaluate(context.Background(), Request{OrgID: orgID, Now: now, Policy: off, Purls: []string{"pkg:npm/express@5.3.0"}})
	if decisions[0].Decision != DecisionAllow {
		t.Errorf("window off must allow, got %+v", decisions[0])
	}
}

func TestEvaluateLooksUpMissingOnceAcrossCallers(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	key := depsdev.VersionKey{System: depsdev.SystemNPM, Name: "express", Version: "5.3.0"}
	lookup := &fakeLookup{
		delay: 50 * time.Millisecond,
		findings: map[depsdev.VersionKey]depsdev.FindingsResult{key: {Findings: depsdev.Findings{
			VersionKey:       &key,
			RequestedVersion: &depsdev.VersionFindings{VersionKey: key, CooldownEnd: now.AddDate(0, 0, 8).Format(time.RFC3339)},
		}, Raw: json.RawMessage(`{}`)}},
		infos: map[string]*depsdev.VersionInfo{"pkg:npm/express@5.3.0": {PublishedAt: now.AddDate(0, 0, -7).Format(time.RFC3339)}},
	}
	fs := &fakeStore{signals: map[string]store.PackageSignal{}}
	e := New(fs, Options{Lookup: lookup})
	orgID := uuid.New()

	var wg sync.WaitGroup
	results := make([][]Decision, 5)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			decisions, err := e.Evaluate(context.Background(), Request{OrgID: orgID, Now: now, Policy: e.DefaultPolicy(), Purls: []string{"pkg:npm/express@5.3.0"}})
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = decisions
		}(i)
	}
	wg.Wait()
	if calls := lookup.calls.Load(); calls != 1 {
		t.Errorf("five concurrent callers must share one lookup, got %d", calls)
	}
	for _, decisions := range results {
		if len(decisions) != 1 || decisions[0].Decision != DecisionHold || !decisions[0].Evaluated {
			t.Errorf("every caller must get the looked-up hold, got %+v", decisions)
		}
	}
	// Stored now: a later evaluation reads the row, no lookup.
	if _, err := e.Evaluate(context.Background(), Request{OrgID: orgID, Now: now, Policy: e.DefaultPolicy(), Purls: []string{"pkg:npm/express@5.3.0"}}); err != nil {
		t.Fatal(err)
	}
	if calls := lookup.calls.Load(); calls != 1 {
		t.Errorf("a stored signal must not be looked up again, got %d calls", calls)
	}
}

func TestEvaluateLookupFailureIsNotEvaluated(t *testing.T) {
	fs := &fakeStore{signals: map[string]store.PackageSignal{}}
	e := New(fs, Options{Lookup: &fakeLookup{err: errors.New("429 from upstream")}})
	decisions, err := e.Evaluate(context.Background(), Request{OrgID: uuid.New(), Policy: e.DefaultPolicy(), Purls: []string{"pkg:npm/express@5.3.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if d := decisions[0]; d.Decision != DecisionAllow || d.Evaluated || d.Reason == "" {
		t.Errorf("a failed lookup must fail open as not evaluated, got %+v", d)
	}
}

package cvetriage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type fakeSource struct {
	ids      []string
	revision string
	records  map[string][]byte
	failOn   map[string]error
}

func (f *fakeSource) Changed(context.Context) ([]string, string, error) {
	return f.ids, f.revision, nil
}

func (f *fakeSource) Record(_ context.Context, cveID string) ([]byte, error) {
	if err := f.failOn[cveID]; err != nil {
		return nil, err
	}
	data, ok := f.records[cveID]
	if !ok {
		return nil, errors.New("not found")
	}
	return data, nil
}

type fakeStore struct {
	records         map[string]dbgen.CveRecord
	subscriptions   []dbgen.CveSubscription
	queued          map[string]int
	touched         int
	events          []store.AdvisoryEvent
	revision        string
	saveErr         error
	autoApply       []Package
	priorAffected   []cvefeed.AffectedProduct
	seedCommit      string
	applied         []string
	appliedPackages []Package
}

func newFakeStore() *fakeStore {
	return &fakeStore{records: map[string]dbgen.CveRecord{}, queued: map[string]int{}}
}

func (f *fakeStore) SaveCVERecord(_ context.Context, record cvefeed.Projection) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.records[record.ID] = dbgen.CveRecord{
		CveID:           record.ID,
		State:           record.State,
		RecordUpdatedAt: sql.NullTime{Time: record.Updated, Valid: !record.Updated.IsZero()},
	}
	return nil
}

func (f *fakeStore) GetCVERecord(_ context.Context, cveID string) (dbgen.CveRecord, error) {
	record, ok := f.records[cveID]
	if !ok {
		return dbgen.CveRecord{}, sql.ErrNoRows
	}
	return record, nil
}

func (f *fakeStore) GetCVEAffected(_ context.Context, _ string) ([]cvefeed.AffectedProduct, error) {
	return f.priorAffected, nil
}

func (f *fakeStore) MatchSubscriptions(context.Context, []string, []string) ([]dbgen.CveSubscription, error) {
	return f.subscriptions, nil
}

func (f *fakeStore) QueueTriageItem(_ context.Context, _ [16]byte, cveID string) error {
	f.queued[cveID]++
	return nil
}

func (f *fakeStore) TouchSubscriptionMatched(context.Context, [16]byte) error {
	f.touched++
	return nil
}

func (f *fakeStore) RecordAdvisoryEvent(_ context.Context, event store.AdvisoryEvent) error {
	f.events = append(f.events, event)
	return nil
}

func (f *fakeStore) AutoApply(_ context.Context, _ [16]byte) ([]Package, error) {
	return f.autoApply, nil
}

func (f *fakeStore) ApplyMapping(_ context.Context, record cvefeed.Projection, packages []Package) error {
	f.applied = append(f.applied, record.ID)
	f.appliedPackages = packages
	return nil
}

func (f *fakeStore) FeedRevision(context.Context) (string, error) { return f.revision, nil }

func (f *fakeStore) FeedSeed(context.Context) (FeedSeed, error) {
	return FeedSeed{Commit: f.seedCommit}, nil
}

func (f *fakeStore) SetFeedRevision(_ context.Context, revision string) error {
	f.revision = revision
	return nil
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "cvefeed", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func (f *fakeStore) kinds() []store.AdvisoryEventKind {
	kinds := make([]store.AdvisoryEventKind, 0, len(f.events))
	for _, event := range f.events {
		kinds = append(kinds, event.Kind)
	}
	return kinds
}

func newSweeper(source cvefeed.Source, target *fakeStore) *Sweeper {
	return &Sweeper{Source: source, Store: target, Log: zerolog.Nop()}
}

func TestSweepStoresAndQueuesMatches(t *testing.T) {
	target := newFakeStore()
	target.subscriptions = []dbgen.CveSubscription{{ID: uuid.New(), Label: "Apache Tomcat"}}
	source := &fakeSource{
		ids:      []string{"CVE-2026-59084"},
		revision: "abc123",
		records:  map[string][]byte{"CVE-2026-59084": fixture(t, "CVE-2026-59084.json")},
	}

	result, err := newSweeper(source, target).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Seen != 1 || result.Stored != 1 || result.Queued != 1 {
		t.Fatalf("result = %+v", result)
	}
	if target.revision != "abc123" {
		t.Errorf("revision = %q, want abc123", target.revision)
	}
	if target.touched != 1 {
		t.Errorf("subscription last-matched not stamped (%d)", target.touched)
	}
	// A record we had never seen is a publication, not a revision.
	if kinds := target.kinds(); len(kinds) != 1 || kinds[0] != store.EventPublished {
		t.Errorf("events = %v", kinds)
	}
}

// The transition with consequences: a record moving to REJECTED must be
// recorded as a withdrawal and must not be queued — there is nothing to decide
// about a vulnerability that no longer exists.
func TestSweepRecordsWithdrawalAndDoesNotQueue(t *testing.T) {
	target := newFakeStore()
	target.subscriptions = []dbgen.CveSubscription{{ID: uuid.New()}}
	target.records["CVE-2026-59084"] = dbgen.CveRecord{
		CveID:           "CVE-2026-59084",
		State:           cvefeed.StatePublished,
		RecordUpdatedAt: sql.NullTime{Time: time.Now().Add(-time.Hour), Valid: true},
	}

	withdrawn := fixture(t, "CVE-2026-59084.json")
	source := &fakeSource{
		ids:      []string{"CVE-2026-59084"},
		revision: "def456",
		records:  map[string][]byte{"CVE-2026-59084": withdrawnRecord(t, withdrawn)},
	}

	result, err := newSweeper(source, target).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Withdrawn != 1 {
		t.Errorf("withdrawn = %d, want 1", result.Withdrawn)
	}
	if result.Queued != 0 {
		t.Errorf("a withdrawn record was queued for triage")
	}
	if kinds := target.kinds(); len(kinds) != 1 || kinds[0] != store.EventWithdrawn {
		t.Errorf("events = %v, want [withdrawn]", kinds)
	}
}

// Revisions are the common case — roughly three quarters of a batch — so they
// must be recognised as such rather than reported as new publications.
func TestSweepRecordsRevision(t *testing.T) {
	target := newFakeStore()
	target.records["CVE-2026-59084"] = dbgen.CveRecord{
		CveID:           "CVE-2026-59084",
		State:           cvefeed.StatePublished,
		RecordUpdatedAt: sql.NullTime{Time: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
	}
	source := &fakeSource{
		ids:      []string{"CVE-2026-59084"},
		revision: "rev2",
		records:  map[string][]byte{"CVE-2026-59084": fixture(t, "CVE-2026-59084.json")},
	}

	result, err := newSweeper(source, target).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Revised != 1 {
		t.Errorf("revised = %d, want 1", result.Revised)
	}
	if kinds := target.kinds(); len(kinds) != 1 || kinds[0] != store.EventCNARevised {
		t.Errorf("events = %v, want [cna_revised]", kinds)
	}
}

// One unreadable record must not stall the batch: the rest are unrelated.
func TestSweepSurvivesOneBadRecord(t *testing.T) {
	target := newFakeStore()
	source := &fakeSource{
		ids:      []string{"CVE-2026-00001", "CVE-2026-59084"},
		revision: "rev3",
		records:  map[string][]byte{"CVE-2026-59084": fixture(t, "CVE-2026-59084.json")},
		failOn:   map[string]error{"CVE-2026-00001": errors.New("boom")},
	}

	result, err := newSweeper(source, target).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep returned an error for one bad record: %v", err)
	}
	if result.Failed != 1 || result.Stored != 1 {
		t.Fatalf("result = %+v, want the good record stored and the bad one counted", result)
	}
}

// The revision must not advance past work that failed to persist, or the next
// pass skips those records and the advisory is lost for good.
func TestSweepHoldsRevisionWhenRecordsFail(t *testing.T) {
	target := newFakeStore()
	target.revision = "old"
	target.saveErr = errors.New("database down")
	source := &fakeSource{
		ids:      []string{"CVE-2026-59084"},
		revision: "new",
		records:  map[string][]byte{"CVE-2026-59084": fixture(t, "CVE-2026-59084.json")},
	}

	result, err := newSweeper(source, target).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Failed != 1 {
		t.Fatalf("result = %+v, want the failure counted", result)
	}
	if target.revision != "old" {
		t.Fatalf("revision advanced to %q past a record that never stored", target.revision)
	}
}

func withdrawnRecord(t *testing.T, data []byte) []byte {
	t.Helper()
	withdrawn := strings.Replace(string(data), `"state":"PUBLISHED"`, `"state":"REJECTED"`, 1)
	if withdrawn == string(data) {
		t.Fatal("fixture did not contain a PUBLISHED state to flip")
	}
	return []byte(withdrawn)
}

// A product opted into auto-apply skips the queue: the identity question was
// answered once for that product, and asking it again per CVE is the cost this
// whole feature exists to avoid paying twice.
func TestSweepAutoAppliesOptedInProducts(t *testing.T) {
	target := newFakeStore()
	target.subscriptions = []dbgen.CveSubscription{{ID: uuid.New(), Label: "Apache Tomcat"}}
	target.autoApply = []Package{{Ecosystem: "Maven", Name: "org.apache.tomcat:tomcat-catalina"}}
	source := &fakeSource{
		ids:      []string{"CVE-2026-59084"},
		revision: "auto1",
		records:  map[string][]byte{"CVE-2026-59084": fixture(t, "CVE-2026-59084.json")},
	}

	result, err := newSweeper(source, target).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Applied != 1 {
		t.Errorf("applied = %d, want 1", result.Applied)
	}
	if result.Queued != 0 {
		t.Errorf("an opted-in product was still queued for a person")
	}
	if len(target.applied) != 1 || target.applied[0] != "CVE-2026-59084" {
		t.Errorf("applied = %v", target.applied)
	}
	// Authoring is a timeline event even when nobody was present for it.
	if kinds := target.kinds(); len(kinds) == 0 || kinds[len(kinds)-1] != store.EventAuthored {
		t.Errorf("events = %v, want a coordinates_authored entry", target.kinds())
	}
}

// Off by default is the whole safety property: a mapping curated for one CVE
// need not hold for the next, since a later flaw can live in a different
// artifact of the same product.
func TestSweepQueuesWhenAutoApplyIsOff(t *testing.T) {
	target := newFakeStore()
	target.subscriptions = []dbgen.CveSubscription{{ID: uuid.New()}}
	source := &fakeSource{
		ids:      []string{"CVE-2026-59084"},
		revision: "auto2",
		records:  map[string][]byte{"CVE-2026-59084": fixture(t, "CVE-2026-59084.json")},
	}

	result, err := newSweeper(source, target).Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if result.Applied != 0 || result.Queued != 1 {
		t.Fatalf("result = %+v, want it queued for a person", result)
	}
}

// A revision must record WHAT moved. Without it a corrected typo and a bound
// that now covers versions somebody runs are indistinguishable on the timeline,
// and only one of them is urgent.
func TestSweepRecordsWhatChangedOnRevision(t *testing.T) {
	target := newFakeStore()
	target.records["CVE-2026-59084"] = dbgen.CveRecord{
		CveID:           "CVE-2026-59084",
		State:           cvefeed.StatePublished,
		RecordUpdatedAt: sql.NullTime{Time: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
	}
	// What we stored last time: the 9.0 branch bounded earlier than it now is.
	target.priorAffected = []cvefeed.AffectedProduct{{
		Product: "Apache Tomcat", ProductKey: "apachetomcat",
		Ranges: []cvefeed.VersionRange{{Introduced: "9.0.13", LastAffected: "9.0.100"}},
	}}
	source := &fakeSource{
		ids:      []string{"CVE-2026-59084"},
		revision: "rev-diff",
		records:  map[string][]byte{"CVE-2026-59084": fixture(t, "CVE-2026-59084.json")},
	}

	if _, err := newSweeper(source, target).Sweep(context.Background()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	var revision *store.AdvisoryEvent
	for i := range target.events {
		if target.events[i].Kind == store.EventCNARevised {
			revision = &target.events[i]
		}
	}
	if revision == nil {
		t.Fatal("no revision event recorded")
	}
	detail := string(revision.Detail)
	if detail == "" || detail == "{}" {
		t.Fatal("a revision was recorded without saying what changed")
	}
	// The widened branch must be named, and flagged as widening.
	if !strings.Contains(detail, "9.0.100") || !strings.Contains(detail, "9.0.119") {
		t.Errorf("detail does not show the bound that moved: %s", detail)
	}
	if !strings.Contains(detail, `"widened":true`) {
		t.Errorf("a later upper bound was not flagged as widening: %s", detail)
	}
}

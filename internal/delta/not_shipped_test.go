package delta

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/shipped"
	"github.com/hibouhq/hibou/internal/store"
)

func TestPartitionNotShipped(t *testing.T) {
	headID := uuid.New()
	shippedID, devID, malwareID, kevID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	name := func(s string) *string { return &s }
	vulns := []store.Vulnerability{
		{Fingerprint: "a", Type: "dependency", Severity: "high", ComponentID: &shippedID, ComponentName: name("lodash")},
		{Fingerprint: "b", Type: "dependency", Severity: "critical", ComponentID: &devID, ComponentName: name("jest"), HasRemediation: true},
		{Fingerprint: "c", Type: "malware", Severity: "critical", ComponentID: &malwareID, ComponentName: name("evil-dev-tool")},
		{Fingerprint: "d", Type: "dependency", Severity: "low", ComponentID: &kevID, ComponentName: name("old-test-lib"), PrimaryIdentifierValue: "CVE-2024-0001"},
	}
	svc := &Service{store: &notShippedKEVStore{listed: map[string]bool{"CVE-2024-0001": true}}, log: zerolog.Nop()}
	svc.SetShippingLookup(func(_ context.Context, _, _, snapshotID uuid.UUID) (map[uuid.UUID]shipped.Decision, error) {
		if snapshotID != headID {
			t.Fatalf("unexpected snapshot %s", snapshotID)
		}
		return map[uuid.UUID]shipped.Decision{
			shippedID: {Shipped: true},
			devID:     {Shipped: false, Reason: "repository: pkg:npm/jest"},
			malwareID: {Shipped: false, Reason: "declared scope: dev"},
			kevID:     {Shipped: false, Reason: "declared scope: test"},
		}, nil
	})

	// Defaults: malware and KEV on not-shipped components still block; the
	// critical jest finding is informational.
	counted, informational, err := svc.partitionNotShipped(context.Background(), uuid.New(), uuid.New(), &GateConfig{HeadSnapshotID: headID}, vulns)
	if err != nil {
		t.Fatal(err)
	}
	if len(counted) != 3 || len(informational) != 1 || informational[0].Fingerprint != "b" {
		t.Fatalf("defaults: counted=%d informational=%v", len(counted), fingerprints(informational))
	}
	note := notShippedNote(informational)
	if !strings.Contains(note, "jest") || !strings.Contains(note, "not counted") {
		t.Errorf("note: %s", note)
	}

	// min_severity critical with fixable_only: jest blocks too.
	cfg := &GateConfig{HeadSnapshotID: headID, NotShipped: &NotShippedGate{KEV: true, MinSeverity: "critical", FixableOnly: true}}
	counted, informational, err = svc.partitionNotShipped(context.Background(), uuid.New(), uuid.New(), cfg, vulns)
	if err != nil {
		t.Fatal(err)
	}
	if len(counted) != 4 || len(informational) != 0 {
		t.Fatalf("severity rule: counted=%d informational=%v", len(counted), fingerprints(informational))
	}

	// KEV off: the exploited low finding on a test library is informational.
	cfg = &GateConfig{HeadSnapshotID: headID, NotShipped: &NotShippedGate{KEV: false}}
	counted, informational, err = svc.partitionNotShipped(context.Background(), uuid.New(), uuid.New(), cfg, vulns)
	if err != nil {
		t.Fatal(err)
	}
	if len(counted) != 2 || len(informational) != 2 {
		t.Fatalf("kev off: counted=%d informational=%v", len(counted), fingerprints(informational))
	}
}

func fingerprints(vulns []store.Vulnerability) []string {
	out := make([]string, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, v.Fingerprint)
	}
	return out
}

type notShippedKEVStore struct {
	DeltaStore
	listed map[string]bool
}

func (s *notShippedKEVStore) FilterKEVAdvisoryIDs(_ context.Context, _ []uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

func (s *notShippedKEVStore) FilterKEVIdentifiers(_ context.Context, identifiers []string) ([]string, error) {
	var out []string
	for _, id := range identifiers {
		if s.listed[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

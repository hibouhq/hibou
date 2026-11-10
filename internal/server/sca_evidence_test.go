package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func scaEvidenceFixture(t *testing.T) (*Server, *store.Repository, *store.Snapshot, store.InventoryDocument) {
	t.Helper()
	s, org, _, _, inv := newSCAFixture(t)
	ctx := context.Background()
	repo, err := s.queries.CreateRepository(ctx, org.ID, nil, inv.Name, "app", org.Provider, inv.ProviderKey, "main", "enrolled")
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	ref, err := s.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{LatestCommitSHA: &commit})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.queries.CreateSnapshot(ctx, ref.ID, commit, store.SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	component, err := s.queries.UpsertComponent(ctx, "pkg:npm/lodash@4.17.20", "lodash", "4.17.20", "npm", nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, repo, snapshot, store.InventoryDocument{Rows: []store.InventoryRow{
		{ComponentID: component.ID, Labels: json.RawMessage(`{"relationship:direct":true}`)},
	}}
}

func TestSCAReportedResultsAndCurrentCommitAreSeparate(t *testing.T) {
	s, repo, snapshot, doc := scaEvidenceFixture(t)
	ctx := context.Background()
	if _, err := s.queries.IngestInventorySource(ctx, snapshot.ID, "legacy:inventory", nil, nil, doc); err != nil {
		t.Fatal(err)
	}
	coverage, err := s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.State != "inventory_ready" || !coverage.HasInventory || coverage.InventorySource != "unknown" {
		t.Fatalf("legacy inventory was classified as missing or guessed: %+v err=%v", coverage, err)
	}
	if _, err := s.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		SnapshotID: snapshot.ID, Type: "dependency", Fingerprint: uuid.NewString(),
		Title: "Reported dependency finding", PrimaryIdentifierKind: "cve",
		PrimaryIdentifierValue: "CVE-2021-23337", OriginalSeverity: dbgen.SeverityLevelHigh,
		Severity: dbgen.SeverityLevelHigh, Status: "detected", ScannerName: "imported-scanner",
		ComponentID: uuid.NullUUID{UUID: doc.Rows[0].ComponentID, Valid: true},
		Metadata:    json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	coverage, err = s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.State != "reported" || !coverage.HasInventory {
		t.Fatalf("existing dependency findings were labeled unassessed: %+v err=%v", coverage, err)
	}
	newHead := strings.Repeat("b", 40)
	if _, err := s.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{LatestCommitSHA: &newHead}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.queries.CreatePlaceholderSnapshot(ctx, snapshot.RefID, newHead); err != nil {
		t.Fatal(err)
	}
	coverage, err = s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.State != "outdated" || coverage.HasInventory || !coverage.PreviousResults ||
		coverage.InventoryCommitSHA != snapshot.CommitSHA || coverage.HeadCommitSHA != newHead {
		t.Fatalf("prior results and current coverage were conflated: %+v err=%v", coverage, err)
	}
}

func TestSCAIntegrationRequiresUploadsNotServerInventory(t *testing.T) {
	s, repo, snapshot, doc := scaEvidenceFixture(t)
	ctx := context.Background()
	if _, err := s.queries.IngestInventorySource(ctx, snapshot.ID, "sbom:hibou-depinventory.cdx.json", nil, nil, doc); err != nil {
		t.Fatal(err)
	}
	coverage, err := s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.Integration != "monitored" {
		t.Fatalf("server inventory implied CI integration: %+v err=%v", coverage, err)
	}
	publisher := forge.NewGatePublisher(nil, nil, nil, forge.NewGatePublisherStoreAdapter(s.queries), nil, nil, "", s.log)
	if enabled, err := publisher.RepositoryReportingEnabled(ctx, repo.ID); enabled || err != nil {
		t.Fatalf("SCA enrollment enabled PR reporting: %v %v", enabled, err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE snapshots SET received_uploads=1 WHERE id=$1`, snapshot.ID); err != nil {
		t.Fatal(err)
	}
	coverage, err = s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.Integration != "ci_integrated" || coverage.InventorySource != "repository" {
		t.Fatalf("CI integration and inventory provenance conflated: %+v err=%v", coverage, err)
	}
	if enabled, err := publisher.RepositoryReportingEnabled(ctx, repo.ID); !enabled || err != nil {
		t.Fatalf("existing upload integration lost PR reporting: %v %v", enabled, err)
	}
}

func TestSCAInventorySourceDoesNotInferCompletenessFromUploadOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, tool, origin, want string
	}{
		{"external CI SBOM", "syft", store.ArtifactOriginCI, "sbom"},
		{"external manual SBOM", "syft", store.ArtifactOriginManual, "sbom"},
		{"CLI in CI", "hibou-deps", store.ArtifactOriginCI, "cli"},
		{"CLI deliverable", "hibou-deps", store.ArtifactOriginManual, "cli"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, repo, snapshot, doc := scaEvidenceFixture(t)
			ctx := context.Background()
			artifact, err := s.queries.CreateSnapshotArtifact(ctx, store.CreateSnapshotArtifactParams{
				SnapshotID: snapshot.ID, Kind: "sbom", ToolName: &tc.tool,
				Filename: "inventory.cdx.json", ObjectKey: "sca-evidence/" + uuid.NewString(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.queries.SetSnapshotArtifactSource(ctx, artifact.ID, tc.origin, nil, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := s.queries.IngestInventorySource(ctx, snapshot.ID, "sbom:inventory.cdx.json", &artifact.ID, nil, doc); err != nil {
				t.Fatal(err)
			}
			coverage, err := s.dependencyCoverageForRepo(ctx, repo, "main")
			if err != nil || coverage.InventorySource != tc.want || coverage.State != "inventory_ready" {
				t.Fatalf("origin was treated as build completeness: %+v err=%v", coverage, err)
			}
		})
	}
}

func TestSCAMixedSourcesRetainProvenanceAndExcludeRevokedEvidence(t *testing.T) {
	s, repo, snapshot, doc := scaEvidenceFixture(t)
	ctx := context.Background()
	if _, err := s.queries.IngestInventorySource(ctx, snapshot.ID, "sbom:hibou-depinventory.cdx.json", nil, nil, doc); err != nil {
		t.Fatal(err)
	}
	coverage, err := s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.InventorySource != "repository" {
		t.Fatalf("repository extraction source lost: %+v err=%v", coverage, err)
	}
	artifact, err := s.queries.CreateSnapshotArtifact(ctx, store.CreateSnapshotArtifactParams{
		SnapshotID: snapshot.ID, Kind: "sbom", Filename: "uploaded.cdx.json", ObjectKey: "sca-evidence/" + uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.queries.IngestInventorySource(ctx, snapshot.ID, "sbom:uploaded.cdx.json", &artifact.ID, nil, doc); err != nil {
		t.Fatal(err)
	}
	coverage, err = s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.InventorySource != "mixed" || strings.Join(coverage.InventorySources, ",") != "repository,sbom" {
		t.Fatalf("mixed sources collapsed: %+v err=%v", coverage, err)
	}
	if _, err := s.queries.RevokeSnapshotArtifact(ctx, artifact.ID, nil, "wrong release"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.queries.RecomputeSnapshotInventory(ctx, snapshot.ID); err != nil {
		t.Fatal(err)
	}
	coverage, err = s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.InventorySource != "repository" {
		t.Fatalf("revoked source still advertised: %+v err=%v", coverage, err)
	}
}

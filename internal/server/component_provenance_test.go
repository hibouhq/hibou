package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/sbom"
	"github.com/hibouhq/hibou/internal/store"
)

func TestInventorySourceEvidenceReadsLinkedRunsAndExcludesRevokedArtifacts(t *testing.T) {
	s, repo, snapshot, _ := scaEvidenceFixture(t)
	ctx := context.Background()
	run, err := s.queries.InsertDepExtractionRun(ctx, store.InsertDepExtractionRunParams{
		RepoID: repo.ID, SnapshotID: snapshot.ID, CommitSHA: snapshot.CommitSHA,
		InputDigest: strings.Repeat("a", 64), ExtractorVersion: "osv-scalibr-v0.5.3+hibou-1",
		SHA256: strings.Repeat("b", 64), SizeBytes: 100, ComponentCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.queries.AttachInventorySource(ctx, snapshot.ID, "sbom:generated.cdx.json", nil, nil, &run.ID); err != nil {
		t.Fatal(err)
	}
	tool := "syft"
	for _, filename := range []string{"hibou-depinventory.cdx.json", "revoked.cdx.json"} {
		artifact, err := s.queries.CreateSnapshotArtifact(ctx, store.CreateSnapshotArtifactParams{
			SnapshotID: snapshot.ID, Kind: "sbom", ToolName: &tool, Filename: filename, ObjectKey: "fixture/" + uuid.NewString(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.queries.AttachInventorySource(ctx, snapshot.ID, "sbom:"+filename, nil, &artifact.ID, nil); err != nil {
			t.Fatal(err)
		}
		if filename == "revoked.cdx.json" {
			if _, err := s.queries.RevokeSnapshotArtifact(ctx, artifact.ID, nil, "synthetic revocation"); err != nil {
				t.Fatal(err)
			}
		}
	}
	sources, err := s.queries.ListInventorySourceEvidence(ctx, snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || !sources[0].Extracted || sources[0].ExtractorVersion != run.ExtractorVersion ||
		sources[1].Extracted || sources[1].ToolName != "syft" {
		t.Fatalf("source evidence was guessed or revoked: %+v", sources)
	}
}

func TestComponentLabelsWithProperties(t *testing.T) {
	base := json.RawMessage(`{"sbom:hibou-depinventory.cdx.json":true}`)
	component := sbom.ParsedComponent{Properties: map[string][]string{
		"hibou:relationship": {"direct"},
		"hibou:scope":        {"dev", "optional"},
		"hibou:module":       {"web"},
		"hibou:registry":     {"public"},
		"hibou:extractor":    {"javascript/packagelockjson"}, // not a label
		"vendor:other":       {"x"},
	}}
	merged := componentLabelsWithProperties(base, component)
	labels := map[string]any{}
	if err := json.Unmarshal(merged, &labels); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sbom:hibou-depinventory.cdx.json", "relationship:direct", "scope:dev", "scope:optional", "module:web", "registry:public"} {
		if _, ok := labels[want]; !ok {
			t.Errorf("label %s missing from %s", want, merged)
		}
	}
	for key := range labels {
		if strings.HasPrefix(key, "extractor") || strings.HasPrefix(key, "vendor") {
			t.Errorf("unexpected label %s", key)
		}
	}
	if got := componentLabelsWithProperties(base, sbom.ParsedComponent{}); string(got) != string(base) {
		t.Errorf("a component without properties must keep the base labels, got %s", got)
	}
}

func TestComponentInventoryProducersUseRecordedEvidenceNotFilenames(t *testing.T) {
	components := []componentWithVulnsResponse{
		{componentProvenance: componentProvenance{InventorySources: []string{"generated.cdx.json", "uploaded.cdx.json"}}},
		{componentProvenance: componentProvenance{InventorySources: []string{"hibou-depinventory.cdx.json"}}},
	}
	attachComponentInventoryProducers(components, []store.InventorySourceEvidence{
		{Label: "sbom:generated.cdx.json", Extracted: true, ExtractorVersion: "osv-scalibr-v0.5.3+hibou-1"},
		{Label: "sbom:uploaded.cdx.json", ToolName: "syft"},
		{Label: "sbom:hibou-depinventory.cdx.json"},
		{Label: "sbom:unrelated.cdx.json", ToolName: "other-tool"},
	})
	got := components[0].InventoryProducers
	if len(got) != 2 || got[0].Name != "Hibou dependency extraction" || got[0].Engine != "OSV-SCALIBR + Hibou rules" ||
		got[0].Version != "osv-scalibr-v0.5.3+hibou-1" || got[1].Name != "syft" || got[1].Engine != "" {
		t.Fatalf("unexpected producer evidence: %+v", got)
	}
	if len(components[1].InventoryProducers) != 0 {
		t.Fatalf("filename alone invented an extractor: %+v", components[1].InventoryProducers)
	}
}

func TestProvenanceFromLabels(t *testing.T) {
	raw := json.RawMessage(`{"sbom:app.cdx.json":true,"sbom:hibou-depinventory.cdx.json":true,"relationship:indirect":true,"relationship:direct":true,"scope:dev":true,"module:web":true,"module:api":true,"resolution:declared":true,"resolution:recorded":true,"registry:public":true,"registry:private":true}`)
	got := provenanceFromLabels(raw)
	if got.Relationship != "direct" {
		t.Errorf("direct must win over indirect, got %q", got.Relationship)
	}
	if got.Resolution != "recorded" {
		t.Errorf("recorded must win over declared, got %q", got.Resolution)
	}
	if got.Registry != "private" {
		t.Errorf("private must win over public, got %q", got.Registry)
	}
	if strings.Join(got.Modules, ",") != "api,web" || strings.Join(got.Scopes, ",") != "dev" {
		t.Errorf("modules %v scopes %v", got.Modules, got.Scopes)
	}
	if strings.Join(got.InventorySources, ",") != "app.cdx.json,hibou-depinventory.cdx.json" {
		t.Errorf("inventory sources %v", got.InventorySources)
	}
	if empty := provenanceFromLabels(nil); empty.Relationship != "" || empty.Registry != "" || len(empty.InventorySources) != 0 {
		t.Errorf("no labels must mean no provenance, got %+v", empty)
	}
}

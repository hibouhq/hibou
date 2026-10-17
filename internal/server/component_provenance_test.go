package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/sbom"
)

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

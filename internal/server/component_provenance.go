package server

import (
	"encoding/json"
	"strings"

	"github.com/hibouhq/hibou/internal/provenance"
	"github.com/hibouhq/hibou/internal/sbom"
	"github.com/hibouhq/hibou/internal/store"
)

// Component provenance (ADR-045 §5) lives in internal/provenance so the
// gate can read it too; this file keeps the ingestion-side helper and the
// names the handlers use.

type componentProvenance = provenance.Provenance

type componentInventoryProducer struct {
	Source  string `json:"source"`
	Name    string `json:"name"`
	Engine  string `json:"engine,omitempty"`
	Version string `json:"version,omitempty"`
}

func attachComponentInventoryProducers(components []componentWithVulnsResponse, sources []store.InventorySourceEvidence) {
	bySource := make(map[string]componentInventoryProducer, len(sources))
	for _, source := range sources {
		producer := componentInventoryProducer{Source: strings.TrimPrefix(source.Label, "sbom:"), Name: source.ToolName}
		if source.Extracted {
			producer.Name = "Hibou dependency extraction"
			producer.Version = source.ExtractorVersion
			if strings.HasPrefix(source.ExtractorVersion, "osv-scalibr-") {
				producer.Engine = "OSV-SCALIBR + Hibou rules"
			}
		}
		if producer.Name != "" {
			bySource[producer.Source] = producer
		}
	}
	for i := range components {
		for _, source := range components[i].InventorySources {
			if producer, ok := bySource[source]; ok {
				components[i].InventoryProducers = append(components[i].InventoryProducers, producer)
			}
		}
	}
}

func provenanceFromLabels(raw json.RawMessage) componentProvenance {
	return provenance.FromLabels(raw)
}

// componentLabelsWithProperties merges an artifact's provenance labels with
// the labels a component's properties imply. Returns base unchanged when
// the component carries nothing hibou understands.
func componentLabelsWithProperties(base json.RawMessage, component sbom.ParsedComponent) json.RawMessage {
	if len(component.Properties) == 0 {
		return base
	}
	labels := map[string]any{}
	if len(base) > 0 {
		_ = json.Unmarshal(base, &labels)
	}
	added := false
	for property, values := range component.Properties {
		prefix, ok := provenance.PropertyLabelPrefixes[property]
		if !ok {
			continue
		}
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				labels[prefix+value] = true
				added = true
			}
		}
	}
	if !added {
		return base
	}
	encoded, err := json.Marshal(labels)
	if err != nil {
		return base
	}
	return encoded
}

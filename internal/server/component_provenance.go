package server

import (
	"encoding/json"
	"strings"

	"github.com/hibouhq/hibou/internal/provenance"
	"github.com/hibouhq/hibou/internal/sbom"
)

// Component provenance (ADR-045 §5) lives in internal/provenance so the
// gate can read it too; this file keeps the ingestion-side helper and the
// names the handlers use.

type componentProvenance = provenance.Provenance

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

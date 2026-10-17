// Package provenance reads what the inventory sources said about one
// component in one snapshot (ADR-045 §5). The built-in extractor writes
// what it knows as CycloneDX properties; ingestion folds them into the
// snapshot_components label set as flat keys ("relationship:direct",
// "scope:dev", "module:web", "registry:private"), next to the artifact
// labels ("sbom:<filename>") the upload path records. The flat shape is
// what the jsonb merge on attach preserves across several artifacts in one
// snapshot, so a version two modules declare keeps both modules and both
// relationships.
package provenance

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/hibouhq/hibou/internal/depinventory"
)

// PropertyLabelPrefixes maps a document property to its label prefix.
var PropertyLabelPrefixes = map[string]string{
	depinventory.PropertyRelationship: "relationship:",
	depinventory.PropertyScope:        "scope:",
	depinventory.PropertyModule:       "module:",
	depinventory.PropertyResolution:   "resolution:",
	depinventory.PropertyRegistry:     "registry:",
	depinventory.PropertyPath:         "path:",
	depinventory.PropertyConstraint:   "constraint:",
}

// Provenance is what the label set says about one component, in the
// vocabulary the API exposes.
type Provenance struct {
	// Relationship is direct, indirect or unknown when any inventory source
	// recorded it; empty when no source did (an uploaded SBOM without a
	// graph). "direct" wins over "indirect" across sources (ADR-045 §5.1).
	Relationship string   `json:"relationship,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Modules      []string `json:"modules,omitempty"`
	// Resolution is "recorded" when any source is a lockfile, "declared"
	// when a manifest reported an exact version, "unresolved" when only a
	// range is known (ADR-045 §2.2), else empty.
	Resolution string `json:"resolution,omitempty"`
	// Constraint is the declared range of an unresolved component.
	Constraint string `json:"constraint,omitempty"`
	// Registry is "private" when any lockfile resolved the package from
	// somewhere other than the public registry, "public" when one did and
	// none said private, else empty.
	Registry string `json:"registry,omitempty"`
	// InventorySources lists the artifacts that reported the component:
	// uploaded SBOM file names and the extractor's document.
	InventorySources []string `json:"inventory_sources,omitempty"`
	// Shipped says whether the component reaches clients (ADR-045 §6):
	// true unless an uploaded SBOM leaves it out or a not-shipped list
	// matches. ShippedReason says which; ShippedIgnored names a list
	// pattern overruled by SBOM evidence.
	Shipped        bool   `json:"shipped"`
	ShippedReason  string `json:"shipped_reason,omitempty"`
	ShippedIgnored string `json:"shipped_ignored,omitempty"`
	// Paths are the manifest paths that declare the component, for the
	// not-shipped path patterns.
	Paths []string `json:"-"`
}

// FromLabels parses a snapshot component's label set.
func FromLabels(raw json.RawMessage) Provenance {
	out := Provenance{Shipped: true}
	if len(raw) == 0 {
		return out
	}
	labels := map[string]any{}
	if err := json.Unmarshal(raw, &labels); err != nil {
		return out
	}
	direct, indirect, unknown := false, false, false
	recorded, declared, unresolved := false, false, false
	public, private := false, false
	for key := range labels {
		switch {
		case strings.HasPrefix(key, "relationship:"):
			switch strings.TrimPrefix(key, "relationship:") {
			case string(depinventory.RelationshipDirect):
				direct = true
			case string(depinventory.RelationshipIndirect):
				indirect = true
			case string(depinventory.RelationshipUnknown):
				unknown = true
			}
		case strings.HasPrefix(key, "scope:"):
			out.Scopes = append(out.Scopes, strings.TrimPrefix(key, "scope:"))
		case strings.HasPrefix(key, "module:"):
			out.Modules = append(out.Modules, strings.TrimPrefix(key, "module:"))
		case strings.HasPrefix(key, "path:"):
			out.Paths = append(out.Paths, strings.TrimPrefix(key, "path:"))
		case strings.HasPrefix(key, "constraint:"):
			if out.Constraint == "" {
				out.Constraint = strings.TrimPrefix(key, "constraint:")
			}
		case strings.HasPrefix(key, "resolution:"):
			switch strings.TrimPrefix(key, "resolution:") {
			case string(depinventory.ResolutionRecorded):
				recorded = true
			case string(depinventory.ResolutionDeclared):
				declared = true
			case string(depinventory.ResolutionUnresolved):
				unresolved = true
			}
		case strings.HasPrefix(key, "registry:"):
			switch strings.TrimPrefix(key, "registry:") {
			case depinventory.RegistryPublic:
				public = true
			case depinventory.RegistryPrivate:
				private = true
			}
		case strings.HasPrefix(key, "sbom:"):
			out.InventorySources = append(out.InventorySources, strings.TrimPrefix(key, "sbom:"))
		}
	}
	switch {
	case direct:
		out.Relationship = string(depinventory.RelationshipDirect)
	case indirect:
		out.Relationship = string(depinventory.RelationshipIndirect)
	case unknown:
		out.Relationship = string(depinventory.RelationshipUnknown)
	}
	switch {
	case recorded:
		out.Resolution = string(depinventory.ResolutionRecorded)
	case declared:
		out.Resolution = string(depinventory.ResolutionDeclared)
	case unresolved:
		out.Resolution = string(depinventory.ResolutionUnresolved)
	}
	switch {
	case private:
		out.Registry = depinventory.RegistryPrivate
	case public:
		out.Registry = depinventory.RegistryPublic
	}
	sort.Strings(out.Scopes)
	sort.Strings(out.Modules)
	sort.Strings(out.InventorySources)
	sort.Strings(out.Paths)
	return out
}

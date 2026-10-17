package depinventory

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"
)

// CycloneDX output feeds the SBOM ingestion that already exists, so the
// built-in extractor is one more producer rather than a second pipeline
// (ADR-045 §3). The graph has one root per module with its direct
// dependencies; relationship, scope, path and resolution travel as
// properties so nothing is lost on the way in.

const (
	PropertyRelationship = "hibou:relationship"
	PropertyResolution   = "hibou:resolution"
	PropertyScope        = "hibou:scope"
	PropertyPath         = "hibou:path"
	PropertyModule       = "hibou:module"
	PropertyExtractor    = "hibou:extractor"
	PropertyRegistry     = "hibou:registry"
	// PropertyConstraint carries the declared range of an unresolved
	// component (ADR-045 §2.2).
	PropertyConstraint = "hibou:constraint"
	// PropertyLayer is the index of the image layer that introduced the
	// component and PropertyBaseImage says whether that layer belongs to
	// the base image (ADR-045 §10).
	PropertyLayer       = "hibou:layer"
	PropertyLayerDigest = "hibou:layer_digest"
	PropertyBaseImage   = "hibou:base_image"
	// ToolName is what the producer run and the component sources show.
	ToolName = "hibou-depinventory"
)

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BomRef     string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	Purl       string        `json:"purl,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cdxDocument struct {
	BomFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Timestamp string `json:"timestamp"`
		Tools     []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tools"`
		Component cdxComponent `json:"component"`
	} `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
}

// ToCycloneDX renders the inventory as a CycloneDX 1.5 JSON document.
// rootName labels the metadata component (the repository); toolVersion is
// the hibou version that extracted.
func ToCycloneDX(inv *Inventory, rootName, toolVersion string, now time.Time) ([]byte, error) {
	doc := cdxDocument{BomFormat: "CycloneDX", SpecVersion: "1.5", Version: 1}
	doc.Metadata.Timestamp = now.UTC().Format(time.RFC3339)
	doc.Metadata.Tools = []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}{{Name: ToolName, Version: toolVersion}}
	doc.Metadata.Component = cdxComponent{Type: "application", BomRef: "root", Name: rootName}
	doc.Components = make([]cdxComponent, 0, len(inv.Components))
	doc.Dependencies = make([]cdxDependency, 0, len(inv.Modules)+1)

	// One bom-ref per purl: the same version declared by two modules is one
	// component with two module roots depending on it.
	seen := make(map[string]struct{}, len(inv.Components))
	directByModule := make(map[string][]string)
	moduleRefs := make([]string, 0, len(inv.Modules))
	for _, module := range inv.Modules {
		ref := moduleRef(module.Path)
		moduleRefs = append(moduleRefs, ref)
		doc.Components = append(doc.Components, cdxComponent{
			Type:   "application",
			BomRef: ref,
			Name:   module.Path,
			Properties: []cdxProperty{
				{Name: PropertyModule, Value: module.Path},
			},
		})
	}
	for _, component := range inv.Components {
		if _, dup := seen[component.Purl]; !dup {
			seen[component.Purl] = struct{}{}
			props := []cdxProperty{
				{Name: PropertyRelationship, Value: string(component.Relationship)},
				{Name: PropertyResolution, Value: string(component.Resolution)},
				{Name: PropertyModule, Value: component.Module},
				{Name: PropertyExtractor, Value: component.Extractor},
			}
			if component.Path != "" {
				props = append(props, cdxProperty{Name: PropertyPath, Value: component.Path})
			}
			if component.Constraint != "" {
				props = append(props, cdxProperty{Name: PropertyConstraint, Value: component.Constraint})
			}
			if component.Registry != "" {
				props = append(props, cdxProperty{Name: PropertyRegistry, Value: component.Registry})
			}
			if component.Layer != nil {
				props = append(props, cdxProperty{Name: PropertyLayer, Value: strconv.Itoa(component.Layer.Index)})
				if component.Layer.DiffID != "" {
					props = append(props, cdxProperty{Name: PropertyLayerDigest, Value: component.Layer.DiffID})
				}
				props = append(props, cdxProperty{Name: PropertyBaseImage, Value: strconv.FormatBool(component.Layer.BaseImage)})
			}
			for _, scope := range component.Scopes {
				props = append(props, cdxProperty{Name: PropertyScope, Value: scope})
			}
			doc.Components = append(doc.Components, cdxComponent{
				Type:       "library",
				BomRef:     component.Purl,
				Name:       component.Name,
				Version:    component.Version,
				Purl:       component.Purl,
				Properties: props,
			})
		}
		if component.Relationship == RelationshipDirect || component.Relationship == RelationshipUnknown {
			// Unknown relationships hang off the module too, so nothing is
			// orphaned in the graph; the property says it is not a known root.
			directByModule[component.Module] = append(directByModule[component.Module], component.Purl)
		}
	}
	doc.Dependencies = append(doc.Dependencies, cdxDependency{Ref: "root", DependsOn: moduleRefs})
	for _, module := range inv.Modules {
		deps := uniqueSorted(directByModule[module.Path])
		doc.Dependencies = append(doc.Dependencies, cdxDependency{Ref: moduleRef(module.Path), DependsOn: deps})
	}
	// Parent edges from the lockfiles: the path from a module to an
	// indirect dependency, which "where is it used" walks.
	children := map[string][]string{}
	for _, edge := range inv.Edges {
		if _, known := seen[edge.From]; !known {
			continue
		}
		if _, known := seen[edge.To]; !known {
			continue
		}
		children[edge.From] = append(children[edge.From], edge.To)
	}
	parents := make([]string, 0, len(children))
	for from := range children {
		parents = append(parents, from)
	}
	sort.Strings(parents)
	for _, from := range parents {
		doc.Dependencies = append(doc.Dependencies, cdxDependency{Ref: from, DependsOn: uniqueSorted(children[from])})
	}
	return json.MarshalIndent(doc, "", "  ")
}

func moduleRef(modulePath string) string {
	return "module:" + modulePath
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

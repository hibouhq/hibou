package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type ParsedComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
	Licenses  []string
	BomRefs   []string
	// Properties are the CycloneDX component properties, by name; a name
	// may repeat (one "hibou:scope" per scope). The built-in extractor
	// carries relationship, scope, module and registry this way
	// (ADR-045 §5).
	Properties map[string][]string
}

type ParsedDependency struct {
	Ref       string
	DependsOn []string
}

type cycloneDXDocument struct {
	BOMFormat string `json:"bomFormat"`
	Metadata  struct {
		Component *cycloneDXComponent `json:"component"`
	} `json:"metadata"`
	Components   []cycloneDXComponent  `json:"components"`
	Dependencies []cycloneDXDependency `json:"dependencies"`
}

type cycloneDXComponent struct {
	// Group carries the namespace CycloneDX splits off the name (npm scope,
	// Maven groupId); dropping it made hibou query advisories under the bare
	// name — see canonicalComponentName.
	Group      string               `json:"group"`
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	PURL       string               `json:"purl"`
	BomRef     string               `json:"bom-ref"`
	Licenses   []cycloneDXLicense   `json:"licenses"`
	Components []cycloneDXComponent `json:"components"`
	Properties []cycloneDXProperty  `json:"properties"`
}

type cycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func componentProperties(entries []cycloneDXProperty) map[string][]string {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[string][]string, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		value := strings.TrimSpace(entry.Value)
		if name == "" || value == "" {
			continue
		}
		out[name] = append(out[name], value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

type cycloneDXLicense struct {
	Expression string `json:"expression"`
	License    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
}

func componentLicenses(entries []cycloneDXLicense) []string {
	out := make([]string, 0, len(entries))
	seen := map[string]struct{}{}
	for _, entry := range entries {
		value := strings.TrimSpace(entry.License.ID)
		if value == "" {
			value = strings.TrimSpace(entry.Expression)
		}
		if value == "" {
			value = strings.TrimSpace(entry.License.Name)
		}
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

type cycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type parsedCycloneDXGraph struct {
	Components           []ParsedComponent
	Dependencies         []ParsedDependency
	RootBomRef           string
	BomRefComponentIndex map[string]int
}

func ParseCycloneDXJSON(data []byte) ([]ParsedComponent, error) {
	parsed, err := parseCycloneDXJSONGraph(data)
	if err != nil {
		return nil, err
	}
	return parsed.Components, nil
}

func ParseCycloneDXJSONGraph(data []byte) ([]ParsedComponent, []ParsedDependency, string, map[string]int, error) {
	parsed, err := parseCycloneDXJSONGraph(data)
	if err != nil {
		return nil, nil, "", nil, err
	}
	return parsed.Components, parsed.Dependencies, parsed.RootBomRef, parsed.BomRefComponentIndex, nil
}

func parseCycloneDXJSONGraph(data []byte) (parsedCycloneDXGraph, error) {
	var doc cycloneDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return parsedCycloneDXGraph{}, fmt.Errorf("decode cyclonedx json: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(doc.BOMFormat), "CycloneDX") {
		return parsedCycloneDXGraph{}, errors.New("sbom is not a CycloneDX JSON document")
	}

	parsed := parsedCycloneDXGraph{
		Components:           make([]ParsedComponent, 0),
		Dependencies:         make([]ParsedDependency, 0, len(doc.Dependencies)),
		RootBomRef:           strings.TrimSpace(componentBomRef(doc.Metadata.Component)),
		BomRefComponentIndex: make(map[string]int),
	}
	seen := map[string]int{}
	if doc.Metadata.Component != nil {
		collectCycloneDXComponent(*doc.Metadata.Component, seen, &parsed)
	}
	for _, component := range doc.Components {
		collectCycloneDXComponent(component, seen, &parsed)
	}
	for _, dependency := range doc.Dependencies {
		ref := strings.TrimSpace(dependency.Ref)
		if ref == "" {
			continue
		}
		dependsOn := make([]string, 0, len(dependency.DependsOn))
		seenDepends := make(map[string]struct{}, len(dependency.DependsOn))
		for _, candidate := range dependency.DependsOn {
			trimmed := strings.TrimSpace(candidate)
			if trimmed == "" {
				continue
			}
			if _, ok := seenDepends[trimmed]; ok {
				continue
			}
			seenDepends[trimmed] = struct{}{}
			dependsOn = append(dependsOn, trimmed)
		}
		parsed.Dependencies = append(parsed.Dependencies, ParsedDependency{Ref: ref, DependsOn: dependsOn})
	}

	return parsed, nil
}

func collectCycloneDXComponent(component cycloneDXComponent, seen map[string]int, parsed *parsedCycloneDXGraph) {
	purl := strings.TrimSpace(component.PURL)
	version := strings.TrimSpace(component.Version)
	name := canonicalComponentName(purl, component.Group, component.Name)
	bomRef := strings.TrimSpace(component.BomRef)
	if purl != "" && version != "" {
		ecosystem := ecosystemFromPURL(purl)
		if ecosystem != "" {
			key := purl + "@" + version
			if index, ok := seen[key]; ok {
				appendComponentBomRef(parsed, index, bomRef)
			} else {
				seen[key] = len(parsed.Components)
				parsed.Components = append(parsed.Components, ParsedComponent{
					PURL:       purl,
					Name:       name,
					Version:    version,
					Ecosystem:  ecosystem,
					Licenses:   componentLicenses(component.Licenses),
					BomRefs:    nil,
					Properties: componentProperties(component.Properties),
				})
				appendComponentBomRef(parsed, len(parsed.Components)-1, bomRef)
			}
		}
	}
	for _, nested := range component.Components {
		collectCycloneDXComponent(nested, seen, parsed)
	}
}

func appendComponentBomRef(parsed *parsedCycloneDXGraph, index int, bomRef string) {
	bomRef = strings.TrimSpace(bomRef)
	if bomRef == "" {
		return
	}
	component := &parsed.Components[index]
	for _, existing := range component.BomRefs {
		if existing == bomRef {
			parsed.BomRefComponentIndex[bomRef] = index
			return
		}
	}
	component.BomRefs = append(component.BomRefs, bomRef)
	parsed.BomRefComponentIndex[bomRef] = index
}

func componentBomRef(component *cycloneDXComponent) string {
	if component == nil {
		return ""
	}
	return component.BomRef
}

func ecosystemFromPURL(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if !strings.HasPrefix(trimmed, "pkg:") {
		return ""
	}
	remainder := strings.TrimPrefix(trimmed, "pkg:")
	stop := len(remainder)
	for _, separator := range []string{"/", "@", "?", "#"} {
		if idx := strings.Index(remainder, separator); idx >= 0 && idx < stop {
			stop = idx
		}
	}
	typeName := strings.ToLower(strings.TrimSpace(remainder[:stop]))
	switch typeName {
	case "gomod", "golang":
		return "go"
	case "nodejs":
		return "npm"
	default:
		return typeName
	}
}

package sbom

import (
	"sort"
	"strings"
)

// ComponentDelta represents one component in the diff.
type ComponentDelta struct {
	PURL        string `json:"purl,omitempty"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	BaseVersion string `json:"base_version,omitempty"`
	HeadVersion string `json:"head_version,omitempty"`
	Ecosystem   string `json:"ecosystem,omitempty"`
}

// SBOMDiff is the result of comparing two parsed SBOMs.
type SBOMDiff struct {
	Added          []ComponentDelta `json:"added"`
	Removed        []ComponentDelta `json:"removed"`
	VersionChanged []ComponentDelta `json:"version_changed"`
	Unchanged      []ComponentDelta `json:"unchanged"`
	Summary        SBOMDiffSummary  `json:"summary"`
}

type SBOMDiffSummary struct {
	TotalBase      int `json:"total_base"`
	TotalHead      int `json:"total_head"`
	Added          int `json:"added"`
	Removed        int `json:"removed"`
	VersionChanged int `json:"version_changed"`
	Unchanged      int `json:"unchanged"`
}

func Compare(base, head []ParsedComponent) *SBOMDiff {
	baseIndex := indexComponents(base)
	headIndex := indexComponents(head)

	diff := &SBOMDiff{
		Added:          make([]ComponentDelta, 0),
		Removed:        make([]ComponentDelta, 0),
		VersionChanged: make([]ComponentDelta, 0),
		Unchanged:      make([]ComponentDelta, 0),
		Summary: SBOMDiffSummary{
			TotalBase: totalIndexedComponents(baseIndex),
			TotalHead: totalIndexedComponents(headIndex),
		},
	}

	for key, headComponents := range headIndex {
		baseComponents, ok := baseIndex[key]
		if !ok {
			appendComponentDeltas(&diff.Added, headComponents)
			continue
		}

		compareComponentGroup(diff, baseComponents, headComponents)
	}

	for key, baseComponents := range baseIndex {
		if _, ok := headIndex[key]; ok {
			continue
		}
		appendComponentDeltas(&diff.Removed, baseComponents)
	}

	sortComponentDeltas(diff.Added)
	sortComponentDeltas(diff.Removed)
	sortComponentDeltas(diff.VersionChanged)
	sortComponentDeltas(diff.Unchanged)

	diff.Summary.Added = len(diff.Added)
	diff.Summary.Removed = len(diff.Removed)
	diff.Summary.VersionChanged = len(diff.VersionChanged)
	diff.Summary.Unchanged = len(diff.Unchanged)

	return diff
}

func compareComponentGroup(diff *SBOMDiff, baseComponents, headComponents []ParsedComponent) {
	baseByVersion := indexGroupVersions(baseComponents)
	headByVersion := indexGroupVersions(headComponents)

	for versionKey, headComponent := range headByVersion {
		baseComponent, ok := baseByVersion[versionKey]
		if !ok {
			continue
		}
		diff.Unchanged = append(diff.Unchanged, ComponentDelta{
			PURL:      preferredString(headComponent.PURL, baseComponent.PURL),
			Name:      preferredString(headComponent.Name, baseComponent.Name),
			Version:   preferredString(headComponent.Version, baseComponent.Version),
			Ecosystem: preferredString(headComponent.Ecosystem, baseComponent.Ecosystem),
		})
		delete(baseByVersion, versionKey)
		delete(headByVersion, versionKey)
	}

	if len(baseComponents) == 1 && len(headComponents) == 1 && len(baseByVersion) == 1 && len(headByVersion) == 1 {
		baseComponent := firstIndexedComponent(baseByVersion)
		headComponent := firstIndexedComponent(headByVersion)
		diff.VersionChanged = append(diff.VersionChanged, ComponentDelta{
			PURL:        preferredString(headComponent.PURL, baseComponent.PURL),
			Name:        preferredString(headComponent.Name, baseComponent.Name),
			BaseVersion: baseComponent.Version,
			HeadVersion: headComponent.Version,
			Ecosystem:   preferredString(headComponent.Ecosystem, baseComponent.Ecosystem),
		})
		return
	}

	appendIndexedComponentDeltas(&diff.Removed, baseByVersion)
	appendIndexedComponentDeltas(&diff.Added, headByVersion)
}

func indexComponents(components []ParsedComponent) map[string][]ParsedComponent {
	indexed := make(map[string]map[string]ParsedComponent, len(components))
	for _, component := range components {
		key := componentKey(component)
		if key == "" {
			continue
		}
		versionKey := componentVersionKey(component)
		if versionKey == "" {
			continue
		}
		if indexed[key] == nil {
			indexed[key] = make(map[string]ParsedComponent)
		}
		if _, exists := indexed[key][versionKey]; exists {
			continue
		}
		indexed[key][versionKey] = component
	}

	groups := make(map[string][]ParsedComponent, len(indexed))
	for key, componentsByVersion := range indexed {
		group := make([]ParsedComponent, 0, len(componentsByVersion))
		for _, component := range componentsByVersion {
			group = append(group, component)
		}
		sortParsedComponents(group)
		groups[key] = group
	}

	return groups
}

func componentKey(component ParsedComponent) string {
	purl := normalizedPURLKey(component.PURL)
	if purl != "" {
		return purl
	}
	name := strings.TrimSpace(component.Name)
	ecosystem := strings.TrimSpace(component.Ecosystem)
	if name == "" {
		return ""
	}
	return name + "|" + ecosystem
}

func componentVersionKey(component ParsedComponent) string {
	if purl := strings.TrimSpace(component.PURL); purl != "" {
		return purl
	}
	if version := strings.TrimSpace(component.Version); version != "" {
		return version
	}
	return componentKey(component)
}

func normalizedPURLKey(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if trimmed == "" {
		return ""
	}
	stop := len(trimmed)
	for _, separator := range []string{"?", "#"} {
		if idx := strings.Index(trimmed, separator); idx >= 0 && idx < stop {
			stop = idx
		}
	}
	body := trimmed[:stop]
	suffix := trimmed[stop:]
	lastSlash := strings.LastIndex(body, "/")
	versionSep := strings.LastIndex(body, "@")
	if versionSep > lastSlash {
		body = body[:versionSep]
	}
	return body + suffix
}

func preferredString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func totalIndexedComponents(indexed map[string][]ParsedComponent) int {
	total := 0
	for _, group := range indexed {
		total += len(group)
	}
	return total
}

func indexGroupVersions(components []ParsedComponent) map[string]ParsedComponent {
	indexed := make(map[string]ParsedComponent, len(components))
	for _, component := range components {
		indexed[componentVersionKey(component)] = component
	}
	return indexed
}

func firstIndexedComponent(indexed map[string]ParsedComponent) ParsedComponent {
	for _, component := range indexed {
		return component
	}
	return ParsedComponent{}
}

func appendComponentDeltas(dst *[]ComponentDelta, components []ParsedComponent) {
	for _, component := range components {
		*dst = append(*dst, ComponentDelta{
			PURL:      component.PURL,
			Name:      component.Name,
			Version:   component.Version,
			Ecosystem: component.Ecosystem,
		})
	}
}

func appendIndexedComponentDeltas(dst *[]ComponentDelta, indexed map[string]ParsedComponent) {
	components := make([]ParsedComponent, 0, len(indexed))
	for _, component := range indexed {
		components = append(components, component)
	}
	sortParsedComponents(components)
	appendComponentDeltas(dst, components)
}

func sortParsedComponents(components []ParsedComponent) {
	sort.Slice(components, func(i, j int) bool {
		left := components[i]
		right := components[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Ecosystem != right.Ecosystem {
			return left.Ecosystem < right.Ecosystem
		}
		if left.PURL != right.PURL {
			return left.PURL < right.PURL
		}
		return left.Version < right.Version
	})
}

func sortComponentDeltas(components []ComponentDelta) {
	sort.Slice(components, func(i, j int) bool {
		left := components[i]
		right := components[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Ecosystem != right.Ecosystem {
			return left.Ecosystem < right.Ecosystem
		}
		if left.PURL != right.PURL {
			return left.PURL < right.PURL
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		if left.BaseVersion != right.BaseVersion {
			return left.BaseVersion < right.BaseVersion
		}
		return left.HeadVersion < right.HeadVersion
	})
}

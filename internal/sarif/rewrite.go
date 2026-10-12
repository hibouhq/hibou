package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// URIRewriter returns the replacement for an artifact location, or false to
// keep it. baseURI is the resolved originalUriBaseIds entry ("" when none).
type URIRewriter func(uri, baseURI string) (string, bool)

// RewriteArtifactURIs rewrites every artifactLocation of the document's runs
// — result locations, code flow locations, related locations and
// run.artifacts — through rewrite. A rewritten location drops its uriBaseId:
// the new URI is relative to the checkout root. Returns the input unchanged
// when nothing was rewritten.
func RewriteArtifactURIs(data []byte, rewrite URIRewriter) ([]byte, int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		return data, 0, fmt.Errorf("decode sarif: %w", err)
	}
	runs, _ := doc["runs"].([]any)
	rewritten := 0
	for _, rawRun := range runs {
		run, ok := rawRun.(map[string]any)
		if !ok {
			continue
		}
		baseIDs, _ := run["originalUriBaseIds"].(map[string]any)
		visit := func(location map[string]any) {
			uri, _ := location["uri"].(string)
			uri = strings.TrimSpace(uri)
			if uri == "" {
				return
			}
			baseID, _ := location["uriBaseId"].(string)
			if replacement, ok := rewrite(uri, resolveBaseURI(baseIDs, baseID)); ok && replacement != uri {
				location["uri"] = replacement
				delete(location, "uriBaseId")
				rewritten++
			}
		}
		walkArtifactLocations(run["results"], visit)
		walkArtifactLocations(run["artifacts"], visit)
	}
	if rewritten == 0 {
		return data, 0, nil
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return data, 0, fmt.Errorf("encode sarif: %w", err)
	}
	return out.Bytes(), rewritten, nil
}

// walkArtifactLocations calls visit on every "artifactLocation" object (and
// run.artifacts[].location) below node.
func walkArtifactLocations(node any, visit func(map[string]any)) {
	switch value := node.(type) {
	case []any:
		for _, item := range value {
			walkArtifactLocations(item, visit)
		}
	case map[string]any:
		for key, child := range value {
			if location, ok := child.(map[string]any); ok && (key == "artifactLocation" || key == "location" && looksLikeArtifactLocation(location)) {
				visit(location)
				continue
			}
			walkArtifactLocations(child, visit)
		}
	}
}

// looksLikeArtifactLocation tells run.artifacts[].location (an
// artifactLocation) from a result's "location" wrapper inside code flows.
func looksLikeArtifactLocation(location map[string]any) bool {
	_, hasURI := location["uri"]
	_, hasPhysical := location["physicalLocation"]
	return hasURI && !hasPhysical
}

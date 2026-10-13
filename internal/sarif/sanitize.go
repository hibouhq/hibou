package sarif

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// snippetRegionKeys are the SARIF region objects that may carry a snippet:
// result and related locations (region, contextRegion), code flows and
// stacks (same shapes), and fixes (deletedRegion).
var snippetRegionKeys = map[string]bool{
	"region":        true,
	"contextRegion": true,
	"deletedRegion": true,
}

// StripSnippets removes the source excerpts a SARIF log carries in
// region.snippet / contextRegion.snippet (anywhere: locations, related
// locations, code flows, fixes) and returns the re-encoded document. Secret
// scanners put the matched secret there verbatim, and hibou derives nothing
// from snippets, so the stored artifact must not keep them.
//
// Numbers are preserved exactly (decoded as json.Number); key order and
// whitespace are not.
func StripSnippets(content []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode sarif: %w", err)
	}
	if _, ok := document.(map[string]any); !ok {
		return nil, errors.New("decode sarif: document is not a JSON object")
	}
	if !stripSnippets(document, "") {
		return content, nil
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("encode sarif: %w", err)
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

// stripSnippets walks the document and reports whether it removed anything.
func stripSnippets(node any, parentKey string) bool {
	changed := false
	switch typed := node.(type) {
	case map[string]any:
		if snippetRegionKeys[parentKey] {
			if _, ok := typed["snippet"]; ok {
				delete(typed, "snippet")
				changed = true
			}
		}
		for key, child := range typed {
			if stripSnippets(child, key) {
				changed = true
			}
		}
	case []any:
		for _, child := range typed {
			if stripSnippets(child, parentKey) {
				changed = true
			}
		}
	}
	return changed
}

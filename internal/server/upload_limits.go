package server

import (
	"bytes"
	"encoding/json"
	"strings"
)

// defaultUploadMaxItems applies when a Server is built without config.Load.
const defaultUploadMaxItems = 200000

func (s *Server) uploadMaxItems() int {
	if s.limits.Upload.MaxItems > 0 {
		return s.limits.Upload.MaxItems
	}
	return defaultUploadMaxItems
}

// skipJSON consumes a JSON value without keeping it: a []skipJSON costs no
// memory per element, so counting a document's entries does not copy it.
type skipJSON struct{}

func (*skipJSON) UnmarshalJSON([]byte) error { return nil }

// uploadJSONProbe reads only what type detection and the item cap need. It
// replaces a map[string]json.RawMessage probe that copied the whole document
// (every top-level value) once more per upload.
type uploadJSONProbe struct {
	Context     json.RawMessage `json:"@context"`
	Statements  []skipJSON      `json:"statements"`
	BOMFormat   json.RawMessage `json:"bomFormat"`
	SPDXVersion json.RawMessage `json:"spdxVersion"`
	Components  []skipJSON      `json:"components"`
	Packages    []skipJSON      `json:"packages"`
	Schema      json.RawMessage `json:"$schema"`
	Document    struct {
		Category string `json:"category"`
	} `json:"document"`
	Vulnerabilities []skipJSON `json:"vulnerabilities"`
	Runs            []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []skipJSON `json:"results"`
	} `json:"runs"`
}

// detect mirrors detectJSONArtifactType's precedence.
func (p *uploadJSONProbe) detect() (string, string, string, int, bool) {
	var context string
	if json.Unmarshal(p.Context, &context) == nil && strings.Contains(context, "openvex.dev") {
		return "vex", "openvex", "", len(p.Statements), true
	}
	if p.Document.Category == "csaf_vex" {
		return "vex", "csaf", "", len(p.Vulnerabilities), true
	}
	if p.BOMFormat != nil {
		return "sbom", "cyclonedx-json", "", len(p.Components), true
	}
	if p.SPDXVersion != nil {
		return "sbom", "spdx-json", "", len(p.Packages), true
	}
	var schema string
	if p.Runs != nil || (json.Unmarshal(p.Schema, &schema) == nil && strings.Contains(strings.ToLower(schema), "sarif")) {
		tool := ""
		results := 0
		for index, run := range p.Runs {
			if index == 0 {
				tool = strings.ToLower(strings.TrimSpace(run.Tool.Driver.Name))
			}
			results += len(run.Results)
		}
		return "sarif", "", tool, results, true
	}
	return "", "", "", 0, false
}

// detectArtifactTypeAndCount is detectArtifactType plus the number of entries
// the artifact will expand into (SARIF results, SBOM components or packages,
// VEX statements, test cases), checked against upload.max_items before any
// processing. A document the narrow probe cannot read falls back to the
// general detector, uncounted.
func detectArtifactTypeAndCount(content []byte) (string, string, string, int, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var probe uploadJSONProbe
		if json.Unmarshal(trimmed, &probe) == nil {
			if uploadType, format, tool, items, ok := probe.detect(); ok {
				return uploadType, format, tool, items, nil
			}
		}
	}
	uploadType, format, tool, err := detectArtifactType(content)
	if err != nil {
		return "", "", "", 0, err
	}
	return uploadType, format, tool, countTextArtifactItems(format, trimmed), nil
}

// countTextArtifactItems approximates the entry count of XML and tag-value
// formats by their element markers; a slight overcount is harmless for a cap.
func countTextArtifactItems(format string, content []byte) int {
	var marker string
	switch format {
	case "cyclonedx-xml":
		marker = "<component"
	case "spdx-xml":
		marker = "<spdx:Package"
	case "spdx-tv":
		marker = "PackageName:"
	case "junit":
		marker = "<testcase"
	default:
		return 0
	}
	return bytes.Count(content, []byte(marker))
}

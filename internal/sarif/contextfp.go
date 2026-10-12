package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ContextFingerprintKey is the partialFingerprints key hibou adds to results
// that carry no scanner fingerprint (ADR-034, D15). The value hashes what the
// flagged code says, not where it sits, so a finding keeps its identity when
// lines are added above it.
const ContextFingerprintKey = "hibou/contextHash/v1"

// contextRadius is the number of lines on each side of the flagged line that
// enter the hash: enough to tell two identical statements apart, few enough
// that an unrelated edit nearby rarely re-keys the finding.
const contextRadius = 2

// SourceReader returns the content of the file a result points at. uri is the
// artifactLocation.uri as written; baseURI is the resolved originalUriBaseIds
// entry for its uriBaseId ("" when none). A non-nil error leaves that result
// unchanged.
type SourceReader func(uri, baseURI string) ([]byte, error)

// AddContextFingerprints adds ContextFingerprintKey to every result that has
// neither fingerprints nor partialFingerprints and whose source line can be
// read. It returns the input unchanged when nothing was added, so documents
// that already carry fingerprints are uploaded byte for byte.
func AddContextFingerprints(data []byte, read SourceReader) ([]byte, int, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		return data, 0, fmt.Errorf("decode sarif: %w", err)
	}
	runs, _ := doc["runs"].([]any)
	files := map[string][]string{}
	added := 0
	for _, rawRun := range runs {
		run, ok := rawRun.(map[string]any)
		if !ok {
			continue
		}
		added += addRunContextFingerprints(run, read, files)
	}
	if added == 0 {
		return data, 0, nil
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return data, 0, fmt.Errorf("encode sarif: %w", err)
	}
	return out.Bytes(), added, nil
}

type pendingContextResult struct {
	result map[string]any
	key    string
	line   int
	order  int
}

func addRunContextFingerprints(run map[string]any, read SourceReader, files map[string][]string) int {
	toolName := ""
	if tool, ok := run["tool"].(map[string]any); ok {
		if driver, ok := tool["driver"].(map[string]any); ok {
			toolName, _ = driver["name"].(string)
		}
	}
	toolName = strings.ToLower(strings.TrimSpace(toolName))
	baseIDs, _ := run["originalUriBaseIds"].(map[string]any)
	artifacts, _ := run["artifacts"].([]any)
	results, _ := run["results"].([]any)

	pending := make([]pendingContextResult, 0)
	for order, rawResult := range results {
		result, ok := rawResult.(map[string]any)
		if !ok || hasAnyFingerprint(result) {
			continue
		}
		uri, baseID, line := contextLocation(result, artifacts)
		if uri == "" || line <= 0 {
			continue
		}
		cacheKey := baseID + "\x00" + uri
		lines, cached := files[cacheKey]
		if !cached {
			content, err := read(uri, resolveBaseURI(baseIDs, baseID))
			if err == nil {
				lines = splitSourceLines(content)
			}
			files[cacheKey] = lines
		}
		if line > len(lines) {
			continue
		}
		pending = append(pending, pendingContextResult{
			result: result,
			key:    contextHashInput(toolName, contextRuleID(result), uri, lines, line),
			line:   line,
			order:  order,
		})
	}

	// Identical contexts in one file (the same statement written twice) are
	// numbered in line order so each keeps a distinct identity.
	sort.SliceStable(pending, func(i, j int) bool {
		if pending[i].line != pending[j].line {
			return pending[i].line < pending[j].line
		}
		return pending[i].order < pending[j].order
	})
	seen := map[string]int{}
	for _, item := range pending {
		occurrence := seen[item.key]
		seen[item.key] = occurrence + 1
		value := sha256Hex(item.key + "\x00" + strconv.Itoa(occurrence))
		partial, _ := item.result["partialFingerprints"].(map[string]any)
		if partial == nil {
			partial = map[string]any{}
		}
		partial[ContextFingerprintKey] = value
		item.result["partialFingerprints"] = partial
	}
	return len(pending)
}

func hasAnyFingerprint(result map[string]any) bool {
	for _, field := range []string{"fingerprints", "partialFingerprints"} {
		values, _ := result[field].(map[string]any)
		for _, value := range values {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				return true
			}
		}
	}
	return false
}

// contextLocation reads the first location the server also uses
// (resultLocation): the artifactLocation uri, falling back to run.artifacts
// through its index.
func contextLocation(result map[string]any, artifacts []any) (string, string, int) {
	locations, _ := result["locations"].([]any)
	if len(locations) == 0 {
		return "", "", 0
	}
	location, _ := locations[0].(map[string]any)
	physical, _ := location["physicalLocation"].(map[string]any)
	artifact, _ := physical["artifactLocation"].(map[string]any)
	region, _ := physical["region"].(map[string]any)
	uri, _ := artifact["uri"].(string)
	baseID, _ := artifact["uriBaseId"].(string)
	if strings.TrimSpace(uri) == "" {
		if index, ok := jsonInt(artifact["index"]); ok && index >= 0 && index < len(artifacts) {
			entry, _ := artifacts[index].(map[string]any)
			entryLocation, _ := entry["location"].(map[string]any)
			uri, _ = entryLocation["uri"].(string)
			if baseID == "" {
				baseID, _ = entryLocation["uriBaseId"].(string)
			}
		}
	}
	line, _ := jsonInt(region["startLine"])
	return strings.TrimSpace(uri), baseID, line
}

func contextRuleID(result map[string]any) string {
	if ruleID, ok := result["ruleId"].(string); ok && strings.TrimSpace(ruleID) != "" {
		return strings.TrimSpace(ruleID)
	}
	if rule, ok := result["rule"].(map[string]any); ok {
		if id, ok := rule["id"].(string); ok {
			return strings.TrimSpace(id)
		}
	}
	return ""
}

func resolveBaseURI(baseIDs map[string]any, baseID string) string {
	if baseID == "" {
		return ""
	}
	entry, _ := baseIDs[baseID].(map[string]any)
	uri, _ := entry["uri"].(string)
	return uri
}

func jsonInt(value any) (int, bool) {
	switch number := value.(type) {
	case json.Number:
		parsed, err := strconv.Atoi(number.String())
		return parsed, err == nil
	case float64:
		return int(number), true
	}
	return 0, false
}

func splitSourceLines(content []byte) []string {
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

// contextHashInput joins the identity parts. Lines are whitespace-normalized
// so re-indentation and trailing spaces do not re-key a finding.
func contextHashInput(tool, ruleID, path string, lines []string, line int) string {
	start := max(line-contextRadius, 1)
	end := min(line+contextRadius, len(lines))
	window := make([]string, 0, end-start+1)
	for n := start; n <= end; n++ {
		window = append(window, strings.Join(strings.Fields(lines[n-1]), " "))
	}
	return strings.Join([]string{tool, ruleID, path, strings.Join(window, "\n")}, "\x00")
}

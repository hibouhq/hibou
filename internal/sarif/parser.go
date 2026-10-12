package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hibouhq/hibou/internal/cwe"
)

const maxDocumentSize = 50 << 20

func Parse(r io.Reader) (*Document, error) {
	if r == nil {
		return nil, errors.New("reader is required")
	}

	var doc Document
	decoder := json.NewDecoder(io.LimitReader(r, maxDocumentSize))
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

// advisoryRuleIDPattern matches rule IDs that are dependency-advisory
// identifiers (CVE and the OSV/distro advisory namespaces) rather than
// static-analysis rules. Scanners that also do dependency scanning (Trivy,
// Grype, …) reuse the advisory ID as the SARIF rule ID, which is what makes
// these recognizable regardless of tool.
var advisoryRuleIDPattern = regexp.MustCompile(`^(?i)(` +
	`CVE-\d{4}-\d+` +
	`|GHSA(-[23456789cfghjmpqrvwx]{4}){3}` +
	`|(RUSTSEC|PYSEC|OSV|MAL|GO|GSD|DSA|DLA|ELSA|ALSA|ALBA|USN)-\d{2,6}[\w.:-]*` +
	`|CGA(-[23456789cfghjmpqrvwx]{4}){3}` +
	`)$`)

// IsAdvisoryFinding reports whether a SARIF result is a dependency advisory
// rather than a static-analysis finding: its rule ID sits in an advisory
// namespace, or the scanner tagged the rule as a vulnerability. Dependency
// advisories are matched server-side from the SBOM with full component
// context, so ingesting them as SAST would double-count every one.
func IsAdvisoryFinding(ruleID string, rule *RuleDescriptor) bool {
	if advisoryRuleIDPattern.MatchString(strings.TrimSpace(ruleID)) {
		return true
	}
	if rule == nil {
		return false
	}
	for _, tag := range rule.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), "vulnerability") {
			return true
		}
	}
	return false
}

// IsSecretFinding reports whether a SARIF result is a leaked-secret
// detection rather than a static-analysis finding. Trivy tags every rule with
// its result type ("vulnerability", "misconfiguration", "secret", "license");
// secrets are reported by the dedicated secret scanner, so ingesting Trivy's
// copies as SAST would duplicate each one. Only the exact tag counts: a SAST
// rule tagged "secrets" or "hardcoded-secret" is still a code finding.
func IsSecretFinding(rule *RuleDescriptor) bool {
	if rule == nil {
		return false
	}
	for _, tag := range rule.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), "secret") {
			return true
		}
	}
	return false
}

func ExtractFindings(doc *Document, repoID string) ([]Finding, error) {
	if doc == nil {
		return nil, errors.New("document is required")
	}

	findings := make([]Finding, 0)
	for _, run := range doc.Runs {
		// Lowercased so the same scanner keys identically wherever the name
		// appears (SARIF driver "Trivy", server-side provider "trivy").
		toolName := strings.ToLower(strings.TrimSpace(run.Tool.Driver.Name))
		toolVersion := strings.TrimSpace(run.Tool.Driver.Version)
		if toolVersion == "" {
			toolVersion = strings.TrimSpace(run.Tool.Driver.SemanticVersion)
		}
		taxonomy := newCWETaxonomy(run)
		for _, result := range run.Results {
			rule := resolveRule(run.Tool, result)
			filePath, startLine, endLine := resultLocation(result)
			ruleID := strings.TrimSpace(result.RuleID)
			if ruleID == "" && result.Rule != nil {
				ruleID = strings.TrimSpace(result.Rule.ID)
			}
			if ruleID == "" {
				ruleID = strings.TrimSpace(rule.ID)
			}
			fingerprint := producerFingerprint(result)
			if fingerprint == "" {
				fingerprint = sha256Hex(repoID + "/" + toolName + "/" + ruleID + "/" + filePath + "/" + strconv.Itoa(int(startLine)))
			}

			finding := Finding{
				Tool:         toolName,
				ToolVersion:  toolVersion,
				TraceFiles:   codeFlowFiles(result.CodeFlows),
				RuleID:       ruleID,
				Severity:     mapSeverity(result.Level),
				FilePath:     filePath,
				StartLine:    startLine,
				EndLine:      endLine,
				Message:      strings.TrimSpace(result.Message.Text),
				Fingerprint:  fingerprint,
				LocationHash: sha256Hex(toolName + "/" + ruleID + "/" + filePath + "/" + strconv.Itoa(int(startLine))),
				Rule:         ruleDescriptor(ruleID, rule, taxonomy),
				ResultCWEs:   taxonomy.resultCWEs(result.Taxa),
			}
			applySuppression(&finding, result.Suppressions)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// ruleDescriptor normalizes a SARIF reportingDescriptor into the per-rule
// catalog record. Returns nil when there is no rule id to key on.
func ruleDescriptor(ruleID string, rule ReportingDescriptor, taxonomy cweTaxonomy) *RuleDescriptor {
	if ruleID == "" {
		return nil
	}

	var props reportingDescriptorProperties
	if len(rule.Properties) > 0 {
		_ = json.Unmarshal(rule.Properties, &props)
	}

	desc := &RuleDescriptor{
		RuleID:           ruleID,
		Name:             strings.TrimSpace(rule.Name),
		HelpURI:          strings.TrimSpace(rule.HelpURI),
		SecuritySeverity: strings.TrimSpace(props.SecuritySeverity),
		Precision:        strings.TrimSpace(props.Precision),
		CWEs:             cwe.Dedupe(append(taxonomy.ruleCWEs(rule.Relationships), tagCWEs(props.Tags)...)),
		Tags:             props.Tags,
		Properties:       rule.Properties,
	}
	if rule.ShortDescription != nil {
		desc.ShortDescription = strings.TrimSpace(rule.ShortDescription.Text)
	}
	if rule.FullDescription != nil {
		desc.FullDescription = strings.TrimSpace(rule.FullDescription.Text)
	}
	if rule.Help != nil {
		desc.HelpMarkdown = strings.TrimSpace(rule.Help.Markdown)
	}
	if rule.DefaultConfiguration != nil {
		desc.DefaultLevel = strings.TrimSpace(rule.DefaultConfiguration.Level)
	}
	return desc
}

// applySuppression marks a finding suppressed when the result carries at
// least one non-rejected suppression (SARIF §3.27.23: an empty array means
// the result is active; a rejected suppression does not suppress). checkov
// downgrades suppressed results to level=warning, so classification keys on
// this field, never on level.
func applySuppression(finding *Finding, suppressions []Suppression) {
	for _, suppression := range suppressions {
		if strings.EqualFold(suppression.Status, "rejected") {
			continue
		}
		finding.Suppressed = true
		finding.SuppressionKind = suppression.Kind
		finding.SuppressionJustification = strings.TrimSpace(suppression.Justification)
		return
	}
}

// resolveRule finds the result's reportingDescriptor: result.rule (§3.27.7,
// which may point into tool.extensions per §3.54.2), then ruleIndex into the
// driver, then ruleId.
func resolveRule(tool Tool, result Result) ReportingDescriptor {
	if ref := result.Rule; ref != nil {
		component, ok := referencedComponent(tool, ref.ToolComponent)
		if ok {
			if descriptor, found := lookupDescriptor(component.Rules, *ref); found {
				return descriptor
			}
		}
	}

	rules := tool.Driver.Rules
	if result.RuleIndex != nil {
		idx := *result.RuleIndex
		if idx >= 0 && idx < len(rules) {
			return rules[idx]
		}
	}

	if result.RuleID == "" {
		return ReportingDescriptor{}
	}

	for _, rule := range rules {
		if strings.EqualFold(rule.ID, result.RuleID) {
			return rule
		}
	}

	return ReportingDescriptor{}
}

// referencedComponent applies §3.54.2: no index and no guid means the driver,
// an index selects tool.extensions, a guid matches the driver or an extension.
func referencedComponent(tool Tool, ref *ToolComponentReference) (ToolComponent, bool) {
	if ref == nil || (ref.Index == nil && ref.GUID == "") {
		return tool.Driver, true
	}
	if ref.Index != nil {
		idx := *ref.Index
		if idx >= 0 && idx < len(tool.Extensions) {
			return tool.Extensions[idx], true
		}
		return ToolComponent{}, false
	}
	if strings.EqualFold(tool.Driver.GUID, ref.GUID) {
		return tool.Driver, true
	}
	for _, extension := range tool.Extensions {
		if strings.EqualFold(extension.GUID, ref.GUID) {
			return extension, true
		}
	}
	return ToolComponent{}, false
}

// lookupDescriptor resolves a reportingDescriptorReference within one
// component's descriptors: index, then guid, then id.
func lookupDescriptor(descriptors []ReportingDescriptor, ref ReportingDescriptorReference) (ReportingDescriptor, bool) {
	if ref.Index != nil {
		idx := *ref.Index
		if idx >= 0 && idx < len(descriptors) {
			return descriptors[idx], true
		}
	}
	if ref.GUID != "" {
		for _, descriptor := range descriptors {
			if strings.EqualFold(descriptor.GUID, ref.GUID) {
				return descriptor, true
			}
		}
	}
	if id := strings.TrimSpace(ref.ID); id != "" {
		for _, descriptor := range descriptors {
			if descriptor.ID == id {
				return descriptor, true
			}
		}
	}
	return ReportingDescriptor{}, false
}

// cweTaxonomy recognizes references to the CWE taxonomy within one run.
// Every producer uses its own GUID for "CWE" (gosec, KICS, SpotBugs, ZAP and
// Flawfinder all differ), so a GUID only counts when this run itself declares
// it as CWE; otherwise the component name "CWE" is the signal all of them
// share (ADR-037 §2), even though §3.54.3 excludes name from lookup.
type cweTaxonomy struct {
	guids map[string]struct{}
	// taxa of the inline CWE taxonomy, for targets that give index/guid but no id.
	taxa []ReportingDescriptor
}

func newCWETaxonomy(run Run) cweTaxonomy {
	taxonomy := cweTaxonomy{guids: map[string]struct{}{}}
	for _, component := range run.Taxonomies {
		if !isCWEName(component.Name) {
			continue
		}
		if component.GUID != "" {
			taxonomy.guids[strings.ToLower(component.GUID)] = struct{}{}
		}
		taxonomy.taxa = append(taxonomy.taxa, component.Taxa...)
	}
	for _, supported := range run.Tool.Driver.SupportedTaxonomies {
		if isCWEName(supported.Name) && supported.GUID != "" {
			taxonomy.guids[strings.ToLower(supported.GUID)] = struct{}{}
		}
	}
	return taxonomy
}

func isCWEName(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "CWE")
}

func (t cweTaxonomy) refersToCWE(ref *ToolComponentReference) bool {
	if ref == nil {
		return false
	}
	if isCWEName(ref.Name) {
		return true
	}
	_, ok := t.guids[strings.ToLower(ref.GUID)]
	return ref.GUID != "" && ok
}

// cweOf reads the CWE a taxon reference names: its id through the
// normalizer ("327" and "CWE-120" both occur), else index/guid into the inline
// taxa. An external taxonomy has no inline taxa, so an id-less target there is
// unresolvable and skipped.
func (t cweTaxonomy) cweOf(ref ReportingDescriptorReference) (int, bool) {
	if !t.refersToCWE(ref.ToolComponent) {
		return 0, false
	}
	if id, ok := cwe.Parse(ref.ID); ok {
		return id, true
	}
	if taxon, ok := lookupDescriptor(t.taxa, ReportingDescriptorReference{Index: ref.Index, GUID: ref.GUID}); ok {
		return cwe.Parse(taxon.ID)
	}
	return 0, false
}

// ruleCWEs keeps relationships that classify every result of the rule
// (ADR-037 §2.1): equal and superset by §3.27.8, plus relevant — the default
// when kinds is absent, and how KICS and Flawfinder state their mapping.
// subset/incomparable only overlap the CWE, so they count per result (taxa);
// disjoint and the ordering kinds never classify.
func (t cweTaxonomy) ruleCWEs(relationships []ReportingDescriptorRelationship) []int {
	out := make([]int, 0, len(relationships))
	for _, relationship := range relationships {
		if !classifiesRule(relationship.Kinds) {
			continue
		}
		if id, ok := t.cweOf(relationship.Target); ok {
			out = append(out, id)
		}
	}
	return cwe.Dedupe(out)
}

func classifiesRule(kinds []string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, kind := range kinds {
		switch strings.TrimSpace(kind) {
		case "equal", "superset", "relevant":
			return true
		}
	}
	return false
}

// resultCWEs reads result.taxa: the taxa this occurrence falls into.
func (t cweTaxonomy) resultCWEs(taxa []ReportingDescriptorReference) []int {
	if len(taxa) == 0 {
		return nil
	}
	out := make([]int, 0, len(taxa))
	for _, ref := range taxa {
		if id, ok := t.cweOf(ref); ok {
			out = append(out, id)
		}
	}
	return cwe.Dedupe(out)
}

func resultLocation(result Result) (string, int32, int32) {
	if len(result.Locations) == 0 {
		return "", 0, 0
	}

	location := result.Locations[0].PhysicalLocation
	return strings.TrimSpace(location.ArtifactLocation.URI), location.Region.StartLine, location.Region.EndLine
}

func mapSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	case "none":
		return "info"
	default:
		return "info"
	}
}

// tagCWEs reads the tag convention: "external/cwe/cwe-<n>" (CodeQL, bandit,
// mobsfscan, njsscan) or a tag starting with "CWE-<n>" (semgrep). CodeQL pads
// ids ("cwe-078"); the normalizer maps that to 78 like everyone else's.
func tagCWEs(tags []string) []int {
	out := make([]int, 0, len(tags))
	for _, tag := range tags {
		if id, ok := cwe.ParseTag(tag); ok {
			out = append(out, id)
		}
	}
	return out
}

func producerFingerprint(result Result) string {
	if fingerprint := firstFingerprintValue(result.Fingerprints); fingerprint != "" {
		return fingerprint
	}

	return firstFingerprintValue(result.PartialFingerprints)
}

func firstFingerprintValue(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}

	return ""
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// codeFlowFiles lists the distinct files of a result's code flows
// (codeFlows[].threadFlows[].locations[].location.physicalLocation), in
// first-seen order. Decoded loosely: codeFlows stay untyped elsewhere.
func codeFlowFiles(codeFlows []map[string]any) []string {
	files := make([]string, 0)
	seen := make(map[string]struct{})
	for _, codeFlow := range codeFlows {
		threadFlows, _ := codeFlow["threadFlows"].([]any)
		for _, rawThread := range threadFlows {
			thread, _ := rawThread.(map[string]any)
			locations, _ := thread["locations"].([]any)
			for _, rawLocation := range locations {
				threadLocation, _ := rawLocation.(map[string]any)
				location, _ := threadLocation["location"].(map[string]any)
				physical, _ := location["physicalLocation"].(map[string]any)
				artifact, _ := physical["artifactLocation"].(map[string]any)
				uri, _ := artifact["uri"].(string)
				uri = strings.TrimSpace(uri)
				if uri == "" {
					continue
				}
				if _, dup := seen[uri]; dup {
					continue
				}
				seen[uri] = struct{}{}
				files = append(files, uri)
			}
		}
	}
	return files
}

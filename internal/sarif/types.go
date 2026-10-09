package sarif

import "encoding/json"

type Document struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
	// Taxonomies holds standard taxonomies such as CWE (§3.14.8); rules and
	// results point into them through relationships and taxa.
	Taxonomies                     []ToolComponent                 `json:"taxonomies"`
	ExternalPropertyFileReferences *ExternalPropertyFileReferences `json:"externalPropertyFileReferences,omitempty"`
}

// ExternalPropertyFileReferences (§3.15) is only read for its taxonomy
// GUIDs: Flawfinder declares CWE as an external file and never inlines it.
type ExternalPropertyFileReferences struct {
	Taxonomies []ExternalPropertyFileReference `json:"taxonomies"`
}

type ExternalPropertyFileReference struct {
	GUID string `json:"guid"`
}

type Tool struct {
	Driver ToolComponent `json:"driver"`
	// Extensions (§3.18.3) may define rules too; result.rule.toolComponent.index
	// points into this array.
	Extensions []ToolComponent `json:"extensions"`
}

type ToolComponent struct {
	Name                string                   `json:"name"`
	GUID                string                   `json:"guid"`
	Version             string                   `json:"version"`
	Rules               []ReportingDescriptor    `json:"rules"`
	Taxa                []ReportingDescriptor    `json:"taxa"`
	SupportedTaxonomies []ToolComponentReference `json:"supportedTaxonomies"`
}

type ReportingDescriptor struct {
	ID                   string                  `json:"id"`
	GUID                 string                  `json:"guid"`
	Name                 string                  `json:"name"`
	ShortDescription     *Message                `json:"shortDescription,omitempty"`
	FullDescription      *Message                `json:"fullDescription,omitempty"`
	Help                 *MultiformatMessage     `json:"help,omitempty"`
	HelpURI              string                  `json:"helpUri"`
	DefaultConfiguration *ReportingConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           json.RawMessage         `json:"properties,omitempty"`
	// Relationships (§3.49.15) map the rule onto taxa — the spec's way of
	// saying "this rule is CWE-327" (gosec, SpotBugs, KICS, ZAP, Flawfinder).
	Relationships []ReportingDescriptorRelationship `json:"relationships"`
}

// ReportingDescriptorRelationship (§3.53) links a rule to a taxon. Kinds
// defaults to ["relevant"] when absent.
type ReportingDescriptorRelationship struct {
	Target ReportingDescriptorReference `json:"target"`
	Kinds  []string                     `json:"kinds"`
}

// ReportingDescriptorReference (§3.52) identifies a rule or taxon by id,
// index or guid within the tool component it names.
type ReportingDescriptorReference struct {
	ID            string                  `json:"id"`
	Index         *int                    `json:"index,omitempty"`
	GUID          string                  `json:"guid"`
	ToolComponent *ToolComponentReference `json:"toolComponent,omitempty"`
}

// ToolComponentReference (§3.54) identifies a driver, extension or taxonomy.
type ToolComponentReference struct {
	Name  string `json:"name"`
	Index *int   `json:"index,omitempty"`
	GUID  string `json:"guid"`
}

type MultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type ReportingConfiguration struct {
	Level string `json:"level"`
}

// reportingDescriptorProperties is the typed view of the rule's properties bag.
// The full bag is preserved verbatim in RuleDescriptor.Properties.
type reportingDescriptorProperties struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
	Precision        string   `json:"precision"`
}

type Result struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex,omitempty"`
	// Rule (§3.27.7) is the spec-complete rule reference; it can point into
	// tool.extensions, which ruleIndex cannot.
	Rule *ReportingDescriptorReference `json:"rule,omitempty"`
	// Taxa (§3.27.8) lists taxa this occurrence falls into beyond what the
	// rule's equal/superset relationships already imply.
	Taxa                []ReportingDescriptorReference `json:"taxa"`
	Level               string                         `json:"level"`
	Message             Message                        `json:"message"`
	Locations           []Location                     `json:"locations"`
	Fingerprints        map[string]string              `json:"fingerprints"`
	PartialFingerprints map[string]string              `json:"partialFingerprints"`
	CodeFlows           []map[string]any               `json:"codeFlows"`
	// Suppressions is SARIF's occurrence-level exclusion record (ADR-023
	// appendix): semgrep/ESLint/checkov emit suppressed results by default,
	// gosec with -track-suppressions. Empty array = active result (that is
	// SARIF semantics, not absence of data); nil = field absent.
	Suppressions []Suppression `json:"suppressions"`
}

// Suppression is one entry of result.suppressions. Kind is "inSource" or
// "external"; Status (optional) is "accepted", "underReview", or "rejected" —
// only a rejected suppression leaves the result active.
type Suppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int32 `json:"startLine"`
	EndLine     int32 `json:"endLine"`
	StartColumn int32 `json:"startColumn"`
	EndColumn   int32 `json:"endColumn"`
}

type Message struct {
	Text string `json:"text"`
}

// RuleDescriptor is the normalized, per-rule catalog record extracted from a
// SARIF reportingDescriptor. It maps 1:1 onto the scan_rules table so rule text
// is stored once instead of copied onto every finding.
type RuleDescriptor struct {
	RuleID           string `json:"rule_id"`
	Name             string `json:"name"`
	ShortDescription string `json:"short_description"`
	FullDescription  string `json:"full_description"`
	HelpURI          string `json:"help_uri"`
	HelpMarkdown     string `json:"help_markdown"`
	DefaultLevel     string `json:"default_level"`
	SecuritySeverity string `json:"security_severity"`
	Precision        string `json:"precision"`
	// CWEs are the rule's classification (ADR-037 §2): taxonomy relationships
	// of kind equal/superset/relevant, then anchored tags.
	CWEs       []int           `json:"cwes"`
	Tags       []string        `json:"tags"`
	Properties json.RawMessage `json:"properties"`
}

type Finding struct {
	Tool         string          `json:"tool"`
	RuleID       string          `json:"rule_id"`
	Severity     string          `json:"severity"`
	FilePath     string          `json:"file_path"`
	StartLine    int32           `json:"start_line"`
	EndLine      int32           `json:"end_line"`
	Message      string          `json:"message"`
	Fingerprint  string          `json:"fingerprint"`
	LocationHash string          `json:"location_hash"`
	Rule         *RuleDescriptor `json:"rule,omitempty"`
	// ResultCWEs come from this occurrence's result.taxa only; they are stored
	// per finding, never on the rule (ADR-037 §2.2).
	ResultCWEs []int `json:"result_cwes,omitempty"`
	// Suppressed marks a result the scanner itself excluded in-source
	// (#nosemgrep, eslint-disable, checkov:skip, #nosec…). It must never
	// become an open finding (ADR-023).
	Suppressed               bool   `json:"suppressed,omitempty"`
	SuppressionKind          string `json:"suppression_kind,omitempty"`
	SuppressionJustification string `json:"suppression_justification,omitempty"`
}

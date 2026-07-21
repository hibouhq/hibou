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
}

type Tool struct {
	Driver ToolComponent `json:"driver"`
}

type ToolComponent struct {
	Name    string                `json:"name"`
	Version string                `json:"version"`
	Rules   []ReportingDescriptor `json:"rules"`
}

type ReportingDescriptor struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name"`
	ShortDescription     *Message                `json:"shortDescription,omitempty"`
	FullDescription      *Message                `json:"fullDescription,omitempty"`
	Help                 *MultiformatMessage     `json:"help,omitempty"`
	HelpURI              string                  `json:"helpUri"`
	DefaultConfiguration *ReportingConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           json.RawMessage         `json:"properties,omitempty"`
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
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex,omitempty"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations"`
	Fingerprints        map[string]string `json:"fingerprints"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	CodeFlows           []map[string]any  `json:"codeFlows"`
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
	RuleID           string          `json:"rule_id"`
	Name             string          `json:"name"`
	ShortDescription string          `json:"short_description"`
	FullDescription  string          `json:"full_description"`
	HelpURI          string          `json:"help_uri"`
	HelpMarkdown     string          `json:"help_markdown"`
	DefaultLevel     string          `json:"default_level"`
	SecuritySeverity string          `json:"security_severity"`
	Precision        string          `json:"precision"`
	CWEs             []string        `json:"cwes"`
	Tags             []string        `json:"tags"`
	Properties       json.RawMessage `json:"properties"`
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
}

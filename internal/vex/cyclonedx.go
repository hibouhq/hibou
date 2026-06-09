package vex

import (
	"encoding/json"
	"fmt"
	"strings"
)

type cycloneDXDocument struct {
	SerialNumber string `json:"serialNumber"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
	} `json:"metadata"`
	Components []struct {
		BOMRef string `json:"bom-ref"`
		PURL   string `json:"purl"`
		Name   string `json:"name"`
	} `json:"components"`
	Vulnerabilities []struct {
		ID       string `json:"id"`
		Analysis struct {
			State         string   `json:"state"`
			Justification string   `json:"justification"`
			Detail        string   `json:"detail"`
			Response      []string `json:"response"`
		} `json:"analysis"`
		Affects []struct {
			Ref string `json:"ref"`
		} `json:"affects"`
	} `json:"vulnerabilities"`
}

func ParseCycloneDX(data []byte) (*ParseResult, error) {
	var doc cycloneDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode cyclonedx document: %w", err)
	}

	components := cycloneDXComponents(doc.Components)

	statements := make([]Statement, 0, len(doc.Vulnerabilities))
	for _, vulnerability := range doc.Vulnerabilities {
		statements = append(statements, cycloneDXStatements(components, vulnerability)...)
	}

	return &ParseResult{
		Format:     FormatCycloneDX,
		Statements: statements,
		DocumentID: strings.TrimSpace(doc.SerialNumber),
		Timestamp:  strings.TrimSpace(doc.Metadata.Timestamp),
	}, nil
}

func cycloneDXComponents(components []struct {
	BOMRef string `json:"bom-ref"`
	PURL   string `json:"purl"`
	Name   string `json:"name"`
}) map[string]string {
	result := make(map[string]string, len(components))
	for _, component := range components {
		key := strings.TrimSpace(component.BOMRef)
		value := strings.TrimSpace(component.PURL)
		if value == "" {
			value = strings.TrimSpace(component.Name)
		}
		if key != "" {
			result[key] = value
		}
	}
	return result
}

func cycloneDXStatements(components map[string]string, vulnerability struct {
	ID       string `json:"id"`
	Analysis struct {
		State         string   `json:"state"`
		Justification string   `json:"justification"`
		Detail        string   `json:"detail"`
		Response      []string `json:"response"`
	} `json:"analysis"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}) []Statement {
	statement, ok := baseCycloneDXStatement(vulnerability)
	if !ok {
		return nil
	}
	if len(vulnerability.Affects) == 0 {
		return []Statement{statement}
	}
	statements := make([]Statement, 0, len(vulnerability.Affects))
	for _, affected := range vulnerability.Affects {
		affectedStatement := statement
		ref := strings.TrimSpace(affected.Ref)
		affectedStatement.ComponentPURL = strings.TrimSpace(components[ref])
		if affectedStatement.ComponentPURL == "" {
			affectedStatement.ComponentPURL = ref
		}
		statements = append(statements, affectedStatement)
	}
	return statements
}

func baseCycloneDXStatement(vulnerability struct {
	ID       string `json:"id"`
	Analysis struct {
		State         string   `json:"state"`
		Justification string   `json:"justification"`
		Detail        string   `json:"detail"`
		Response      []string `json:"response"`
	} `json:"analysis"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}) (Statement, bool) {
	status := mapCycloneDXState(vulnerability.Analysis.State)
	if status == "" {
		return Statement{}, false
	}
	statement := Statement{
		VulnerabilityID: strings.TrimSpace(vulnerability.ID),
		Status:          status,
		Justification:   mapCycloneDXJustification(vulnerability.Analysis.Justification),
		ImpactStatement: strings.TrimSpace(vulnerability.Analysis.Detail),
		ActionStatement: strings.Join(vulnerability.Analysis.Response, ", "),
	}
	if statement.VulnerabilityID == "" {
		return Statement{}, false
	}
	return statement, true
}

func mapCycloneDXState(value string) string {
	switch strings.TrimSpace(value) {
	case "not_affected", "exploitable", "affected":
		if strings.TrimSpace(value) == "exploitable" {
			return StatusAffected
		}
		return strings.TrimSpace(value)
	case "resolved", "fixed":
		return StatusFixed
	case "under_investigation", "in_triage":
		return StatusUnderInvestigation
	default:
		return ""
	}
}

func mapCycloneDXJustification(value string) string {
	switch strings.TrimSpace(value) {
	case "code_not_reachable":
		return JustCodeNotInExecutePath
	case "code_not_present":
		return JustVulnerableCodeNotPresent
	case "component_not_present":
		return JustComponentNotPresent
	case "protected_by_mitigating_control":
		return JustInlineMitigationsExist
	case "requires_configuration":
		return JustCodeCannotBeControlled
	default:
		return normalizeJustification(value)
	}
}

func normalizeJustification(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case JustComponentNotPresent:
		return JustComponentNotPresent
	case JustVulnerableCodeNotPresent, "code_not_present":
		return JustVulnerableCodeNotPresent
	case JustCodeNotInExecutePath, "code_not_reachable":
		return JustCodeNotInExecutePath
	case JustCodeCannotBeControlled, "requires_configuration":
		return JustCodeCannotBeControlled
	case JustInlineMitigationsExist, "protected_by_mitigating_control":
		return JustInlineMitigationsExist
	default:
		return ""
	}
}

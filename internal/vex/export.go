package vex

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var cveIDPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+$`)

type ExportPublisher struct {
	Category  string
	Name      string
	Namespace string
}

type ExportMeta struct {
	Author     string
	Publisher  ExportPublisher
	DocumentID string
	TrackingID string
	TLPLabel   string
	Timestamp  time.Time
}

type csafRevision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

type csafExportDocument struct {
	Document struct {
		Category    string `json:"category"`
		CsafVersion string `json:"csaf_version"`
		Publisher   struct {
			Category  string `json:"category"`
			Name      string `json:"name"`
			Namespace string `json:"namespace,omitempty"`
		} `json:"publisher"`
		Tracking struct {
			ID                 string         `json:"id"`
			CurrentReleaseDate string         `json:"current_release_date"`
			InitialReleaseDate string         `json:"initial_release_date"`
			Status             string         `json:"status"`
			Version            string         `json:"version"`
			RevisionHistory    []csafRevision `json:"revision_history"`
		} `json:"tracking"`
		Distribution struct {
			TLP struct {
				Label string `json:"label"`
			} `json:"tlp"`
		} `json:"distribution"`
	} `json:"document"`
	ProductTree struct {
		Branches []csafBranch `json:"branches"`
	} `json:"product_tree"`
	Vulnerabilities []csafExportVulnerability `json:"vulnerabilities"`
}

type csafExportVulnerability struct {
	CVE string `json:"cve,omitempty"`
	IDs []struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	} `json:"ids,omitempty"`
	ProductStatus struct {
		KnownNotAffected   []string `json:"known_not_affected,omitempty"`
		KnownAffected      []string `json:"known_affected,omitempty"`
		Fixed              []string `json:"fixed,omitempty"`
		UnderInvestigation []string `json:"under_investigation,omitempty"`
	} `json:"product_status"`
	Flags []struct {
		Label      string   `json:"label"`
		ProductIDs []string `json:"product_ids"`
	} `json:"flags,omitempty"`
	Threats []struct {
		Category  string `json:"category"`
		Details   string `json:"details"`
		ProductID string `json:"product_id,omitempty"`
	} `json:"threats,omitempty"`
	Remediations []struct {
		Details    string   `json:"details"`
		ProductIDs []string `json:"product_ids"`
	} `json:"remediations,omitempty"`
}

type csafBuildState struct {
	vendorBranch csafBranch
	productIndex map[string]int
	vulnIndex    map[string]*csafVulnerability
	vulns        []csafVulnerability
}

func ExportOpenVEX(statements []Statement, metadata ExportMeta) ([]byte, error) {
	timestamp := metadata.Timestamp.UTC().Format(time.RFC3339)
	if metadata.Timestamp.IsZero() {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	documentID := strings.TrimSpace(metadata.DocumentID)
	if documentID == "" {
		documentID = fmt.Sprintf("urn:uuid:%d", time.Now().UTC().UnixNano())
	}

	type product struct {
		ID string `json:"@id"`
	}
	type vulnerability struct {
		ID string `json:"@id"`
	}
	type openVEXExportStatement struct {
		Vulnerability   vulnerability `json:"vulnerability"`
		Products        []product     `json:"products,omitempty"`
		Status          string        `json:"status"`
		Justification   string        `json:"justification,omitempty"`
		ImpactStatement string        `json:"impact_statement,omitempty"`
		ActionStatement string        `json:"action_statement,omitempty"`
	}
	type openVEXExportDocument struct {
		Context    string                   `json:"@context"`
		ID         string                   `json:"@id"`
		Author     string                   `json:"author,omitempty"`
		Timestamp  string                   `json:"timestamp"`
		Statements []openVEXExportStatement `json:"statements"`
	}

	items := make([]openVEXExportStatement, 0, len(statements))
	for _, statement := range statements {
		item := openVEXExportStatement{
			Vulnerability:   vulnerability{ID: strings.TrimSpace(statement.VulnerabilityID)},
			Status:          strings.TrimSpace(statement.Status),
			Justification:   strings.TrimSpace(statement.Justification),
			ImpactStatement: strings.TrimSpace(statement.ImpactStatement),
			ActionStatement: strings.TrimSpace(statement.ActionStatement),
		}
		if component := strings.TrimSpace(statement.ComponentPURL); component != "" {
			item.Products = []product{{ID: component}}
		}
		items = append(items, item)
	}

	return json.MarshalIndent(openVEXExportDocument{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         documentID,
		Author:     strings.TrimSpace(metadata.Author),
		Timestamp:  timestamp,
		Statements: items,
	}, "", "  ")
}

func ExportCSAF(statements []Statement, metadata ExportMeta) ([]byte, error) {
	timestamp, documentID, trackingID, tlpLabel := normalizeCSAFMetadata(metadata)
	vendorName := csafVendorName(metadata)
	state := newCSAFBuildState(vendorName)
	for index, statement := range statements {
		addCSAFStatement(&state, statement, index)
	}
	doc := buildCSAFDocument(metadata, timestamp, trackingID, tlpLabel, vendorName, documentID, state)
	return json.MarshalIndent(doc, "", "  ")
}

func normalizeCSAFMetadata(metadata ExportMeta) (string, string, string, string) {
	timestamp := metadata.Timestamp.UTC().Format(time.RFC3339)
	if metadata.Timestamp.IsZero() {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	documentID := strings.TrimSpace(metadata.DocumentID)
	if documentID == "" {
		documentID = fmt.Sprintf("csaf-%d", time.Now().UTC().UnixNano())
	}
	trackingID := strings.TrimSpace(metadata.TrackingID)
	if trackingID == "" {
		trackingID = documentID
	}
	tlpLabel := strings.TrimSpace(metadata.TLPLabel)
	if tlpLabel == "" {
		tlpLabel = "TLP:CLEAR"
	}
	return timestamp, documentID, trackingID, tlpLabel
}

func csafVendorName(metadata ExportMeta) string {
	vendorName := strings.TrimSpace(metadata.Publisher.Name)
	if vendorName == "" {
		return "hibou"
	}
	return vendorName
}

func newCSAFBuildState(vendorName string) csafBuildState {
	return csafBuildState{
		vendorBranch: csafBranch{Category: "vendor", Name: vendorName},
		productIndex: make(map[string]int),
		vulnIndex:    make(map[string]*csafVulnerability),
		vulns:        make([]csafVulnerability, 0),
	}
}

func addCSAFStatement(state *csafBuildState, statement Statement, index int) {
	productID := fmt.Sprintf("product-%d", index+1)
	productName, productVersion := csafProductIdentity(statement)
	productBranchIndex := ensureCSAFProductBranch(state, productName, productVersion)
	appendCSAFProductVersion(state, productBranchIndex, productID, productName, productVersion)
	entry := ensureCSAFVulnerability(state, strings.TrimSpace(statement.VulnerabilityID))
	applyCSAFStatus(entry, statement.Status, productID)
	appendCSAFStatementDetails(entry, statement, productID)
}

func ensureCSAFProductBranch(state *csafBuildState, productName, productVersion string) int {
	productNameKey := productName + "@" + productVersion
	if productBranchIndex, ok := state.productIndex[productNameKey]; ok {
		return productBranchIndex
	}
	state.vendorBranch.Branches = append(state.vendorBranch.Branches, csafBranch{Category: "product_name", Name: productName})
	productBranchIndex := len(state.vendorBranch.Branches) - 1
	state.productIndex[productNameKey] = productBranchIndex
	return productBranchIndex
}

func appendCSAFProductVersion(state *csafBuildState, productBranchIndex int, productID, productName, productVersion string) {
	versionName := productVersion
	if versionName == "" {
		versionName = "all versions"
	}
	state.vendorBranch.Branches[productBranchIndex].Branches = append(state.vendorBranch.Branches[productBranchIndex].Branches, csafBranch{
		Category: "product_version",
		Name:     versionName,
		Product:  &csafProduct{ProductID: productID, Name: productName},
	})
}

func ensureCSAFVulnerability(state *csafBuildState, key string) *csafVulnerability {
	if entry, ok := state.vulnIndex[key]; ok {
		return entry
	}
	vuln := csafVulnerability{}
	if cveIDPattern.MatchString(key) {
		vuln.CVE = strings.ToUpper(key)
	} else if key != "" {
		vuln.IDs = []struct {
			SystemName string `json:"system_name"`
			Text       string `json:"text"`
		}{{SystemName: identifierSystemName(key), Text: key}}
	}
	state.vulns = append(state.vulns, vuln)
	entry := &state.vulns[len(state.vulns)-1]
	state.vulnIndex[key] = entry
	return entry
}

func applyCSAFStatus(entry *csafVulnerability, status, productID string) {
	switch strings.TrimSpace(status) {
	case StatusNotAffected:
		entry.ProductStatus.KnownNotAffected = append(entry.ProductStatus.KnownNotAffected, productID)
	case StatusAffected:
		entry.ProductStatus.KnownAffected = append(entry.ProductStatus.KnownAffected, productID)
	case StatusFixed:
		entry.ProductStatus.Fixed = append(entry.ProductStatus.Fixed, productID)
	case StatusUnderInvestigation:
		entry.ProductStatus.UnderInvestigation = append(entry.ProductStatus.UnderInvestigation, productID)
	}
}

func appendCSAFStatementDetails(entry *csafVulnerability, statement Statement, productID string) {
	if justification := strings.TrimSpace(statement.Justification); justification != "" {
		entry.Flags = append(entry.Flags, struct {
			Label      string   `json:"label"`
			ProductIDs []string `json:"product_ids"`
		}{Label: justification, ProductIDs: []string{productID}})
	}
	if impact := strings.TrimSpace(statement.ImpactStatement); impact != "" {
		entry.Threats = append(entry.Threats, struct {
			Category  string `json:"category"`
			Details   string `json:"details"`
			ProductID string `json:"product_id"`
		}{Category: "impact", Details: impact})
	}
	if action := strings.TrimSpace(statement.ActionStatement); action != "" {
		entry.Remediations = append(entry.Remediations, struct {
			Details    string   `json:"details"`
			ProductIDs []string `json:"product_ids"`
		}{Details: action, ProductIDs: []string{productID}})
	}
}

func buildCSAFDocument(metadata ExportMeta, timestamp, trackingID, tlpLabel, vendorName, documentID string, state csafBuildState) csafExportDocument {
	var doc csafExportDocument
	doc.Document.Category = "csaf_vex"
	doc.Document.CsafVersion = "2.0"
	doc.Document.Publisher.Category = strings.TrimSpace(metadata.Publisher.Category)
	if doc.Document.Publisher.Category == "" {
		doc.Document.Publisher.Category = "vendor"
	}
	doc.Document.Publisher.Name = vendorName
	doc.Document.Publisher.Namespace = strings.TrimSpace(metadata.Publisher.Namespace)
	doc.Document.Tracking.ID = trackingID
	doc.Document.Tracking.CurrentReleaseDate = timestamp
	doc.Document.Tracking.InitialReleaseDate = timestamp
	doc.Document.Tracking.Status = "final"
	doc.Document.Tracking.Version = "1"
	doc.Document.Tracking.RevisionHistory = []csafRevision{{Date: timestamp, Number: "1", Summary: "Initial release"}}
	doc.Document.Distribution.TLP.Label = tlpLabel
	doc.ProductTree.Branches = []csafBranch{state.vendorBranch}
	doc.Vulnerabilities = exportCSAFVulnerabilities(state.vulns)
	_ = documentID
	return doc
}

func exportCSAFVulnerabilities(vulns []csafVulnerability) []csafExportVulnerability {
	exported := make([]csafExportVulnerability, 0, len(vulns))
	for _, vuln := range vulns {
		var item csafExportVulnerability
		item.CVE = vuln.CVE
		item.IDs = append(item.IDs, vuln.IDs...)
		item.ProductStatus.KnownNotAffected = append(item.ProductStatus.KnownNotAffected, vuln.ProductStatus.KnownNotAffected...)
		item.ProductStatus.KnownAffected = append(item.ProductStatus.KnownAffected, vuln.ProductStatus.KnownAffected...)
		item.ProductStatus.Fixed = append(item.ProductStatus.Fixed, vuln.ProductStatus.Fixed...)
		item.ProductStatus.UnderInvestigation = append(item.ProductStatus.UnderInvestigation, vuln.ProductStatus.UnderInvestigation...)
		for _, flag := range vuln.Flags {
			item.Flags = append(item.Flags, struct {
				Label      string   `json:"label"`
				ProductIDs []string `json:"product_ids"`
			}{Label: flag.Label, ProductIDs: append([]string(nil), flag.ProductIDs...)})
		}
		for _, threat := range vuln.Threats {
			item.Threats = append(item.Threats, struct {
				Category  string `json:"category"`
				Details   string `json:"details"`
				ProductID string `json:"product_id,omitempty"`
			}{Category: threat.Category, Details: threat.Details, ProductID: threat.ProductID})
		}
		for _, remediation := range vuln.Remediations {
			item.Remediations = append(item.Remediations, struct {
				Details    string   `json:"details"`
				ProductIDs []string `json:"product_ids"`
			}{Details: remediation.Details, ProductIDs: append([]string(nil), remediation.ProductIDs...)})
		}
		exported = append(exported, item)
	}
	return exported
}

func identifierSystemName(vulnerabilityID string) string {
	trimmed := strings.TrimSpace(vulnerabilityID)
	if trimmed == "" {
		return "hibou"
	}
	if index := strings.Index(trimmed, "-"); index > 0 {
		return strings.ToUpper(trimmed[:index])
	}
	return "hibou"
}

func csafProductIdentity(statement Statement) (string, string) {
	component := strings.TrimSpace(statement.ComponentPURL)
	if component == "" {
		if supplier := strings.TrimSpace(statement.Supplier); supplier != "" {
			return supplier, ""
		}
		return "org-wide", ""
	}
	name := component
	version := ""
	if atIndex := strings.LastIndex(component, "@"); atIndex > strings.LastIndex(component, "/") {
		name = component[:atIndex]
		version = component[atIndex+1:]
	}
	if slashIndex := strings.LastIndex(name, "/"); slashIndex >= 0 && slashIndex < len(name)-1 {
		name = name[slashIndex+1:]
	}
	if name == "" {
		name = component
	}
	return name, version
}

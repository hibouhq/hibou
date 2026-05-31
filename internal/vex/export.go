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

	type product struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
	}
	type branch struct {
		Category string   `json:"category"`
		Name     string   `json:"name"`
		Product  *product `json:"product,omitempty"`
		Branches []branch `json:"branches,omitempty"`
	}
	type tlp struct {
		Label string `json:"label"`
	}
	type distribution struct {
		TLP tlp `json:"tlp"`
	}
	type flag struct {
		Label      string   `json:"label"`
		ProductIDs []string `json:"product_ids,omitempty"`
	}
	type identifier struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	}
	type threat struct {
		Category string `json:"category"`
		Details  string `json:"details"`
	}
	type remediation struct {
		Category   string   `json:"category"`
		Details    string   `json:"details"`
		ProductIDs []string `json:"product_ids,omitempty"`
	}
	type vulnerability struct {
		CVE           string              `json:"cve,omitempty"`
		IDs           []identifier        `json:"ids,omitempty"`
		ProductStatus map[string][]string `json:"product_status"`
		Flags         []flag              `json:"flags,omitempty"`
		Threats       []threat            `json:"threats,omitempty"`
		Remediations  []remediation       `json:"remediations,omitempty"`
	}
	type revision struct {
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
				ID                 string     `json:"id"`
				CurrentReleaseDate string     `json:"current_release_date"`
				InitialReleaseDate string     `json:"initial_release_date"`
				Status             string     `json:"status"`
				Version            string     `json:"version"`
				RevisionHistory    []revision `json:"revision_history"`
			} `json:"tracking"`
			Distribution distribution `json:"distribution"`
		} `json:"document"`
		ProductTree struct {
			Branches []branch `json:"branches"`
		} `json:"product_tree"`
		Vulnerabilities []vulnerability `json:"vulnerabilities"`
	}

	vendorName := strings.TrimSpace(metadata.Publisher.Name)
	if vendorName == "" {
		vendorName = "hibou"
	}
	branches := make([]branch, 0, 1)
	vulnIndex := make(map[string]*vulnerability)
	vulns := make([]vulnerability, 0)
	vendorBranch := branch{Category: "vendor", Name: vendorName}
	productIndex := make(map[string]int)

	for index, statement := range statements {
		productID := fmt.Sprintf("product-%d", index+1)
		productName, productVersion := csafProductIdentity(statement)
		productNameKey := productName + "@" + productVersion
		productBranchIndex, ok := productIndex[productNameKey]
		if !ok {
			vendorBranch.Branches = append(vendorBranch.Branches, branch{Category: "product_name", Name: productName})
			productBranchIndex = len(vendorBranch.Branches) - 1
			productIndex[productNameKey] = productBranchIndex
		}
		versionName := productVersion
		if versionName == "" {
			versionName = "all versions"
		}
		vendorBranch.Branches[productBranchIndex].Branches = append(vendorBranch.Branches[productBranchIndex].Branches, branch{
			Category: "product_version",
			Name:     versionName,
			Product:  &product{ProductID: productID, Name: productName},
		})

		key := strings.TrimSpace(statement.VulnerabilityID)
		entry, ok := vulnIndex[key]
		if !ok {
			vuln := vulnerability{ProductStatus: map[string][]string{}}
			if cveIDPattern.MatchString(key) {
				vuln.CVE = strings.ToUpper(key)
			} else if key != "" {
				vuln.IDs = []identifier{{SystemName: identifierSystemName(key), Text: key}}
			}
			vulns = append(vulns, vuln)
			entry = &vulns[len(vulns)-1]
			vulnIndex[key] = entry
		}
		switch strings.TrimSpace(statement.Status) {
		case StatusNotAffected:
			entry.ProductStatus["known_not_affected"] = append(entry.ProductStatus["known_not_affected"], productID)
		case StatusAffected:
			entry.ProductStatus["known_affected"] = append(entry.ProductStatus["known_affected"], productID)
		case StatusFixed:
			entry.ProductStatus["fixed"] = append(entry.ProductStatus["fixed"], productID)
		case StatusUnderInvestigation:
			entry.ProductStatus["under_investigation"] = append(entry.ProductStatus["under_investigation"], productID)
		}
		if justification := strings.TrimSpace(statement.Justification); justification != "" {
			entry.Flags = append(entry.Flags, flag{Label: justification, ProductIDs: []string{productID}})
		}
		if impact := strings.TrimSpace(statement.ImpactStatement); impact != "" {
			entry.Threats = append(entry.Threats, threat{Category: "impact", Details: impact})
		}
		if action := strings.TrimSpace(statement.ActionStatement); action != "" {
			entry.Remediations = append(entry.Remediations, remediation{Category: "mitigation", Details: action, ProductIDs: []string{productID}})
		}
	}

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
	doc.Document.Tracking.RevisionHistory = []revision{{Date: timestamp, Number: "1", Summary: "Initial release"}}
	doc.Document.Distribution.TLP.Label = tlpLabel
	doc.ProductTree.Branches = append(branches, vendorBranch)
	doc.Vulnerabilities = vulns

	return json.MarshalIndent(doc, "", "  ")
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

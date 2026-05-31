package vex

import (
	"encoding/json"
	"fmt"
	"strings"
)

type csafDocument struct {
	Document struct {
		Category string `json:"category"`
		Tracking struct {
			ID                 string `json:"id"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
		Publisher struct {
			Name string `json:"name"`
		} `json:"publisher"`
	} `json:"document"`
	ProductTree struct {
		Branches []csafBranch `json:"branches"`
	} `json:"product_tree"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafBranch struct {
	Category                    string               `json:"category"`
	Name                        string               `json:"name"`
	Product                     *csafProduct         `json:"product"`
	ProductIdentificationHelper *csafProductIDHelper `json:"product_identification_helper,omitempty"`
	Branches                    []csafBranch         `json:"branches"`
}

type csafProduct struct {
	ProductID                   string               `json:"product_id"`
	Name                        string               `json:"name"`
	ProductRef                  string               `json:"product_ref"`
	ProductIdentificationHelper *csafProductIDHelper `json:"product_identification_helper,omitempty"`
}

type csafProductIDHelper struct {
	PURL string `json:"purl"`
}

type csafVulnerability struct {
	CVE string `json:"cve"`
	IDs []struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	} `json:"ids"`
	ProductStatus struct {
		KnownNotAffected   []string `json:"known_not_affected"`
		KnownAffected      []string `json:"known_affected"`
		Fixed              []string `json:"fixed"`
		UnderInvestigation []string `json:"under_investigation"`
	} `json:"product_status"`
	Flags []struct {
		Label      string   `json:"label"`
		ProductIDs []string `json:"product_ids"`
	} `json:"flags"`
	Threats []struct {
		Category  string `json:"category"`
		Details   string `json:"details"`
		ProductID string `json:"product_id"`
	} `json:"threats"`
	Remediations []struct {
		Details    string   `json:"details"`
		ProductIDs []string `json:"product_ids"`
	} `json:"remediations"`
}

func ParseCSAF(data []byte) (*ParseResult, error) {
	var doc csafDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode csaf document: %w", err)
	}
	if strings.TrimSpace(doc.Document.Category) != "csaf_vex" {
		return nil, fmt.Errorf("document is not csaf vex")
	}

	products := make(map[string]csafProductMatch)
	for _, branch := range doc.ProductTree.Branches {
		collectCSAFProducts(branch, products)
	}

	statements := make([]Statement, 0)
	for _, vuln := range doc.Vulnerabilities {
		statements = append(statements, buildCSAFStatements(vuln, products)...)
	}

	return &ParseResult{
		Format:     FormatCSAF,
		Statements: statements,
		DocumentID: strings.TrimSpace(doc.Document.Tracking.ID),
		Timestamp:  strings.TrimSpace(doc.Document.Tracking.CurrentReleaseDate),
	}, nil
}

type csafProductMatch struct {
	Name string
	PURL string
}

func collectCSAFProducts(branch csafBranch, products map[string]csafProductMatch) {
	if branch.Product != nil {
		id := strings.TrimSpace(branch.Product.ProductID)
		if id == "" {
			id = strings.TrimSpace(branch.Product.ProductRef)
		}
		if id != "" {
			productName := strings.TrimSpace(branch.Product.Name)
			if productName == "" {
				productName = strings.TrimSpace(branch.Name)
			}
			products[id] = csafProductMatch{
				Name: productName,
				PURL: firstNonEmpty(
					productHelperPURL(branch.Product.ProductIdentificationHelper),
					productHelperPURL(branch.ProductIdentificationHelper),
				),
			}
		}
	}
	for _, child := range branch.Branches {
		collectCSAFProducts(child, products)
	}
}

func buildCSAFStatements(vuln csafVulnerability, products map[string]csafProductMatch) []Statement {
	entries := make([]Statement, 0)
	vulnerabilityID := csafVulnerabilityID(vuln)
	appendEntries := func(ids []string, status string) {
		for _, id := range ids {
			product := products[strings.TrimSpace(id)]
			statement := Statement{
				VulnerabilityID: vulnerabilityID,
				Status:          status,
				ComponentPURL:   strings.TrimSpace(product.PURL),
				Supplier:        strings.TrimSpace(product.Name),
			}
			statement.Justification = csafJustificationForProduct(vuln.Flags, id)
			statement.ImpactStatement = csafImpactForProduct(vuln.Threats, id)
			statement.ActionStatement = csafRemediationForProduct(vuln.Remediations, id)
			if statement.VulnerabilityID == "" {
				continue
			}
			entries = append(entries, statement)
		}
	}

	appendEntries(vuln.ProductStatus.KnownNotAffected, StatusNotAffected)
	appendEntries(vuln.ProductStatus.KnownAffected, StatusAffected)
	appendEntries(vuln.ProductStatus.Fixed, StatusFixed)
	appendEntries(vuln.ProductStatus.UnderInvestigation, StatusUnderInvestigation)
	return entries
}

func csafVulnerabilityID(vuln csafVulnerability) string {
	if trimmed := strings.TrimSpace(vuln.CVE); trimmed != "" {
		return trimmed
	}
	for _, identifier := range vuln.IDs {
		if trimmed := strings.TrimSpace(identifier.Text); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func productHelperPURL(helper *csafProductIDHelper) string {
	if helper == nil {
		return ""
	}
	return strings.TrimSpace(helper.PURL)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func csafJustificationForProduct(flags []struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}, productID string) string {
	for _, flag := range flags {
		if len(flag.ProductIDs) == 0 {
			return normalizeJustification(flag.Label)
		}
		for _, candidate := range flag.ProductIDs {
			if strings.TrimSpace(candidate) == strings.TrimSpace(productID) {
				return normalizeJustification(flag.Label)
			}
		}
	}
	return ""
}

func csafImpactForProduct(threats []struct {
	Category  string `json:"category"`
	Details   string `json:"details"`
	ProductID string `json:"product_id"`
}, productID string) string {
	for _, threat := range threats {
		if strings.TrimSpace(threat.Category) != "impact" {
			continue
		}
		if threat.ProductID == "" || strings.TrimSpace(threat.ProductID) == strings.TrimSpace(productID) {
			return strings.TrimSpace(threat.Details)
		}
	}
	return ""
}

func csafRemediationForProduct(remediations []struct {
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}, productID string) string {
	for _, remediation := range remediations {
		if len(remediation.ProductIDs) == 0 {
			return strings.TrimSpace(remediation.Details)
		}
		for _, candidate := range remediation.ProductIDs {
			if strings.TrimSpace(candidate) == strings.TrimSpace(productID) {
				return strings.TrimSpace(remediation.Details)
			}
		}
	}
	return ""
}

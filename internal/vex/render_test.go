package vex

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func productStatements() []Statement {
	return []Statement{
		{
			VulnerabilityID: "CVE-2026-1234",
			Aliases:         []string{"GHSA-aaaa-bbbb-cccc"},
			Status:          StatusAffected,
			ActionStatement: "Upgrade to 9.0.3",
			ComponentPURL:   "pkg:maven/org.example/parser@2.3.1",
			ProductPURL:     "pkg:generic/example/product",
			ProductName:     "product",
			ProductVersion:  "8.4.1",
		},
		{
			VulnerabilityID: "CVE-2026-1234",
			Aliases:         []string{"GHSA-aaaa-bbbb-cccc"},
			Status:          StatusNotAffected,
			Justification:   JustCodeNotInExecutePath,
			ImpactStatement: "The parser only reads trusted configuration.",
			ComponentPURL:   "pkg:maven/org.example/parser@2.3.1",
			ProductPURL:     "pkg:generic/example/product",
			ProductName:     "product",
			ProductVersion:  "9.0.2",
			ProductCPE:      "cpe:2.3:a:example:product:9.0.2:*:*:*:*:*:*:*",
		},
	}
}

func productMeta() ExportMeta {
	return ExportMeta{
		Author:     "Example Corp Product Security",
		Publisher:  ExportPublisher{Category: "vendor", Name: "Example Corp", Namespace: "https://example.com"},
		DocumentID: "urn:uuid:3f9c1f0e-0000-4000-8000-000000000001",
		TrackingID: "EX-2026-001",
		TLPLabel:   "TLP:AMBER",
		Timestamp:  time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC),
		Title:      "CVE-2026-1234 in product",
	}
}

// The same inputs must give the same bytes in every format, whatever the
// order the statements arrive in: a sent document is verified by re-rendering.
func TestExportersAreDeterministic(t *testing.T) {
	forward := productStatements()
	reversed := []Statement{forward[1], forward[0]}
	for name, render := range map[string]func([]Statement, ExportMeta) ([]byte, error){
		"openvex":   ExportOpenVEX,
		"cyclonedx": ExportCycloneDX,
		"csaf":      ExportCSAF,
		"advisory": func(statements []Statement, meta ExportMeta) ([]byte, error) {
			return ExportCSAFAdvisory(statements, meta, []AdvisoryInfo{{VulnerabilityID: "CVE-2026-1234", Description: "XXE in parser", CVSSVersion: "3.1", CVSSScore: 8.1, CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", ExploitStatus: "Exploitation observed"}})
		},
	} {
		first, err := render(forward, productMeta())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		second, err := render(reversed, productMeta())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("%s: output depends on statement order", name)
		}
	}
}

func TestExportOpenVEXNamesTheReleaseAsProductAndTheComponentAsSubcomponent(t *testing.T) {
	payload, err := ExportOpenVEX(productStatements(), productMeta())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Statements []struct {
			Vulnerability struct {
				Name    string   `json:"name"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerability"`
			Products []struct {
				ID            string `json:"@id"`
				Subcomponents []struct {
					ID string `json:"@id"`
				} `json:"subcomponents"`
			} `json:"products"`
			Status        string `json:"status"`
			Justification string `json:"justification"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("statements = %d", len(doc.Statements))
	}
	first := doc.Statements[0]
	if first.Products[0].ID != "pkg:generic/example/product@8.4.1" || first.Products[0].Subcomponents[0].ID != "pkg:maven/org.example/parser@2.3.1" {
		t.Fatalf("product axis wrong: %+v", first.Products)
	}
	if first.Vulnerability.Name != "CVE-2026-1234" || len(first.Vulnerability.Aliases) != 1 {
		t.Fatalf("vulnerability wrong: %+v", first.Vulnerability)
	}
	if doc.Statements[1].Justification != JustCodeNotInExecutePath {
		t.Fatalf("justification lost: %+v", doc.Statements[1])
	}
}

func TestExportRefusesNotAffectedWithoutJustification(t *testing.T) {
	statements := []Statement{{VulnerabilityID: "CVE-2026-1", Status: StatusNotAffected, ProductPURL: "pkg:generic/example/product"}}
	if _, err := ExportOpenVEX(statements, productMeta()); err == nil {
		t.Fatal("OpenVEX accepted not_affected without justification or impact statement")
	}
	if _, err := ExportCSAF(statements, productMeta()); err == nil {
		t.Fatal("CSAF accepted not_affected without justification or impact statement")
	}
}

func TestExportCSAFAdvisoryCarriesStatusFlagsScoresAndThreats(t *testing.T) {
	payload, err := ExportCSAFAdvisory(productStatements(), productMeta(), []AdvisoryInfo{{
		VulnerabilityID: "CVE-2026-1234", Title: "XXE", Description: "XXE in parser", CVSSVersion: "3.1", CVSSScore: 8.1,
		CVSSVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", ExploitStatus: "Exploitation observed",
	}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, want := range []string{
		`"category": "csaf_security_advisory"`,
		`"label": "AMBER"`,
		`"known_affected": [`,
		`"PRODUCT-8.4.1"`,
		`"known_not_affected": [`,
		`"label": "vulnerable_code_not_in_execute_path"`,
		`"category": "exploit_status"`,
		`"baseSeverity": "HIGH"`,
		`"cpe": "cpe:2.3:a:example:product:9.0.2:*:*:*:*:*:*:*"`,
		`"purl": "pkg:generic/example/product@9.0.2"`,
		`"version": "` + RendererVersion + `"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("advisory lacks %s:\n%s", want, text)
		}
	}
	if strings.Contains(text, "null") {
		t.Fatalf("CSAF output carries null values:\n%s", text)
	}
}

func TestExportCycloneDXUsesSingleProductAsMetadataComponent(t *testing.T) {
	statements := productStatements()[1:]
	payload, err := ExportCycloneDX(statements, productMeta())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Component struct {
				PURL string `json:"purl"`
			} `json:"component"`
		} `json:"metadata"`
		Vulnerabilities []struct {
			Analysis struct {
				State         string `json:"state"`
				Justification string `json:"justification"`
			} `json:"analysis"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Component.PURL != "pkg:generic/example/product@9.0.2" {
		t.Fatalf("metadata component = %q", doc.Metadata.Component.PURL)
	}
	if doc.SerialNumber != productMeta().DocumentID {
		t.Fatalf("serial = %q", doc.SerialNumber)
	}
	vuln := doc.Vulnerabilities[0]
	if vuln.Analysis.State != "not_affected" || vuln.Analysis.Justification != "code_not_reachable" || vuln.Affects[0].Ref != "pkg:maven/org.example/parser@2.3.1" {
		t.Fatalf("vulnerability = %+v", vuln)
	}
}

func TestCSAFTLPLabelUsesCSAF2Vocabulary(t *testing.T) {
	for in, want := range map[string]string{"TLP:CLEAR": "WHITE", "": "WHITE", "tlp:green": "GREEN", "TLP:AMBER+STRICT": "AMBER", "RED": "RED"} {
		if got := csafTLPLabel(in); got != want {
			t.Fatalf("csafTLPLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// CSAF 2.0 profiles require notes on every vulnerability and a remediation
// for every known-affected product.
func TestExportCSAFMeetsProfileMandatoryFields(t *testing.T) {
	statements := []Statement{{VulnerabilityID: "CVE-2026-9", Status: StatusAffected, ProductPURL: "pkg:generic/example/product", ProductVersion: "1.0.0"}}
	payload, err := ExportCSAF(statements, productMeta())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vulnerabilities []struct {
			Notes []struct {
				Category string `json:"category"`
			} `json:"notes"`
			Remediations []struct {
				Category   string   `json:"category"`
				ProductIDs []string `json:"product_ids"`
			} `json:"remediations"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatal(err)
	}
	vuln := doc.Vulnerabilities[0]
	if len(vuln.Notes) == 0 {
		t.Fatal("vulnerability without notes")
	}
	if len(vuln.Remediations) != 1 || vuln.Remediations[0].Category != "none_available" || len(vuln.Remediations[0].ProductIDs) != 1 {
		t.Fatalf("remediations = %+v", vuln.Remediations)
	}
}

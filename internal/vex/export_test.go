package vex

import (
	"encoding/json"
	"testing"
	"time"
)

func TestExportCSAFUsesIDsForNonCVEsAndRequiredMetadata(t *testing.T) {
	payload, err := ExportCSAF([]Statement{{
		VulnerabilityID: "GHSA-abcd-1234",
		Status:          StatusAffected,
		ComponentPURL:   "pkg:golang/github.com/acme/lib@1.2.3",
	}}, ExportMeta{
		Author: "analyst",
		Publisher: ExportPublisher{
			Category:  "tool",
			Name:      "Acme",
			Namespace: "https://example.com/orgs/github/acme",
		},
		DocumentID: "doc-1",
		TrackingID: "track-1",
		TLPLabel:   "TLP:CLEAR",
		Timestamp:  time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ExportCSAF returned error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("unmarshal exported CSAF: %v", err)
	}
	document := doc["document"].(map[string]any)
	if document["csaf_version"] != "2.0" {
		t.Fatalf("expected csaf_version 2.0, got %#v", document["csaf_version"])
	}
	publisher := document["publisher"].(map[string]any)
	if publisher["category"] != "tool" || publisher["name"] != "Acme" {
		t.Fatalf("unexpected publisher metadata: %#v", publisher)
	}
	tracking := document["tracking"].(map[string]any)
	if tracking["id"] != "track-1" {
		t.Fatalf("expected tracking id, got %#v", tracking)
	}
	revisions := tracking["revision_history"].([]any)
	if len(revisions) != 1 {
		t.Fatalf("expected single revision history entry, got %#v", revisions)
	}
	distribution := document["distribution"].(map[string]any)
	if distribution["tlp"].(map[string]any)["label"] != "TLP:CLEAR" {
		t.Fatalf("expected TLP:CLEAR tlp label, got %#v", distribution)
	}
	branches := doc["product_tree"].(map[string]any)["branches"].([]any)
	vendor := branches[0].(map[string]any)
	if vendor["category"] != "vendor" {
		t.Fatalf("expected vendor category branch, got %#v", vendor)
	}
	vulns := doc["vulnerabilities"].([]any)
	vulnerability := vulns[0].(map[string]any)
	if _, ok := vulnerability["cve"]; ok {
		t.Fatalf("expected non-CVE advisory to use ids array, got %#v", vulnerability)
	}
	ids := vulnerability["ids"].([]any)
	if ids[0].(map[string]any)["text"] != "GHSA-abcd-1234" {
		t.Fatalf("expected GHSA identifier in ids, got %#v", ids)
	}
}

func TestParseCSAFUsesRealPURLAndLeavesComponentEmptyWithoutOne(t *testing.T) {
	result, err := ParseCSAF([]byte(`{
	  "document": {
	    "category": "csaf_vex",
	    "tracking": {"id": "doc-1", "current_release_date": "2026-05-28T12:00:00Z"},
	    "publisher": {"name": "Acme"}
	  },
	  "product_tree": {
	    "branches": [
	      {
	        "category": "vendor",
	        "name": "Acme",
	        "branches": [
	          {
	            "category": "product_name",
	            "name": "Widget",
	            "branches": [
	              {
	                "category": "product_version",
	                "name": "1.0.0",
	                "product": {
	                  "product_id": "prod-1",
	                  "name": "Widget 1.0.0",
	                  "product_identification_helper": {"purl": "pkg:golang/github.com/acme/widget@1.0.0"}
	                }
	              },
	              {
	                "category": "product_version",
	                "name": "2.0.0",
	                "product": {
	                  "product_id": "prod-2",
	                  "name": "Widget 2.0.0"
	                }
	              }
	            ]
	          }
	        ]
	      }
	    ]
	  },
	  "vulnerabilities": [
	    {
	      "ids": [{"system_name": "GHSA", "text": "GHSA-abcd-1234"}],
	      "product_status": {
	        "known_not_affected": ["prod-1"],
	        "known_affected": ["prod-2"]
	      },
	      "flags": [{"label": "component_not_present", "product_ids": ["prod-1"]}]
	    }
	  ]
	}`))
	if err != nil {
		t.Fatalf("ParseCSAF returned error: %v", err)
	}
	if len(result.Statements) != 2 {
		t.Fatalf("expected two CSAF statements, got %#v", result.Statements)
	}
	if result.Statements[0].ComponentPURL != "pkg:golang/github.com/acme/widget@1.0.0" {
		t.Fatalf("expected real purl for first product, got %#v", result.Statements[0])
	}
	if result.Statements[1].ComponentPURL != "" {
		t.Fatalf("expected empty component purl when CSAF omitted helper, got %#v", result.Statements[1])
	}
	if result.Statements[1].Supplier != "Widget 2.0.0" {
		t.Fatalf("expected product name in supplier field, got %#v", result.Statements[1])
	}
	if result.Statements[0].VulnerabilityID != "GHSA-abcd-1234" {
		t.Fatalf("expected vulnerability id from ids array, got %#v", result.Statements[0])
	}
}

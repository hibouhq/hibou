package vex

import "testing"

func TestParseOpenVEXFansOutProducts(t *testing.T) {
	result, err := ParseOpenVEX([]byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "@id": "doc-1",
	  "timestamp": "2026-05-29T10:00:00Z",
	  "statements": [
	    {
	      "vulnerability": {"@id": "CVE-2026-0001"},
	      "products": [
	        {"@id": "pkg:golang/example/one@1.0.0"},
	        {"@id": "pkg:golang/example/two@2.0.0"}
	      ],
	      "status": "affected"
	    }
	  ]
	}`))
	if err != nil {
		t.Fatalf("ParseOpenVEX returned error: %v", err)
	}
	if len(result.Statements) != 2 {
		t.Fatalf("expected two statements, got %#v", result.Statements)
	}
	if result.Statements[0].ComponentPURL != "pkg:golang/example/one@1.0.0" {
		t.Fatalf("unexpected first component purl: %#v", result.Statements[0])
	}
	if result.Statements[1].ComponentPURL != "pkg:golang/example/two@2.0.0" {
		t.Fatalf("unexpected second component purl: %#v", result.Statements[1])
	}
}

func TestParseCycloneDXFansOutAffectedComponents(t *testing.T) {
	result, err := ParseCycloneDX([]byte(`{
	  "serialNumber": "urn:uuid:doc-1",
	  "metadata": {"timestamp": "2026-05-29T10:00:00Z"},
	  "components": [
	    {"bom-ref": "component-a", "purl": "pkg:golang/example/a@1.0.0"},
	    {"bom-ref": "component-b", "purl": "pkg:golang/example/b@2.0.0"}
	  ],
	  "vulnerabilities": [
	    {
	      "id": "CVE-2026-0002",
	      "analysis": {"state": "affected"},
	      "affects": [
	        {"ref": "component-a"},
	        {"ref": "component-b"}
	      ]
	    }
	  ]
	}`))
	if err != nil {
		t.Fatalf("ParseCycloneDX returned error: %v", err)
	}
	if len(result.Statements) != 2 {
		t.Fatalf("expected two statements, got %#v", result.Statements)
	}
	if result.Statements[0].ComponentPURL != "pkg:golang/example/a@1.0.0" {
		t.Fatalf("unexpected first component purl: %#v", result.Statements[0])
	}
	if result.Statements[1].ComponentPURL != "pkg:golang/example/b@2.0.0" {
		t.Fatalf("unexpected second component purl: %#v", result.Statements[1])
	}
}

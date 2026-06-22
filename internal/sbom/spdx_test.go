package sbom

import "testing"

func TestParseSPDXJSON(t *testing.T) {
	t.Parallel()

	components, err := ParseSPDXJSON([]byte(`{
		"spdxVersion":"SPDX-2.3",
		"documentNamespace":"https://example.com/spdx/doc",
		"packages":[
			{
				"SPDXID":"SPDXRef-DOCUMENT",
				"name":"https://example.com/spdx/doc#document-root",
				"versionInfo":"0.0.0"
			},
			{
				"SPDXID":"SPDXRef-Package-golang.org-x-net",
				"name":"golang.org/x/net",
				"versionInfo":"v0.25.0",
				"externalRefs":[
					{
						"referenceCategory":"PACKAGE-MANAGER",
						"referenceLocator":"pkg:golang/golang.org/x/net@v0.25.0",
						"referenceType":"purl"
					}
				]
			},
			{
				"SPDXID":"SPDXRef-Package-local-lib",
				"name":"local-lib",
				"versionInfo":"1.2.3"
			}
		]
	}`))
	if err != nil {
		t.Fatalf("ParseSPDXJSON() error = %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("component count = %d, want 2", len(components))
	}
	if got := components[0]; got.Name != "golang.org/x/net" || got.Version != "v0.25.0" || got.PURL != "pkg:golang/golang.org/x/net@v0.25.0" || got.Ecosystem != "go" {
		t.Fatalf("first component = %#v, want parsed purl-backed go component", got)
	}
	if got := components[1]; got.Name != "local-lib" || got.Version != "1.2.3" || got.PURL != "" || got.Ecosystem != "" {
		t.Fatalf("second component = %#v, want name/version without purl", got)
	}
}

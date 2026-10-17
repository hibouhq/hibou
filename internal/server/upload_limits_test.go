package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetectArtifactTypeAndCount(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, content, wantType, wantFormat, wantTool string
		wantItems                                     int
	}{
		{"sarif", `{"runs":[{"tool":{"driver":{"name":" Semgrep "}},"results":[{},{}]},{"results":[{}]}]}`, "sarif", "", "semgrep", 3},
		{"sarif by schema", `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json"}`, "sarif", "", "", 0},
		{"cyclonedx", `{"bomFormat":"CycloneDX","components":[{"name":"a"},{"name":"b"}]}`, "sbom", "cyclonedx-json", "", 2},
		{"spdx", `{"spdxVersion":"SPDX-2.3","packages":[{"name":"a"}]}`, "sbom", "spdx-json", "", 1},
		{"openvex", `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{},{},{}]}`, "vex", "openvex", "", 3},
		{"csaf", `{"document":{"category":"csaf_vex"},"vulnerabilities":[{}]}`, "vex", "csaf", "", 1},
		{"junit", `<testsuites><testsuite><testcase name="a"/><testcase name="b"/></testsuite></testsuites>`, "tests", "junit", "", 2},
		{"cyclonedx xml", `<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components><component/></components></bom>`, "sbom", "cyclonedx-xml", "", 2},
		// A field of an unexpected type defeats the narrow probe; the general
		// detector still classifies the document.
		{"fallback", `{"bomFormat":"CycloneDX","components":"oops"}`, "sbom", "cyclonedx-json", "", 0},
	}
	for _, tc := range cases {
		gotType, gotFormat, gotTool, gotItems, err := detectArtifactTypeAndCount([]byte(tc.content))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if gotType != tc.wantType || gotFormat != tc.wantFormat || gotTool != tc.wantTool || gotItems != tc.wantItems {
			t.Errorf("%s = (%q, %q, %q, %d), want (%q, %q, %q, %d)", tc.name, gotType, gotFormat, gotTool, gotItems, tc.wantType, tc.wantFormat, tc.wantTool, tc.wantItems)
		}
		// Classification must agree with the general detector.
		legacyType, legacyFormat, legacyTool, _ := detectArtifactType([]byte(tc.content))
		if legacyType != gotType || legacyFormat != gotFormat || legacyTool != gotTool {
			t.Errorf("%s disagrees with detectArtifactType: (%q, %q, %q)", tc.name, legacyType, legacyFormat, legacyTool)
		}
	}
	if _, _, _, _, err := detectArtifactTypeAndCount([]byte("   ")); err == nil {
		t.Fatal("empty content must be rejected")
	}
}

func TestValidateUploadRequestRejectsUnsafeCommitSHA(t *testing.T) {
	t.Parallel()

	base := uploadRequest{Provider: "github", Org: "acme", Repo: "app", Ref: "refs/heads/main"}
	for _, sha := range []string{"=HYPERLINK(\"x\")", "-1+1", "abc def", strings.Repeat("a", 65), "a'b"} {
		input := base
		input.CommitSHA = sha
		if err := validateUploadRequest(input); err == nil {
			t.Errorf("commit_sha %q accepted", sha)
		}
	}
	input := base
	input.CommitSHA = "  0123456789ABCDEF0123456789abcdef01234567 "
	normalizeUploadRequest(&input)
	if err := validateUploadRequest(input); err != nil {
		t.Fatalf("hex commit_sha refused: %v", err)
	}
	if input.CommitSHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("commit_sha not normalized: %q", input.CommitSHA)
	}
}

func TestCompareLocalSBOMsRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	body, _ := json.Marshal(compareSBOMsRequest{BaseContent: strings.Repeat("A", maxSBOMCompareBytes)})
	recorder := httptest.NewRecorder()
	(&Server{}).handleCompareLocalSBOMs(recorder, httptest.NewRequest(http.MethodPost, toolSBOMCompare, bytes.NewReader(body)))
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", recorder.Code)
	}
}

// TestValidateUploadRequestRejectsUnsafeRepo: an upload enrols the
// repository it names, so the name must be one a forge could hold.
func TestValidateUploadRequestRejectsUnsafeRepo(t *testing.T) {
	t.Parallel()

	base := uploadRequest{Provider: "github", Org: "acme", Ref: "refs/heads/main", CommitSHA: "0123456789abcdef0123456789abcdef01234567"}
	for _, repo := range []string{"../x", ".", "..", "a/b", `a\b`, "x';drop table repositories;--", strings.Repeat("a", 101), "-rf", "a b", "café"} {
		input := base
		input.Repo = repo
		if err := validateUploadRequest(input); err == nil {
			t.Errorf("repo %q accepted", repo)
		}
	}
	for _, repo := range []string{"app", "my_repo", "site.v2", "Hibou-Server", "a"} {
		input := base
		input.Repo = repo
		if err := validateUploadRequest(input); err != nil {
			t.Errorf("repo %q refused: %v", repo, err)
		}
	}
}

package server

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/sarif"
	"github.com/hibouhq/hibou/internal/store"
)

func mustParseSARIF(t *testing.T, doc string) *sarif.Document {
	t.Helper()
	parsed, err := sarif.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func strPtr(s string) *string { return &s }

func TestCompareProducerRuns(t *testing.T) {
	previous := []store.ProducerRun{
		{Producer: "gosec", Outcome: store.ProducerOutcomeCompleted, Version: strPtr("2.21.0")},
		{Producer: "trivy", Outcome: store.ProducerOutcomeCompleted},
	}
	current := []store.ProducerRun{
		// Two SARIF files from the same tool: worst outcome wins, skipped files merge.
		{Producer: "gosec", Outcome: store.ProducerOutcomeCompleted, Version: strPtr("2.22.0"), Scope: store.ProducerScopeFull, FindingCount: 2, ScopeDeclared: true},
		{Producer: "gosec", Outcome: store.ProducerOutcomePartial, Scope: store.ProducerScopeFull, FindingCount: 1, ScopeDeclared: true,
			SkippedFiles: []store.SkippedFile{{Path: "big.go", Reason: "timeout"}}},
		{Producer: "opengrep oss", Outcome: store.ProducerOutcomeCompleted, Scope: store.ProducerScopePartial, ScopePaths: []string{"a.go"}},
		{Producer: sbomMatchingProducer, Outcome: ""},
	}
	got := compareProducerRuns(current, previous)
	byProducer := map[string]producerCoverage{}
	for _, coverage := range got {
		byProducer[coverage.Producer] = coverage
	}
	if got[0].Producer != "trivy" || got[0].Status != producerStatusMissing {
		t.Fatalf("missing producer must sort first: %+v", got[0])
	}
	gosec := byProducer["gosec"]
	if gosec.Status != producerStatusRan || gosec.Outcome != store.ProducerOutcomePartial || gosec.FindingCount != 3 || len(gosec.SkippedFiles) != 1 || !gosec.ScopeDeclared {
		t.Fatalf("gosec = %+v", gosec)
	}
	if gosec.Version == nil || *gosec.Version != "2.22.0" || gosec.PreviousVersion == nil || *gosec.PreviousVersion != "2.21.0" {
		t.Fatalf("gosec versions = %v / %v", gosec.Version, gosec.PreviousVersion)
	}
	opengrep := byProducer["opengrep oss"]
	if opengrep.Status != producerStatusNew || opengrep.Scope != store.ProducerScopePartial || opengrep.ScopeDeclared {
		t.Fatalf("opengrep = %+v", opengrep)
	}
	if byProducer[sbomMatchingProducer].Status != producerStatusPending {
		t.Fatalf("unfinished advisory scan must be pending: %+v", byProducer[sbomMatchingProducer])
	}
}

const producerRunSARIF = `{"version":"2.1.0","runs":[
 {"tool":{"driver":{"name":"gosec","version":"2.22.0"}},
  "invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[
    {"level":"error","message":{"text":"timeout"},"descriptor":{"id":"Timeout"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"big.go"}}}]}]}],
  "results":[{"ruleId":"G101","level":"error","message":{"text":"creds"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":3}}}]}]},
 {"tool":{"driver":{"name":"Opengrep OSS","semanticVersion":"1.30.0"}},"invocations":[{"executionSuccessful":true}],"results":[]}
]}`

// Ingest records one producer run per SARIF run with its evidence, merges
// the uploader's declaration, fills scanner_version, and a re-processed
// artifact replaces its runs instead of duplicating them.
func TestSARIFIngestRecordsProducerRuns(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	writeArtifactForProcessingTest(t, srv, snapshotID, "sarif", nil, strPtr("gosec"), producerRunSARIF)
	ctx := context.Background()
	artifacts, err := srv.queries.ListSnapshotArtifactsBySnapshot(ctx, snapshotID)
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("artifacts = %d, %v", len(artifacts), err)
	}
	partial := store.ProducerScopePartial
	if err := srv.queries.SetSnapshotArtifactRunDeclaration(ctx, artifacts[0].ID, store.ArtifactRunDeclaration{
		Scope: &partial, ScopePaths: []string{"a.go", "big.go"}, ConfigDigest: strPtr("sha256:rules"),
	}); err != nil {
		t.Fatalf("SetSnapshotArtifactRunDeclaration: %v", err)
	}
	processArtifactSnapshotForTest(t, srv, snapshotID)

	runs, err := srv.queries.ListProducerRunsBySnapshot(ctx, snapshotID)
	if err != nil {
		t.Fatalf("ListProducerRunsBySnapshot: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("runs = %+v", runs)
	}
	gosec, opengrep := runs[0], runs[1]
	if gosec.Producer != "gosec" || gosec.Version == nil || *gosec.Version != "2.22.0" || gosec.Outcome != store.ProducerOutcomePartial ||
		gosec.Scope != store.ProducerScopePartial || !gosec.ScopeDeclared || len(gosec.ScopePaths) != 2 || gosec.FindingCount != 1 ||
		len(gosec.SkippedFiles) != 1 || gosec.SkippedFiles[0].Reason != "timeout" || gosec.ConfigDigest == nil {
		t.Fatalf("gosec run = %+v", gosec)
	}
	if opengrep.Producer != "opengrep oss" || opengrep.Version == nil || *opengrep.Version != "1.30.0" || opengrep.RunIndex != 1 {
		t.Fatalf("opengrep run = %+v", opengrep)
	}

	vulns, err := srv.queries.ListAllVulnerabilitiesBySnapshot(ctx, snapshotID)
	if err != nil || len(vulns) != 1 || vulns[0].ScannerVersion != "2.22.0" {
		t.Fatalf("scanner_version not stored: %+v %v", vulns, err)
	}

	// Re-processing the same artifact replaces its runs.
	if err := srv.queries.ReplaceArtifactProducerRuns(ctx, snapshotID, artifacts[0].ID, sarifProducerRuns(mustParseSARIF(t, producerRunSARIF), artifacts[0], nil)); err != nil {
		t.Fatalf("ReplaceArtifactProducerRuns: %v", err)
	}
	again, _ := srv.queries.ListProducerRunsBySnapshot(ctx, snapshotID)
	if len(again) != 2 {
		t.Fatalf("re-processing duplicated runs: %d", len(again))
	}
}

func TestUploadRunDeclaration(t *testing.T) {
	cases := []struct {
		name    string
		input   autoUploadRequest
		scope   string
		paths   int
		wantErr bool
	}{
		{name: "nothing declared", input: autoUploadRequest{}},
		{name: "full", input: autoUploadRequest{Scope: "FULL", ToolVersion: " 2.22.0 "}, scope: "full"},
		{name: "paths imply partial, deduplicated", input: autoUploadRequest{Paths: []string{"./a.go", "a.go", " ", "b.go"}}, scope: "partial", paths: 2},
		{name: "full with paths", input: autoUploadRequest{Scope: "full", Paths: []string{"a.go"}}, wantErr: true},
		{name: "unknown scope", input: autoUploadRequest{Scope: "diff"}, wantErr: true},
		{name: "oversized digest", input: autoUploadRequest{ConfigDigest: strings.Repeat("x", maxDeclaredValueLen+1)}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.input.runDeclaration()
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (got.Scope == nil && tc.scope != "") || (got.Scope != nil && *got.Scope != tc.scope) || len(got.ScopePaths) != tc.paths {
				t.Fatalf("declaration = %+v", got)
			}
			if tc.input.ToolVersion != "" && (got.ToolVersion == nil || *got.ToolVersion != "2.22.0") {
				t.Fatalf("tool version = %v", got.ToolVersion)
			}
		})
	}
}

// The Phase 5 POC captures (real OpenGrep interfile and SpotBugs + FSB
// reports on hibou-sample-project) through the real processing path: runs
// with versions, the cross-file finding with its code-flow files.
func TestIngestRealScannerCaptures(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	for _, capture := range []struct{ file, tool string }{
		{"opengrep-interfile-java.sarif", "opengrep"},
		{"spotbugs-fsb-java.sarif", "spotbugs"},
	} {
		data, err := os.ReadFile("../sarif/testdata/" + capture.file)
		if err != nil {
			t.Fatal(err)
		}
		writeArtifactForProcessingTest(t, srv, snapshotID, "sarif", nil, strPtr(capture.tool), string(data))
	}
	processArtifactSnapshotForTest(t, srv, snapshotID)
	ctx := context.Background()

	runs, err := srv.queries.ListProducerRunsBySnapshot(ctx, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	versions := map[string]string{}
	for _, run := range runs {
		if run.Outcome != store.ProducerOutcomeCompleted {
			t.Errorf("%s outcome = %s", run.Producer, run.Outcome)
		}
		versions[run.Producer] = derefString(run.Version)
	}
	if versions["opengrep oss"] != "1.30.0" || versions["spotbugs"] != "4.9.3" {
		t.Fatalf("producer versions = %v", versions)
	}

	vulns, err := srv.queries.ListAllVulnerabilitiesBySnapshot(ctx, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	var taint *store.Vulnerability
	spotbugsFindings := 0
	for i := range vulns {
		switch vulns[i].ScannerName {
		case "opengrep oss":
			if strings.Contains(vulns[i].PrimaryIdentifierValue, "command-injection") {
				taint = &vulns[i]
			}
		case "spotbugs":
			spotbugsFindings++
		}
	}
	if taint == nil || len(presence.TraceFiles(*taint)) < 2 {
		t.Fatalf("cross-file finding with its trace files: %+v", taint)
	}
	if spotbugsFindings != 6 {
		t.Fatalf("spotbugs findings = %d, want the 6 of the capture", spotbugsFindings)
	}
}

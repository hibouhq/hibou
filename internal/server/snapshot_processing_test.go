package server

import (
	"context"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/store"
)

func TestProcessNextArtifactSnapshotIngestsCycloneDXComponents(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	scannerStub := &advisoryScannerStub{calls: make(chan advisoryScanCall, 1)}
	srv.advisoryScanner = scannerStub
	srv.advisoryProviders = []string{"osv"}
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", stringPtrForProcessingTest("cyclonedx-json"), nil, `{
		"bomFormat":"CycloneDX",
		"specVersion":"1.5",
		"version":1,
		"metadata":{"component":{"bom-ref":"root-app","name":"hibou","version":"1.0.0","purl":"pkg:gomod/github.com/hibouhq/hibou@1.0.0"}},
		"components":[
			{"bom-ref":"dep-a","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
			{"bom-ref":"dep-a-alias","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
			{"bom-ref":"dep-b","name":"chalk","version":"5.0.0","purl":"pkg:npm/chalk@5.0.0"},
			{"bom-ref":"skipped","name":"missing-version","purl":"pkg:npm/missing-version"}
		],
		"dependencies":[
			{"ref":"root-app","dependsOn":["dep-a","dep-b","dep-a","skipped"]},
			{"ref":"dep-a","dependsOn":["dep-b","missing"]}
		]
	}`)
	processArtifactSnapshotForTest(t, srv, snapshotID)

	components, err := srv.queries.ListComponentsBySnapshot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("ListComponentsBySnapshot: %v", err)
	}
	if len(components) != 3 {
		t.Fatalf("component count = %d, want 3", len(components))
	}
	var dependencyEdges int
	if err := srv.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM component_dependencies WHERE snapshot_id = $1`, snapshotID).Scan(&dependencyEdges); err != nil {
		t.Fatalf("count component_dependencies: %v", err)
	}
	if dependencyEdges != 3 {
		t.Fatalf("dependency edge count = %d, want 3", dependencyEdges)
	}
	rootRef, err := srv.queries.GetSnapshotDependencyRoot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotDependencyRoot: %v", err)
	}
	if rootRef == nil || *rootRef != "pkg:gomod/github.com/hibouhq/hibou@1.0.0" {
		t.Fatalf("persisted root_ref = %v, want declared root purl", rootRef)
	}
	select {
	case call := <-scannerStub.calls:
		if call.SnapshotID != snapshotID {
			t.Fatalf("scan snapshot id = %s, want %s", call.SnapshotID, snapshotID)
		}
		if !reflect.DeepEqual(call.Providers, []string{"osv"}) {
			t.Fatalf("scan providers = %v, want [osv]", call.Providers)
		}
		if call.Triggered != "system" {
			t.Fatalf("scan triggeredBy = %q, want system", call.Triggered)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected advisory scan trigger after component ingest")
	}
	assertSnapshotProcessingCompleted(t, srv, snapshotID)
	if components[0].Ecosystem == "" && components[1].Ecosystem == "" {
		t.Fatal("expected ingested components to include ecosystems")
	}
}

func TestProcessNextArtifactSnapshotIngestsSPDXComponentsWithoutDependencies(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	scannerStub := &advisoryScannerStub{calls: make(chan advisoryScanCall, 1)}
	srv.advisoryScanner = scannerStub
	srv.advisoryProviders = []string{"osv"}
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", stringPtrForProcessingTest("spdx-json"), nil, `{
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
				"SPDXID":"SPDXRef-Package-left-pad",
				"name":"left-pad",
				"versionInfo":"1.3.0",
				"externalRefs":[
					{
						"referenceCategory":"PACKAGE-MANAGER",
						"referenceLocator":"pkg:npm/left-pad@1.3.0",
						"referenceType":"purl"
					}
				]
			}
		]
	}`)
	processArtifactSnapshotForTest(t, srv, snapshotID)

	components, err := srv.queries.ListComponentsBySnapshot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("ListComponentsBySnapshot: %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("component count = %d, want 2", len(components))
	}
	var dependencyEdges int
	if err := srv.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM component_dependencies WHERE snapshot_id = $1`, snapshotID).Scan(&dependencyEdges); err != nil {
		t.Fatalf("count component_dependencies: %v", err)
	}
	if dependencyEdges != 0 {
		t.Fatalf("dependency edge count = %d, want 0", dependencyEdges)
	}
	rootRef, err := srv.queries.GetSnapshotDependencyRoot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotDependencyRoot: %v", err)
	}
	if rootRef != nil {
		t.Fatalf("persisted root_ref = %v, want nil", rootRef)
	}
	select {
	case call := <-scannerStub.calls:
		if call.SnapshotID != snapshotID {
			t.Fatalf("scan snapshot id = %s, want %s", call.SnapshotID, snapshotID)
		}
		if !reflect.DeepEqual(call.Providers, []string{"osv"}) {
			t.Fatalf("scan providers = %v, want [osv]", call.Providers)
		}
		if call.Triggered != "system" {
			t.Fatalf("scan triggeredBy = %q, want system", call.Triggered)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected advisory scan trigger after component ingest")
	}
	assertSnapshotProcessingCompleted(t, srv, snapshotID)
	if components[0].Ecosystem == "" && components[1].Ecosystem == "" {
		t.Fatal("expected ingested components to include ecosystems")
	}
}

func TestProcessNextArtifactSnapshotIngestsSARIFFindings(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	scannerStub := &advisoryScannerStub{calls: make(chan advisoryScanCall, 1)}
	srv.advisoryScanner = scannerStub
	srv.advisoryProviders = []string{"osv"}
	writeArtifactForProcessingTest(t, srv, snapshotID, "sarif", nil, stringPtrForProcessingTest("semgrep"), `{
		"version":"2.1.0",
		"runs":[{
			"tool":{"driver":{"name":"semgrep","rules":[{"id":"go.sql","name":"SQL injection","helpUri":"https://example.test/rule","properties":{"tags":["CWE-89"]}}]}},
			"results":[{
				"ruleId":"go.sql",
				"level":"error",
				"message":{"text":"possible SQL injection"},
				"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go"},"region":{"startLine":12,"endLine":14}}}],
				"fingerprints":{"primary":"semgrep-1"}
			}]
		}]
	}`)
	processArtifactSnapshotForTest(t, srv, snapshotID)

	vulnerabilities, _, err := srv.queries.ListVulnerabilitiesBySnapshot(context.Background(), snapshotID, store.VulnerabilityListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListVulnerabilitiesBySnapshot: %v", err)
	}
	if len(vulnerabilities) != 1 {
		t.Fatalf("vulnerability count = %d, want 1", len(vulnerabilities))
	}
	if vulnerabilities[0].Type != "sast" {
		t.Fatalf("vulnerability type = %q, want sast", vulnerabilities[0].Type)
	}
	select {
	case call := <-scannerStub.calls:
		t.Fatalf("unexpected advisory scan trigger for SARIF-only processing: %+v", call)
	case <-time.After(200 * time.Millisecond):
	}
	assertSnapshotProcessingCompleted(t, srv, snapshotID)
	if vulnerabilities[0].ScannerName != "semgrep" {
		t.Fatalf("scanner_name = %q, want semgrep", vulnerabilities[0].ScannerName)
	}
}

func TestProcessClaimedArtifactSnapshotBaseIsIdempotentForCycloneDX(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", stringPtrForProcessingTest("cyclonedx-json"), nil, `{
		"bomFormat":"CycloneDX",
		"specVersion":"1.5",
		"version":1,
		"metadata":{"component":{"bom-ref":"root-app","name":"hibou","version":"1.0.0","purl":"pkg:gomod/github.com/hibouhq/hibou@1.0.0"}},
		"components":[
			{"bom-ref":"dep-a","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
			{"bom-ref":"dep-a-alias","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}
		],
		"dependencies":[{"ref":"root-app","dependsOn":["dep-a","dep-a-alias"]}]
	}`)

	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if _, err := srv.processClaimedArtifactSnapshotBase(context.Background(), snapshot); err != nil {
		t.Fatalf("first processClaimedArtifactSnapshotBase: %v", err)
	}
	if _, err := srv.processClaimedArtifactSnapshotBase(context.Background(), snapshot); err != nil {
		t.Fatalf("second processClaimedArtifactSnapshotBase: %v", err)
	}

	components, err := srv.queries.ListComponentsBySnapshot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("ListComponentsBySnapshot: %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("component count = %d, want 2", len(components))
	}
	var dependencyCount int
	if err := srv.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM component_dependencies WHERE snapshot_id = $1`, snapshotID).Scan(&dependencyCount); err != nil {
		t.Fatalf("count component_dependencies: %v", err)
	}
	if dependencyCount != 1 {
		t.Fatalf("component dependency rows = %d, want 1", dependencyCount)
	}
	rootRef, err := srv.queries.GetSnapshotDependencyRoot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotDependencyRoot: %v", err)
	}
	if rootRef == nil || *rootRef != "pkg:gomod/github.com/hibouhq/hibou@1.0.0" {
		t.Fatalf("persisted root_ref = %v, want declared root purl", rootRef)
	}
	var attachedCount int
	if err := srv.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM snapshot_components WHERE snapshot_id = $1`, snapshotID).Scan(&attachedCount); err != nil {
		t.Fatalf("count snapshot_components: %v", err)
	}
	if attachedCount != 2 {
		t.Fatalf("snapshot component rows = %d, want 2", attachedCount)
	}
}

func TestProcessClaimedArtifactSnapshotBaseIsIdempotentForSARIF(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	writeArtifactForProcessingTest(t, srv, snapshotID, "sarif", nil, stringPtrForProcessingTest("semgrep"), `{
		"version":"2.1.0",
		"runs":[{
			"tool":{"driver":{"name":"semgrep","rules":[{"id":"go.sql","name":"SQL injection","helpUri":"https://example.test/rule","properties":{"tags":["CWE-89"]}}]}},
			"results":[{
				"ruleId":"go.sql",
				"level":"error",
				"message":{"text":"possible SQL injection"},
				"locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go"},"region":{"startLine":12,"endLine":14}}}],
				"fingerprints":{"primary":"semgrep-1"}
			}]
		}]
	}`)

	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if _, err := srv.processClaimedArtifactSnapshotBase(context.Background(), snapshot); err != nil {
		t.Fatalf("first processClaimedArtifactSnapshotBase: %v", err)
	}
	if _, err := srv.processClaimedArtifactSnapshotBase(context.Background(), snapshot); err != nil {
		t.Fatalf("second processClaimedArtifactSnapshotBase: %v", err)
	}

	vulnerabilities, _, err := srv.queries.ListVulnerabilitiesBySnapshot(context.Background(), snapshotID, store.VulnerabilityListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListVulnerabilitiesBySnapshot: %v", err)
	}
	if len(vulnerabilities) != 1 {
		t.Fatalf("vulnerability count = %d, want 1", len(vulnerabilities))
	}
	if vulnerabilities[0].Fingerprint != "semgrep-1" {
		t.Fatalf("fingerprint = %q, want semgrep-1", vulnerabilities[0].Fingerprint)
	}
	var vulnCount int
	if err := srv.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM vulnerabilities WHERE snapshot_id = $1 AND type = 'sast'`, snapshotID).Scan(&vulnCount); err != nil {
		t.Fatalf("count vulnerabilities: %v", err)
	}
	if vulnCount != 1 {
		t.Fatalf("sast vulnerability rows = %d, want 1", vulnCount)
	}
}

func TestProcessNextArtifactSnapshotHeartbeatsLongRunningClaim(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	format := "cyclonedx-json"
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", &format, nil, `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`)
	quarantineUnrelatedClaimableSnapshots(t, srv, snapshotID)
	srv.cfg.Worker.LeaseDuration = 90 * time.Millisecond
	srv.cfg.Worker.HeartbeatInterval = 25 * time.Millisecond

	original := processClaimedSnapshotHook
	defer func() {
		processClaimedSnapshotHook = original
	}()
	started := make(chan struct{})
	release := make(chan struct{})
	processClaimedSnapshotHook = func(ctx context.Context, _ *Server, snapshot *store.Snapshot) (*artifactProcessingResult, error) {
		if snapshot.ID != snapshotID {
			return &artifactProcessingResult{}, nil
		}
		close(started)
		select {
		case <-release:
			return &artifactProcessingResult{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	resultCh := make(chan error, 1)
	go func() {
		_, err := srv.processNextArtifactSnapshot(context.Background())
		resultCh <- err
	}()

	<-started
	time.Sleep(220 * time.Millisecond)

	claim, err := srv.queries.ClaimNextArtifactProcessingSnapshot(context.Background(), "worker-b", time.Now().Add(time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextArtifactProcessingSnapshot(worker-b) error = %v", err)
	}
	if claim != nil && claim.ID == snapshotID {
		t.Fatalf("concurrent claim = %#v, want target snapshot to remain owned while heartbeat is renewing", claim)
	}

	close(release)
	if err := <-resultCh; err != nil {
		t.Fatalf("processNextArtifactSnapshot() error = %v", err)
	}
	assertSnapshotProcessingCompleted(t, srv, snapshotID)
}

func TestProcessNextArtifactSnapshotStopsWhenOwnershipLost(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	format := "cyclonedx-json"
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", &format, nil, `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`)
	quarantineUnrelatedClaimableSnapshots(t, srv, snapshotID)
	srv.cfg.Worker.LeaseDuration = 5 * time.Minute
	srv.cfg.Worker.HeartbeatInterval = 15 * time.Millisecond

	original := processClaimedSnapshotHook
	defer func() {
		processClaimedSnapshotHook = original
	}()
	started := make(chan struct{})
	var canceled atomic.Bool
	processClaimedSnapshotHook = func(ctx context.Context, _ *Server, snapshot *store.Snapshot) (*artifactProcessingResult, error) {
		if snapshot.ID != snapshotID {
			return &artifactProcessingResult{}, nil
		}
		close(started)
		<-ctx.Done()
		canceled.Store(true)
		return nil, ctx.Err()
	}

	resultCh := make(chan error, 1)
	go func() {
		_, err := srv.processNextArtifactSnapshot(context.Background())
		resultCh <- err
	}()

	<-started
	if _, err := srv.db.ExecContext(context.Background(), `
		UPDATE snapshots
		SET artifact_processing_claimed_by = 'worker-b',
			artifact_processing_claim_expires_at = NOW() + INTERVAL '5 minutes'
		WHERE id = $1
	`, snapshotID); err != nil {
		t.Fatalf("steal claim: %v", err)
	}

	if err := <-resultCh; err != nil {
		t.Fatalf("processNextArtifactSnapshot() error = %v", err)
	}
	if !canceled.Load() {
		t.Fatal("processing context was not canceled after ownership loss")
	}

	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot.ArtifactProcessingClaimedBy == nil || *snapshot.ArtifactProcessingClaimedBy != "worker-b" {
		t.Fatalf("claim owner after ownership loss = %#v, want worker-b", snapshot.ArtifactProcessingClaimedBy)
	}
	if snapshot.ArtifactProcessingFinishedAt != nil {
		t.Fatalf("artifact_processing_finished_at = %v, want nil after abandonment", snapshot.ArtifactProcessingFinishedAt)
	}
	if snapshot.ArtifactProcessingLastError != nil {
		t.Fatalf("artifact_processing_last_error = %#v, want nil after ownership loss", snapshot.ArtifactProcessingLastError)
	}
	if snapshot.Status != store.SnapshotStatusComplete {
		t.Fatalf("status = %q, want complete for reclaimable abandoned claim", snapshot.Status)
	}
}

func TestProcessNextArtifactSnapshotCompletesWithWarningWhenArtifactsMixed(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", stringPtrForProcessingTest("cyclonedx-json"), nil, `{
		"bomFormat":"CycloneDX",
		"specVersion":"1.5",
		"version":1,
		"components":[{"name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]
	}`)
	writeArtifactForProcessingTest(t, srv, snapshotID, "sarif", nil, stringPtrForProcessingTest("semgrep"), `{invalid`)
	processArtifactSnapshotForTest(t, srv, snapshotID)

	components, err := srv.queries.ListComponentsBySnapshot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("ListComponentsBySnapshot: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("component count = %d, want 1", len(components))
	}

	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot.Status != store.SnapshotStatusComplete {
		t.Fatalf("snapshot status = %q, want complete", snapshot.Status)
	}
	if snapshot.ArtifactProcessingFinishedAt == nil {
		t.Fatal("artifact_processing_finished_at = nil, want value")
	}
	if snapshot.ArtifactProcessingLastError == nil {
		t.Fatal("artifact_processing_last_error = nil, want warning")
	}
	if !strings.Contains(*snapshot.ArtifactProcessingLastError, "sarif") {
		t.Fatalf("artifact_processing_last_error = %q, want sarif warning", *snapshot.ArtifactProcessingLastError)
	}
	if !strings.Contains(*snapshot.ArtifactProcessingLastError, "parse sarif artifact") {
		t.Fatalf("artifact_processing_last_error = %q, want parse failure detail", *snapshot.ArtifactProcessingLastError)
	}
}

func TestProcessNextArtifactSnapshotCompletesWhenClaimedArtifactsDisappear(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", stringPtrForProcessingTest("cyclonedx-json"), nil, `{
		"bomFormat":"CycloneDX",
		"specVersion":"1.5",
		"version":1,
		"components":[{"name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]
	}`)
	quarantineUnrelatedClaimableSnapshots(t, srv, snapshotID)

	if _, err := srv.db.ExecContext(context.Background(), `
		UPDATE snapshots
		SET artifact_processing_claimed_by = $2,
			artifact_processing_claim_expires_at = NOW() + INTERVAL '1 minute',
			artifact_processing_attempts = 1,
			artifact_processing_started_at = NOW()
		WHERE id = $1
	`, snapshotID, srv.artifactWorkerID); err != nil {
		t.Fatalf("seed claimed snapshot: %v", err)
	}
	claimed, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if claimed == nil {
		t.Fatal("claimed snapshot = nil, want snapshot")
	}
	if _, err := srv.db.ExecContext(context.Background(), `DELETE FROM snapshot_artifacts WHERE snapshot_id = $1`, snapshotID); err != nil {
		t.Fatalf("delete claimed artifacts: %v", err)
	}

	run := srv.startArtifactProcessingRun(context.Background(), snapshotID)
	defer srv.stopArtifactProcessingRun(run)

	result, err := srv.processClaimedArtifactSnapshot(run.ctx, claimed)
	if err != nil {
		t.Fatalf("processClaimedArtifactSnapshot: %v", err)
	}
	if result == nil {
		result = &artifactProcessingResult{}
	}
	if err := srv.completeArtifactProcessingSnapshot(context.Background(), run, snapshotID, result.warning, result.componentsIngested); err != nil {
		t.Fatalf("completeArtifactProcessingSnapshot: %v", err)
	}

	assertSnapshotProcessingCompleted(t, srv, snapshotID)

	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot.ArtifactProcessingLastError != nil {
		t.Fatalf("artifact_processing_last_error = %q, want nil", *snapshot.ArtifactProcessingLastError)
	}
	if snapshot.ArtifactProcessingAttempts != 1 {
		t.Fatalf("artifact_processing_attempts = %d, want 1", snapshot.ArtifactProcessingAttempts)
	}
}

func TestProcessNextArtifactSnapshotMarksAllInvalidBatchFailedAndRetryable(t *testing.T) {
	srv, snapshotID := newArtifactProcessingTestServer(t)
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", stringPtrForProcessingTest("cyclonedx-json"), nil, `{invalid`)
	writeArtifactForProcessingTest(t, srv, snapshotID, "sbom", stringPtrForProcessingTest("cyclonedx-json"), nil, `{still invalid`)
	quarantineUnrelatedClaimableSnapshots(t, srv, snapshotID)

	for attempt := 1; attempt <= int(artifactProcessingMaxAttempts); attempt++ {
		processed, err := srv.processNextArtifactSnapshot(context.Background())
		if err != nil {
			t.Fatalf("processNextArtifactSnapshot(attempt %d): %v", attempt, err)
		}
		if !processed {
			t.Fatalf("processed(attempt %d) = false, want true", attempt)
		}

		snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
		if err != nil {
			t.Fatalf("GetSnapshotByID(attempt %d): %v", attempt, err)
		}
		if snapshot.Status != store.SnapshotStatusFailed {
			t.Fatalf("snapshot status(attempt %d) = %q, want failed", attempt, snapshot.Status)
		}
		if snapshot.ArtifactProcessingLastError == nil {
			t.Fatalf("artifact_processing_last_error(attempt %d) = nil, want error", attempt)
		}
		if !strings.Contains(*snapshot.ArtifactProcessingLastError, "artifact ingest warnings") {
			t.Fatalf("artifact_processing_last_error(attempt %d) = %q, want aggregate warning", attempt, *snapshot.ArtifactProcessingLastError)
		}
		if snapshot.ArtifactProcessingAttempts != attempt {
			t.Fatalf("artifact_processing_attempts(attempt %d) = %d, want %d", attempt, snapshot.ArtifactProcessingAttempts, attempt)
		}
		if attempt < int(artifactProcessingMaxAttempts) {
			if snapshot.ArtifactProcessingFinishedAt != nil {
				t.Fatalf("artifact_processing_finished_at(attempt %d) = %v, want nil", attempt, snapshot.ArtifactProcessingFinishedAt)
			}
			if snapshot.ArtifactProcessingClaimedBy != nil {
				t.Fatalf("artifact_processing_claimed_by(attempt %d) = %v, want nil", attempt, snapshot.ArtifactProcessingClaimedBy)
			}
			continue
		}
		if snapshot.ArtifactProcessingFinishedAt == nil {
			t.Fatal("artifact_processing_finished_at(final attempt) = nil, want value")
		}
	}

	processed, err := srv.processNextArtifactSnapshot(context.Background())
	if err != nil {
		t.Fatalf("processNextArtifactSnapshot(after max attempts): %v", err)
	}
	if processed {
		t.Fatal("processed(after max attempts) = true, want false")
	}
}

func newArtifactProcessingTestServer(t *testing.T) (*Server, uuid.UUID) {
	t.Helper()
	srv, org, _, _ := newDiscoveryTestServer(t)
	artifactDir := t.TempDir()
	artifactStore, err := objstore.NewFilesystemStore(artifactDir)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	srv.objStore = artifactStore
	srv.artifactWorkerID = "test-worker"
	repo := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForProcessingTest(uniqueName(t, "sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uniqueName(t, "commit"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	return srv, snapshot.ID
}

func writeArtifactForProcessingTest(t *testing.T, srv *Server, snapshotID uuid.UUID, kind string, format, tool *string, content string) {
	t.Helper()
	params := buildSnapshotArtifactParams(snapshotID, kind, optionalStringValue(format), optionalStringValue(tool), "", []byte(content))
	if err := srv.objStore.Put(context.Background(), params.ObjectKey, strings.NewReader(content), optionalStringValue(params.ContentType)); err != nil {
		t.Fatalf("Put artifact object: %v", err)
	}
	if _, err := srv.queries.CreateSnapshotArtifact(context.Background(), store.CreateSnapshotArtifactParams{
		SnapshotID:  snapshotID,
		Kind:        kind,
		Format:      format,
		ToolName:    tool,
		ObjectKey:   params.ObjectKey,
		SHA256:      params.SHA256,
		SizeBytes:   int64(len(content)),
		ContentType: params.ContentType,
	}); err != nil {
		t.Fatalf("CreateSnapshotArtifact: %v", err)
	}
	if err := srv.queries.AddSnapshotArtifactBytes(context.Background(), snapshotID, int64(len(content))); err != nil {
		t.Fatalf("AddSnapshotArtifactBytes: %v", err)
	}
}

// processArtifactSnapshotForTest drives artifact processing until the given
// snapshot is finished.
//
// processNextArtifactSnapshot claims the next claimable snapshot in the WHOLE
// database, and `go test ./...` runs packages in parallel against one Postgres.
// A bare quarantine-then-claim races: another package can insert a claimable
// snapshot in the gap and win the claim, which made these tests fail roughly
// 1 run in 4. Re-quarantining and retrying until our own snapshot is finished
// removes the race without teaching production code about tests.
func processArtifactSnapshotForTest(t *testing.T, srv *Server, snapshotID uuid.UUID) {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		quarantineUnrelatedClaimableSnapshots(t, srv, snapshotID)
		processed, err := srv.processNextArtifactSnapshot(context.Background())
		if err != nil {
			t.Fatalf("processNextArtifactSnapshot: %v", err)
		}
		if artifactProcessingFinishedForTest(t, srv, snapshotID) {
			return
		}
		if !processed {
			t.Fatalf("snapshot %s was never claimed for artifact processing", snapshotID)
		}
		// Something else was claimed (a concurrent package's row); try again.
	}
	t.Fatalf("snapshot %s still unprocessed after repeated attempts", snapshotID)
}

func artifactProcessingFinishedForTest(t *testing.T, srv *Server, snapshotID uuid.UUID) bool {
	t.Helper()
	var finished bool
	if err := srv.db.QueryRowContext(context.Background(),
		`SELECT artifact_processing_finished_at IS NOT NULL FROM snapshots WHERE id = $1`, snapshotID,
	).Scan(&finished); err != nil {
		t.Fatalf("check artifact processing state: %v", err)
	}
	return finished
}

func quarantineUnrelatedClaimableSnapshots(t *testing.T, srv *Server, snapshotID uuid.UUID) {
	t.Helper()
	if _, err := srv.db.ExecContext(context.Background(), `
		UPDATE snapshots
		SET artifact_processing_finished_at = NOW(),
			artifact_processing_claimed_by = NULL,
			artifact_processing_claim_expires_at = NULL
		WHERE id <> $1
			AND artifact_processing_finished_at IS NULL
			AND (status = 'complete' OR status = 'failed')
	`, snapshotID); err != nil {
		t.Fatalf("quarantineUnrelatedClaimableSnapshots: %v", err)
	}
}

func assertSnapshotProcessingCompleted(t *testing.T, srv *Server, snapshotID uuid.UUID) {
	t.Helper()
	snapshot, err := srv.queries.GetSnapshotByID(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot == nil {
		t.Fatal("snapshot = nil, want snapshot")
	}
	if snapshot.Status != store.SnapshotStatusComplete {
		t.Fatalf("snapshot status = %q, want complete", snapshot.Status)
	}
	if snapshot.ArtifactProcessingFinishedAt == nil {
		t.Fatal("artifact_processing_finished_at = nil, want value")
	}
	if snapshot.ArtifactProcessingClaimedBy != nil {
		t.Fatalf("artifact_processing_claimed_by = %v, want nil", snapshot.ArtifactProcessingClaimedBy)
	}
	if snapshot.ArtifactProcessingLastError != nil {
		t.Fatalf("artifact_processing_last_error = %q, want nil", *snapshot.ArtifactProcessingLastError)
	}
}

func stringPtrForProcessingTest(value string) *string {
	return &value
}

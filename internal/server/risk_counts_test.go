package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/kev"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// ADR-023 semantics table: a false positive never was a vulnerability; an
// accepted risk is still risk, flagged; resolved/suppressed are not risk —
// unless the suppression is disputed (ADR-026), which makes it risk again.
func TestRiskSeverityCounts(t *testing.T) {
	t.Parallel()

	vulnerabilities := []store.Vulnerability{
		{Fingerprint: "open", Severity: store.SeverityLevelCritical, Status: "detected"},
		{Fingerprint: "accepted", Severity: store.SeverityLevelHigh, Status: "detected"},
		{Fingerprint: "fp", Severity: store.SeverityLevelHigh, Status: "detected"},
		{Fingerprint: "fixed", Severity: store.SeverityLevelLow, Status: "resolved"},
		{Fingerprint: "nosec", Severity: store.SeverityLevelLow, Status: "suppressed"},
		{Fingerprint: "contested", Severity: store.SeverityLevelMedium, Status: "suppressed"},
	}
	acceptances := []store.FindingAcceptance{
		{Fingerprint: "accepted", ReasonKind: "risk_accepted"},
		{Fingerprint: "fp", ReasonKind: "false_positive"},
	}
	disputed := map[string]struct{}{"contested": {}}

	counts := riskSeverityCounts(vulnerabilities, acceptances, disputed)
	if counts.Critical != 1 || counts.High != 1 || counts.Low != 0 {
		t.Fatalf("counts = %+v, want critical=1 high=1 low=0", counts)
	}
	if counts.Medium != 1 {
		t.Fatalf("medium = %d, want 1 (disputed suppression counts as risk)", counts.Medium)
	}
	if counts.AcceptedRisk != 1 {
		t.Fatalf("accepted_risk = %d, want 1 (accepted risk counts, flagged)", counts.AcceptedRisk)
	}
}

func TestOpenMarkedKEVCountUsesRiskSemantics(t *testing.T) {
	t.Parallel()

	vulnerabilities := []store.Vulnerability{
		{Fingerprint: "open", Status: "detected", KEV: true},
		{Fingerprint: "accepted", Status: "detected", KEV: true},
		{Fingerprint: "fp", Status: "detected", KEV: true},
		{Fingerprint: "resolved", Status: "resolved", KEV: true},
		{Fingerprint: "suppressed", Status: "suppressed", KEV: true},
		{Fingerprint: "disputed", Status: "suppressed", KEV: true},
		{Fingerprint: "not-kev", Status: "detected", KEV: false},
	}
	acceptances := []store.FindingAcceptance{
		{Fingerprint: "accepted", ReasonKind: "risk_accepted"},
		{Fingerprint: "fp", ReasonKind: "false_positive"},
	}

	if count := openMarkedKEVCount(vulnerabilities, acceptances, map[string]struct{}{"disputed": {}}); count != 3 {
		t.Fatalf("count = %d, want 3 (open, accepted, disputed)", count)
	}
}

func TestReleaseKEVOpenUsesPinnedSnapshotRiskSemantics(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	srv.cfg.KEV = config.KEVConfig{Enabled: true, CISA: config.KEVSourceConfig{Enabled: true}}
	ctx := context.Background()
	repo := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	pinnedSnapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, uniqueName(t, "release-pinned"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot(pinned): %v", err)
	}
	if _, err := srv.queries.UpsertRelease(ctx, store.UpsertReleaseParams{
		RepoID: repo.ID, RefID: ref.ID, SnapshotID: &pinnedSnapshot.ID, Version: "v1.0.0", Source: store.ReleaseSourceTag,
	}); err != nil {
		t.Fatalf("UpsertRelease: %v", err)
	}

	aliasCVE := strings.ToUpper("CVE-2099-" + uuid.NewString()[:8])
	bareCVE := strings.ToUpper("CVE-2099-" + uuid.NewString()[:8])
	advisory, err := srv.queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{
		CanonicalID: "GHSA-" + uuid.NewString(), Title: "alias KEV", Description: "", Severity: dbgen.SeverityLevelMedium, CweIds: []string{},
	})
	if err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}
	if err := srv.queries.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{AdvisoryID: advisory.ID, Alias: aliasCVE}); err != nil {
		t.Fatalf("UpsertAdvisoryAlias: %v", err)
	}
	seedKEVEntries(t, srv, "cisa", []kev.Entry{{CVEID: aliasCVE}, {CVEID: bareCVE}})

	createFinding := func(fingerprint string, severity dbgen.SeverityLevel, status, identifier string, advisoryID uuid.NullUUID) {
		t.Helper()
		if _, createErr := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
			Type: "dependency", SnapshotID: pinnedSnapshot.ID, Title: fingerprint,
			PrimaryIdentifierKind: "cve", PrimaryIdentifierValue: identifier,
			OriginalSeverity: severity, Severity: severity, Status: status,
			ScannerName: "unit-test", Fingerprint: fingerprint, AdvisoryID: advisoryID,
		}); createErr != nil {
			t.Fatalf("CreateVulnerability(%s): %v", fingerprint, createErr)
		}
	}
	createFinding("alias-medium", dbgen.SeverityLevelMedium, "detected", "GHSA-ignored", uuid.NullUUID{UUID: advisory.ID, Valid: true})
	createFinding("bare-accepted", dbgen.SeverityLevelHigh, "detected", bareCVE, uuid.NullUUID{})
	createFinding("high-unlisted", dbgen.SeverityLevelHigh, "detected", "CVE-2099-00001", uuid.NullUUID{})
	createFinding("false-positive", dbgen.SeverityLevelMedium, "detected", bareCVE, uuid.NullUUID{})
	createFinding("disputed-suppressed", dbgen.SeverityLevelLow, "suppressed", bareCVE, uuid.NullUUID{})
	createFinding("resolved", dbgen.SeverityLevelCritical, "resolved", bareCVE, uuid.NullUUID{})
	for _, acceptance := range []store.AcceptFindingInput{
		{RepoID: repo.ID, Fingerprint: "bare-accepted", ReasonKind: "risk_accepted", Reason: "accepted risk"},
		{RepoID: repo.ID, Fingerprint: "false-positive", ReasonKind: "false_positive", Reason: "not vulnerable"},
	} {
		if _, acceptanceErr := srv.queries.UpsertFindingAcceptance(ctx, acceptance); acceptanceErr != nil {
			t.Fatalf("UpsertFindingAcceptance(%s): %v", acceptance.Fingerprint, acceptanceErr)
		}
	}
	if _, err := srv.db.ExecContext(ctx, `INSERT INTO finding_disputes (repo_id, fingerprint, reason) VALUES ($1, $2, $3)`, repo.ID, "disputed-suppressed", "contested"); err != nil {
		t.Fatalf("insert dispute: %v", err)
	}

	newerSnapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, uniqueName(t, "newer"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot(newer): %v", err)
	}
	if _, err := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type: "dependency", SnapshotID: newerSnapshot.ID, Title: "newer-only", PrimaryIdentifierKind: "cve", PrimaryIdentifierValue: bareCVE,
		OriginalSeverity: dbgen.SeverityLevelCritical, Severity: dbgen.SeverityLevelCritical, Status: "detected", ScannerName: "unit-test", Fingerprint: "newer-only",
	}); err != nil {
		t.Fatalf("CreateVulnerability(newer): %v", err)
	}

	recorder := httptest.NewRecorder()
	srv.handleListReleases(recorder, newRepoRequest(t, admin, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/releases", "github", org.Slug, repo.Slug))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list releases = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data []store.ReleaseWithRisk `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode releases: %v", err)
	}
	if len(response.Data) != 1 || response.Data[0].KEVOpen == nil {
		t.Fatalf("release KEV posture = %+v, want one release with kev_open=3", response.Data)
	}
	if got := *response.Data[0].KEVOpen; got != 3 {
		t.Fatalf("release kev_open = %d, want 3", got)
	}
	if response.Data[0].CriticalCount != 0 || response.Data[0].HighCount != 2 || response.Data[0].MediumCount != 1 || response.Data[0].LowCount != 1 {
		t.Fatalf("release risk posture = %+v, want critical=0 high=2 medium=1 low=1", response.Data[0])
	}
}

func TestRiskOnlyKEVListMatchesOpenKEVCount(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, "risk-only-kev", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	findings := make([]store.Vulnerability, 0, 6)
	createFinding := func(fingerprint, status string) {
		identifier := strings.ToUpper("CVE-2099-" + uuid.NewString())
		seedKEVEntries(t, srv, "cisa", []kev.Entry{{CVEID: identifier}})
		finding, createErr := srv.queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
			Type: "dependency", SnapshotID: snapshot.ID, Title: fingerprint,
			PrimaryIdentifierKind: "cve", PrimaryIdentifierValue: identifier,
			OriginalSeverity: dbgen.SeverityLevelHigh, Severity: dbgen.SeverityLevelHigh,
			Status: status, ScannerName: "unit-test", Fingerprint: fingerprint,
		})
		if createErr != nil {
			t.Fatalf("CreateVulnerability(%s): %v", fingerprint, createErr)
		}
		findings = append(findings, *finding)
	}

	createFinding("open", "detected")
	createFinding("accepted", "detected")
	createFinding("false-positive", "detected")
	createFinding("disputed-suppressed", "suppressed")
	createFinding("suppressed", "suppressed")
	createFinding("resolved", "resolved")

	for _, acceptance := range []store.AcceptFindingInput{
		{RepoID: repo.ID, Fingerprint: "accepted", ReasonKind: "risk_accepted", Reason: "accepted risk"},
		{RepoID: repo.ID, Fingerprint: "false-positive", ReasonKind: "false_positive", Reason: "not vulnerable"},
	} {
		if _, err := srv.queries.UpsertFindingAcceptance(ctx, acceptance); err != nil {
			t.Fatalf("UpsertFindingAcceptance(%s): %v", acceptance.Fingerprint, err)
		}
	}
	if _, err := srv.db.ExecContext(ctx, `INSERT INTO finding_disputes (repo_id, fingerprint, reason) VALUES ($1, $2, $3)`, repo.ID, "disputed-suppressed", "suppression is contested"); err != nil {
		t.Fatalf("insert dispute: %v", err)
	}
	for index := range findings {
		findings[index].KEV = true
	}

	wantTotal := openMarkedKEVCount(findings, []store.FindingAcceptance{
		{Fingerprint: "accepted", ReasonKind: "risk_accepted"},
		{Fingerprint: "false-positive", ReasonKind: "false_positive"},
	}, map[string]struct{}{"disputed-suppressed": {}})
	if wantTotal != 3 {
		t.Fatalf("open KEV count = %d, want 3", wantTotal)
	}
	if _, total, err := srv.queries.ListVulnerabilitiesBySnapshotDynamic(ctx, snapshot.ID, "type::text = $2", []interface{}{"dependency"}, true, "", 50, 0); err != nil || total != wantTotal {
		t.Fatalf("dynamic risk-only list total/error = %d/%v, want %d/nil", total, err, wantTotal)
	}

	for _, query := range []string{"risk_only=true", "risk_only=true&q=type:dependency"} {
		recorder := httptest.NewRecorder()
		srv.handleGetRefFindings(recorder, newRepoRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/repos/"+repo.Slug+"/findings?ref=main&"+query, "github", org.Slug, repo.Slug))
		if recorder.Code != http.StatusOK {
			t.Fatalf("risk-only list (%s) = %d: %s", query, recorder.Code, recorder.Body.String())
		}
		var response findingsListResponse
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatalf("decode risk-only list (%s): %v", query, err)
		}
		if response.Pagination.Total != wantTotal || len(response.Data) != wantTotal {
			t.Fatalf("risk-only list (%s) total/data = %d/%d, want %d/%d", query, response.Pagination.Total, len(response.Data), wantTotal, wantTotal)
		}
	}

	orgFingerprints := make(map[string]struct{}, wantTotal)
	for page := 1; page <= 2; page++ {
		recorder := httptest.NewRecorder()
		path := "/api/v1/orgs/github/" + org.Slug + "/vulnerabilities?risk_only=true&per_page=2&page=" + strconv.Itoa(page)
		srv.handleListOrgVulnerabilities(recorder, newOrgRequest(t, member, http.MethodGet, path, "github", org.Slug))
		if recorder.Code != http.StatusOK {
			t.Fatalf("org risk-only list page %d = %d: %s", page, recorder.Code, recorder.Body.String())
		}
		var response struct {
			Data       []orgVulnerabilityResponse `json:"data"`
			Pagination struct {
				Total int `json:"total"`
			} `json:"pagination"`
		}
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatalf("decode org risk-only list page %d: %v", page, err)
		}
		wantPageSize := 2
		if page == 2 {
			wantPageSize = 1
		}
		if response.Pagination.Total != wantTotal || len(response.Data) != wantPageSize {
			t.Fatalf("org risk-only list page %d total/data = %d/%d, want %d/%d", page, response.Pagination.Total, len(response.Data), wantTotal, wantPageSize)
		}
		for _, vulnerability := range response.Data {
			orgFingerprints[vulnerability.Fingerprint] = struct{}{}
		}
	}
	for _, fingerprint := range []string{"open", "accepted", "disputed-suppressed"} {
		if _, ok := orgFingerprints[fingerprint]; !ok {
			t.Fatalf("org risk-only list missing eligible fingerprint %q: %#v", fingerprint, orgFingerprints)
		}
	}
}

func TestAddKEVOpenCount(t *testing.T) {
	t.Parallel()

	total := 2
	entry := 3
	destination := &total
	destination = addKEVOpenCount(destination, &entry, true)
	if destination == nil || *destination != 5 {
		t.Fatalf("total = %v, want 5", destination)
	}

	destination = addKEVOpenCount(destination, nil, true)
	if destination != nil {
		t.Fatalf("total = %v, want unavailable", destination)
	}
}

func TestCountTrendSnapshotSeveritiesExcludesFalsePositives(t *testing.T) {
	t.Parallel()

	vulnerabilities := []store.Vulnerability{
		{Fingerprint: "sast-open", Type: "sast", Severity: store.SeverityLevelHigh, Status: "detected"},
		{Fingerprint: "sast-fp", Type: "sast", Severity: store.SeverityLevelHigh, Status: "detected"},
		{Fingerprint: "dep-fp", Type: "dependency", Severity: store.SeverityLevelCritical, Status: "detected"},
	}
	kinds := map[string]string{"sast-fp": "false_positive", "dep-fp": "false_positive"}

	findings, vulns := countTrendSnapshotSeverities(vulnerabilities, kinds, nil)
	if findings.High != 1 {
		t.Fatalf("findings.High = %d, want 1 (FP excluded)", findings.High)
	}
	if vulns.Critical != 0 {
		t.Fatalf("vulns.Critical = %d, want 0 (FP excluded)", vulns.Critical)
	}
}

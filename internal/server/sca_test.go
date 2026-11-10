package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/cache"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/provider"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/scanner"
	"github.com/hibouhq/hibou/internal/store"
)

func TestSCACoverage(t *testing.T) {
	s := &Server{}
	s.cfg.DepInventory.Enabled, s.cfg.DepInventory.OnPush = true, true
	now := time.Now()
	before := now.Add(-time.Minute)
	cases := []struct {
		name     string
		enrolled bool
		o        store.SCAObservation
		want     string
	}{
		{"discovery is not clean", false, store.SCAObservation{}, "not_monitored"},
		{"snapshot alone is not SCA", true, store.SCAObservation{CommitSHA: "a"}, "not_assessed"},
		{"queued", true, store.SCAObservation{JobStatus: "pending"}, "queued"},
		{"extracting", true, store.SCAObservation{JobStatus: "processing"}, "extracting"},
		{"failed extraction", true, store.SCAObservation{JobStatus: "failed", JobError: "clone denied"}, "failed"},
		{"no files", true, store.SCAObservation{Detail: "no lockfile or manifest recognised at this commit", ProducerOutcome: "partial"}, "unsupported"},
		{"all excluded", true, store.SCAObservation{Detail: "all recognized dependency files were excluded", ProducerOutcome: "partial"}, "partial"},
		{"no advisory scan", true, store.SCAObservation{HasInventory: true, HasComponents: true}, "inventory_ready"},
		{"completed empty extraction", true, store.SCAObservation{HasInventory: true, ProducerOutcome: "completed"}, "complete"},
		{"partial empty extraction", true, store.SCAObservation{HasInventory: true, ProducerOutcome: "partial", Detail: "Some files could not be read"}, "partial"},
		{"empty upload without producer evidence", true, store.SCAObservation{HasInventory: true}, "inventory_ready"},
		{"imported dependency results", true, store.SCAObservation{HasInventory: true, HasReportedFindings: true}, "reported"},
		{"matching", true, store.SCAObservation{HasInventory: true, ScanStatus: "running"}, "matching"},
		{"advisory failure", true, store.SCAObservation{HasInventory: true, ScanStatus: "failed"}, "failed"},
		{"complete", true, store.SCAObservation{HasInventory: true, ScanStatus: "complete", LastAssessed: &now}, "complete"},
		{"partial module", true, store.SCAObservation{HasInventory: true, ScanStatus: "complete", ProducerOutcome: "partial"}, "partial"},
		{"partial provider", true, store.SCAObservation{HasInventory: true, ScanStatus: "complete", ProviderFailed: true}, "partial"},
		{"new head", true, store.SCAObservation{HeadCommit: "b", CommitSHA: "a", HasInventory: true, ScanStatus: "complete"}, "outdated"},
		{"new head preserves prior results", true, store.SCAObservation{HeadCommit: "b", PreviousCommit: "a", PreviousInventory: true}, "outdated"},
		{"older in-flight job", true, store.SCAObservation{HeadCommit: "b", CommitSHA: "b", JobCommit: "a", JobStatus: "processing", HasInventory: true, ScanStatus: "complete"}, "complete"},
		{"CI supersedes extraction failure", true, store.SCAObservation{HeadCommit: "b", CommitSHA: "b", JobStatus: "failed", LastAttempt: &before, LastAssessed: &now, HasInventory: true, ScanStatus: "complete", ProducerOutcome: "failed"}, "complete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.scaCoverage(tc.enrolled, tc.o)
			if got.State != tc.want {
				t.Fatalf("state=%s want=%s", got.State, tc.want)
			}
		})
	}
	s.cfg.DepInventory.Enabled = false
	if got := s.scaCoverage(true, store.SCAObservation{}); got.State != "disabled" {
		t.Fatalf("disabled extraction state=%s", got.State)
	}
	if got := s.scaCoverage(true, store.SCAObservation{HasInventory: true, ScanStatus: "complete"}); got.State != "complete" {
		t.Fatalf("disabled extraction must preserve uploaded coverage, got %s", got.State)
	}
}

func newSCAFixture(t *testing.T) (*Server, *store.Organization, *store.User, *store.User, *store.ForgeRepository) {
	t.Helper()
	s, org, admin, viewer := newDiscoveryTestServer(t)
	ctx := context.Background()
	org.ForgeAccountID, org.ForgeAccountLogin = uuid.NewString(), org.Slug
	if err := s.queries.SetOrganizationForgeAccount(ctx, org.ID, org.ForgeAccountID, org.Slug); err != nil {
		t.Fatal(err)
	}
	repoID := uuid.NewString()
	inv, err := s.queries.UpsertForgeRepository(ctx, store.ForgeRepository{
		Provider: org.Provider, AccountLogin: org.Slug, AccountID: org.ForgeAccountID,
		Owner: org.Slug, Name: "app", FullName: org.Slug + "/app", ProviderRepoID: &repoID, DefaultBranch: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.DepInventory.Enabled, s.cfg.DepInventory.OnPush = true, true
	s.cfg.SecretScan.Enabled = true
	t.Cleanup(func() {
		_, _ = s.db.Exec(`DELETE FROM organizations WHERE id=$1`, org.ID)
		_, _ = s.db.Exec(`DELETE FROM forge_repositories WHERE id=$1`, inv.Repository.ID)
	})
	return s, org, admin, viewer, inv.Repository
}

func TestEnableSCAEnrollmentAndIdempotence(t *testing.T) {
	s, org, admin, _, inv := newSCAFixture(t)
	ctx := context.Background()
	w := httptest.NewRecorder()
	s.handleEnableSCA(w, newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{"provider_ids": []string{inv.ProviderKey, inv.ProviderKey}}))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	var response struct {
		Data struct {
			Results []enableSCAResult `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	results := response.Data.Results
	if len(results) != 2 || results[0].Status != "accepted" || results[0].JobID == nil || *results[0].JobID != *results[1].JobID {
		t.Fatalf("results=%+v", results)
	}
	repo, err := s.queries.GetRepositoryBySlug(ctx, org.ID, results[0].RepoSlug)
	if err != nil || repo == nil {
		t.Fatalf("repo=%v err=%v", repo, err)
	}
	if _, err := s.queries.VerifiedForgeRepositoryTarget(ctx, repo.ID); err != nil {
		t.Fatalf("enrollment did not capture immutable identity: %v", err)
	}
	var secrets int
	if err := s.db.QueryRow(`SELECT count(*) FROM secret_scan_jobs WHERE repo_id=$1`, repo.ID).Scan(&secrets); err != nil || secrets != 0 {
		t.Fatalf("Enable SCA scheduled secret scans: count=%d err=%v", secrets, err)
	}
	if _, err := s.db.Exec(`UPDATE dep_extraction_jobs SET status='processing' WHERE id=$1`, results[0].JobID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, _, created, err := s.enableSCA(ctx, org, inv.ProviderKey)
			if err != nil || created || result.JobID == nil || *result.JobID != *results[0].JobID {
				t.Errorf("concurrent result=%+v created=%v err=%v", result, created, err)
			}
		}()
	}
	wg.Wait()
	jobs, err := s.queries.ListDepExtractionJobsByRepo(ctx, repo.ID, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs=%d err=%v", len(jobs), err)
	}
}

func TestEnableSCADenialsAndBulkIsolation(t *testing.T) {
	s, org, admin, viewer, inv := newSCAFixture(t)
	for _, tc := range []struct {
		name string
		user *store.User
		body any
		want int
	}{
		{"viewer", viewer, map[string]any{"provider_ids": []string{inv.ProviderKey}}, http.StatusForbidden},
		{"anonymous", nil, map[string]any{"provider_ids": []string{inv.ProviderKey}}, http.StatusUnauthorized},
		{"empty", admin, map[string]any{"provider_ids": []string{}}, http.StatusBadRequest},
		{"oversized", admin, map[string]any{"provider_ids": make([]string, 51)}, http.StatusBadRequest},
		{"untrusted metadata", admin, map[string]any{"provider_ids": []string{inv.ProviderKey}, "clone_url": "https://example.com"}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleEnableSCA(w, newEnrollRequest(t, tc.user, org.Provider, org.Slug, tc.body))
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body)
			}
		})
	}
	s.cfg.DepInventory.Enabled = false
	w := httptest.NewRecorder()
	s.handleEnableSCA(w, newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{"provider_ids": []string{inv.ProviderKey}}))
	if w.Code != http.StatusConflict {
		t.Fatalf("disabled status=%d body=%s", w.Code, w.Body)
	}
	if repo, _ := s.queries.GetRepositoryByProviderID(context.Background(), org.ID, org.Provider, inv.ProviderKey); repo != nil {
		t.Fatal("disabled request enrolled repository")
	}
	s.cfg.DepInventory.Enabled = true
	w = httptest.NewRecorder()
	s.handleEnableSCA(w, newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{"provider_ids": []string{"foreign/not-ours", inv.ProviderKey}}))
	var response struct {
		Data struct {
			Results []enableSCAResult `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data.Results) != 2 || response.Data.Results[0].Status != "failed" || response.Data.Results[1].Status != "accepted" {
		t.Fatalf("bulk result=%s", w.Body)
	}
}

func TestEnableSCARefusesReboundIdentity(t *testing.T) {
	s, org, _, _, inv := newSCAFixture(t)
	ctx := context.Background()
	result, repo, _, err := s.enableSCA(ctx, org, inv.ProviderKey)
	if err != nil {
		t.Fatal(err)
	}
	newID := uuid.NewString()
	inv.ProviderRepoID = &newID
	if _, err := s.queries.UpsertForgeRepository(ctx, *inv); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.enableSCA(ctx, org, inv.ProviderKey); err == nil {
		t.Fatal("rebound identity was accepted")
	}
	jobs, err := s.queries.ListDepExtractionJobsByRepo(ctx, repo.ID, 10)
	if err != nil || len(jobs) != 1 || jobs[0].ID != *result.JobID {
		t.Fatalf("identity failure changed queue: jobs=%v err=%v", jobs, err)
	}
	if _, err := s.executeDepExtractionJob(ctx, jobs[0]); err == nil {
		t.Fatal("worker accepted changed identity")
	}
}

type scaFixtureProvider struct{}

type scaContentForge struct {
	discoveryTestForgeProvider
	repository forge.Repository
}

type scaPRContentForge struct {
	*scaContentForge
	statuses []forge.CommitStatus
}

func (p *scaPRContentForge) ComparePatch(context.Context, string, string, string, string) (*forge.PatchDiff, error) {
	return &forge.PatchDiff{Files: []forge.PatchFile{{Path: "README.md", Status: "modified"}}}, nil
}

func (p *scaPRContentForge) GetFileContent(_ context.Context, _, _, path, _ string) ([]byte, error) {
	if path == repoconfig.RepoConfigPath {
		return []byte("version: 1\nquality_gates:\n  - branches: ['*']\n    code:\n      max_critical: 0\n"), nil
	}
	return nil, forge.ErrFileNotFound
}

func (p *scaPRContentForge) CreateCommitStatus(_ context.Context, _, _, _ string, status forge.CommitStatus) error {
	p.statuses = append(p.statuses, status)
	return nil
}

func (p *scaContentForge) GetRepository(context.Context, string, string) (*forge.Repository, error) {
	return &p.repository, nil
}

func (scaFixtureProvider) Name() string                  { return "sca-fixture" }
func (scaFixtureProvider) SupportedEcosystems() []string { return []string{"npm"} }
func (scaFixtureProvider) BatchSize() int                { return 100 }
func (scaFixtureProvider) QueryPackages(_ context.Context, queries []provider.PackageQuery) ([]provider.AdvisoryResult, error) {
	for _, q := range queries {
		if q.Name == "lodash" && q.Version == "4.17.20" {
			return []provider.AdvisoryResult{{
				ProviderName: "sca-fixture", ProviderID: "CVE-2021-23337",
				Title:   "Controlled lodash vulnerable-package fixture",
				RawData: json.RawMessage(`{"id":"CVE-2021-23337","fixture":true}`),
				AffectedRanges: []advisory.AffectedRange{{
					Ecosystem: "npm", PackageName: "lodash", Introduced: "0", Fixed: "4.17.21",
				}},
			}}, nil
		}
	}
	return nil, nil
}

func TestSCAWithoutUploadExtractsAndMatches(t *testing.T) {
	s, org, _, _, inv := newSCAFixture(t)
	ctx := context.Background()
	origin := filepath.Join(t.TempDir(), "origin.git")
	if err := os.Mkdir(origin, 0o700); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = origin
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com", "GIT_CONFIG_NOSYSTEM=1", "HOME="+origin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("config", "uploadpack.allowFilter", "true")
	for name, content := range map[string]string{
		"package.json":      `{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}`,
		"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}}}`,
	} {
		if err := os.WriteFile(filepath.Join(origin, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("add", ".")
	git("commit", "-qm", "fixture")
	inv.HTMLURL = strings.TrimSuffix(origin, ".git")
	if _, err := s.queries.UpsertForgeRepository(ctx, *inv); err != nil {
		t.Fatal(err)
	}
	s.forges[org.Provider] = &scaContentForge{
		discoveryTestForgeProvider: discoveryTestForgeProvider{id: org.Provider},
		repository: forge.Repository{Owner: inv.Owner, OwnerID: org.ForgeAccountID, Name: inv.Name,
			ProviderRepoID: *inv.ProviderRepoID, CloneURL: origin},
	}
	result, repo, _, err := s.enableSCA(ctx, org, inv.ProviderKey)
	if err != nil {
		t.Fatal(err)
	}
	s.bus = events.New(s.log)
	s.repoConfigLoader = repoconfig.NewLoader(s.forges, s.log)
	trigger := &advisoryScannerStub{calls: make(chan advisoryScanCall, 1)}
	s.advisoryScanner, s.advisoryProviders = trigger, []string{"sca-fixture"}
	job, err := s.queries.GetDepExtractionJob(ctx, *result.JobID)
	if err != nil {
		t.Fatal(err)
	}
	snapshotID, err := s.executeDepExtractionJob(ctx, job)
	if err != nil || snapshotID == nil {
		t.Fatalf("extract without uploads: snapshot=%v err=%v", snapshotID, err)
	}
	select {
	case call := <-trigger.calls:
		if call.SnapshotID != *snapshotID {
			t.Fatalf("advisory scan targets wrong snapshot: %+v", call)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("extraction did not trigger advisory matching")
	}
	// Execute the automatically requested match with a controlled provider,
	// using the real cache, advisory ingestion and vulnerability persistence.
	service := scanner.New(s.queries, cache.New(s.queries, cache.Config{DefaultTTL: time.Hour}, s.log),
		advisory.NewIngester(s.queries, s.log), s.bus,
		map[string]provider.AdvisoryProvider{"sca-fixture": scaFixtureProvider{}}, s.log)
	if _, err := service.RunScan(ctx, *snapshotID, []string{"sca-fixture"}, "system"); err != nil {
		var detail string
		lookupErr := s.db.QueryRow(`SELECT COALESCE(sp.error_message,'') FROM scan_providers sp JOIN scans sc ON sc.id=sp.scan_id WHERE sc.snapshot_id=$1 ORDER BY sc.created_at DESC LIMIT 1`, *snapshotID).Scan(&detail)
		t.Fatalf("advisory matching: %v, detail=%s, lookup=%v", err, detail, lookupErr)
	}
	findings, err := s.queries.ListAllVulnerabilitiesBySnapshot(ctx, *snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range findings {
		if finding.PrimaryIdentifierValue == "CVE-2021-23337" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CVE-2021-23337 from extracted lodash; findings=%+v", findings)
	}
	components, err := s.queries.ListComponentsBySnapshot(ctx, *snapshotID)
	if err != nil || len(components) == 0 {
		t.Fatalf("components=%v err=%v", components, err)
	}
	snapshot, err := s.queries.GetSnapshotByID(ctx, *snapshotID)
	if err != nil || snapshot == nil || snapshot.Status != store.SnapshotStatusComplete {
		t.Fatalf("scan-only snapshot not readable: snapshot=%v err=%v", snapshot, err)
	}
	if uploaded, err := s.queries.RepoHasUploadActivity(ctx, repo.ID); err != nil || uploaded {
		t.Fatalf("test must not depend on any upload: uploaded=%v err=%v", uploaded, err)
	}
	t.Run("documentation-only PR gets a completed head inventory", func(t *testing.T) {
		prProvider := &scaPRContentForge{scaContentForge: s.forges[org.Provider].(*scaContentForge)}
		s.forges[org.Provider] = prProvider
		if _, err := s.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{LatestCommitSHA: &snapshot.CommitSHA}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(origin, "README.md"), []byte("Synthetic documentation change\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		git("add", "README.md")
		git("commit", "-qm", "documentation only")
		command := exec.Command("git", "rev-parse", "HEAD")
		command.Dir = origin
		output, err := command.Output()
		if err != nil {
			t.Fatal(err)
		}
		head := strings.TrimSpace(string(output))
		ref, err := s.queries.UpsertRef(ctx, repo.ID, "refs/pull/1", store.RefTypePullRequest, store.UpsertRefOptions{
			LatestCommitSHA: &head, MergeTargetRefID: &snapshot.RefID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.queries.CreatePlaceholderSnapshot(ctx, ref.ID, head); err != nil {
			t.Fatal(err)
		}
		deltaStore := delta.NewStoreAdapter(s.queries)
		publisher := forge.NewGatePublisher(s.forges, delta.NewService(deltaStore, s.log, deltaStore), s.bus,
			forge.NewGatePublisherStoreAdapter(s.queries), repoConfigGateLoader{loader: s.repoConfigLoader}, nil, "", s.log)
		publisher.SetAdvisoryScanEnabled(true)
		publisher.PublishGateForRef(ctx, ref.ID)
		if len(prProvider.statuses) != 1 || prProvider.statuses[0].State != "pending" {
			t.Fatalf("pending head guard lost: %+v", prProvider.statuses)
		}
		if err := s.maybeEnqueuePRDepExtraction(ctx, repo, ref, head); err != nil {
			t.Fatal(err)
		}
		job, err := s.queries.GetLatestDepExtractionJobForRef(ctx, repo.ID, ref.Name)
		if err != nil || job == nil || job.Reason != store.DepExtractionReasonPullRequest {
			t.Fatalf("documentation-only PR not queued: job=%+v err=%v", job, err)
		}
		id, err := s.executeDepExtractionJob(ctx, job)
		if err != nil || id == nil {
			t.Fatalf("PR inventory failed: id=%v err=%v", id, err)
		}
		completed, err := s.queries.GetSnapshotByID(ctx, *id)
		if err != nil || completed == nil || completed.Status != store.SnapshotStatusComplete || completed.CommitSHA != head {
			t.Fatalf("PR head still awaits upload: snapshot=%+v err=%v", completed, err)
		}
		if _, err := service.RunScan(ctx, *id, []string{"sca-fixture"}, "system"); err != nil {
			t.Fatal(err)
		}
		publisher.PublishGateForRef(ctx, ref.ID)
		if len(prProvider.statuses) != 2 || prProvider.statuses[1].State != "success" {
			t.Fatalf("documentation-only PR gate did not complete: %+v", prProvider.statuses)
		}
	})
}
func TestSCAEnqueueRollback(t *testing.T) {
	s, org, _, _, inv := newSCAFixture(t)
	ctx := context.Background()
	tx, err := s.queries.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	repo, err := q.CreateRepository(ctx, org.ID, nil, inv.Name, "app", org.Provider, inv.ProviderKey, "main", "enrolled")
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := q.EnqueueSCAExtraction(ctx, store.EnqueueDepExtractionJobParams{RepoID: repo.ID, RefName: "main", Reason: store.DepExtractionReasonEnableSCA})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if persisted, err := s.queries.GetRepositoryByID(ctx, repo.ID); err != nil || persisted != nil {
		t.Fatalf("rolled-back enrollment persisted: repo=%v err=%v", persisted, err)
	}
	if persisted, err := s.queries.GetDepExtractionJob(ctx, job.ID); err != nil || persisted != nil {
		t.Fatalf("rolled-back queue persisted: job=%v err=%v", persisted, err)
	}
}

func TestSCABootstrapBoundsAndUploadedEvidence(t *testing.T) {
	s, org, _, _, inv := newSCAFixture(t)
	ctx := context.Background()
	for i := range 25 {
		copy := *inv
		copy.Name = fmt.Sprintf("app-%02d", i)
		copy.FullName = org.Slug + "/" + copy.Name
		id := uuid.NewString()
		copy.ProviderRepoID = &id
		row, err := s.queries.UpsertForgeRepository(ctx, copy)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM forge_repositories WHERE id=$1`, row.Repository.ID) })
		repo, err := s.queries.CreateRepository(ctx, org.ID, nil, copy.Name, copy.Name, org.Provider, row.Repository.ProviderKey, "main", "enrolled")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			ref, err := s.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := s.queries.CreatePlaceholderSnapshot(ctx, ref.ID, strings.Repeat("a", 40))
			if err != nil {
				t.Fatal(err)
			}
			s.bus = events.New(s.log)
			if err := s.ingestExtractedInventory(ctx, snapshot, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}]}`)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, want := range []int64{10, 10, 4, 0} {
		count, err := s.queries.BootstrapSCA(ctx, org.ID, 100)
		if err != nil || count != want {
			t.Fatalf("per-org bounded bootstrap count=%d want=%d err=%v", count, want, err)
		}
	}
	observations, err := s.queries.ListSCAObservations(ctx, org.ID, uuid.Nil, "", store.RefTypeBranch)
	if err != nil || len(observations) != 25 {
		t.Fatalf("batched observations=%d err=%v", len(observations), err)
	}
}
func TestSCABootstrapAndCoverageQueries(t *testing.T) {
	s, org, _, _, inv := newSCAFixture(t)
	ctx := context.Background()
	if _, err := s.queries.BootstrapSCA(ctx, org.ID, 100); err != nil {
		t.Fatal(err)
	}

	t.Run("empty extraction source", func(t *testing.T) {
		s, org, admin, _, inv := newSCAFixture(t)
		ctx := context.Background()
		repo, err := s.queries.CreateRepository(ctx, org.ID, nil, inv.Name, "empty-app", org.Provider, inv.ProviderKey, "main", "enrolled")
		if err != nil {
			t.Fatal(err)
		}
		ref, err := s.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{})
		if err != nil {
			t.Fatal(err)
		}
		commit := strings.Repeat("a", 40)
		snapshot, err := s.queries.CreatePlaceholderSnapshot(ctx, ref.ID, commit)
		if err != nil {
			t.Fatal(err)
		}
		run, err := s.queries.InsertDepExtractionRun(ctx, store.InsertDepExtractionRunParams{
			RepoID: repo.ID, SnapshotID: snapshot.ID, CommitSHA: commit,
			InputDigest: strings.Repeat("b", 64), ExtractorVersion: "test",
			SHA256: strings.Repeat("c", 64), SizeBytes: 100, ComponentCount: 0,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.queries.AttachInventorySource(ctx, snapshot.ID, "sbom:"+depInventoryArtifactFilename, nil, nil, &run.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.queries.UpsertSnapshotProducerRun(ctx, snapshot.ID, store.ProducerRunInput{
			Producer: depInventoryProducer, Scope: store.ProducerScopeFull, ScopeDeclared: true, Outcome: store.ProducerOutcomeCompleted,
		}); err != nil {
			t.Fatal(err)
		}
		observations, err := s.queries.ListSCAObservations(ctx, org.ID, repo.ID, "", store.RefTypeBranch)
		if err != nil {
			t.Fatal(err)
		}
		o := observations[repo.ID]
		if !o.HasInventory || o.HasComponents || o.InventorySource != "repository" || o.InventoryCommit != commit {
			t.Fatalf("empty extraction evidence lost: %+v", o)
		}
		if got := s.scaCoverage(true, o); got.State != "complete" || !got.HasInventory {
			t.Fatalf("completed empty extraction coverage=%+v", got)
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("provider", org.Provider)
		route.URLParams.Add("slug", org.Slug)
		route.URLParams.Add("repoSlug", repo.Slug)
		request = request.WithContext(context.WithValue(auth.WithUser(request.Context(), admin), chi.RouteCtxKey, route))
		recorder := httptest.NewRecorder()
		s.handleGetRepo(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("repository detail status=%d body=%s", recorder.Code, recorder.Body)
		}
		var response struct {
			Data repoVisibilityResponse `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Data.SCA == nil || response.Data.SCA.InventorySource != "repository" || response.Data.SCA.State != "complete" {
			t.Fatalf("repository detail omitted inventory provenance: %+v", response.Data.SCA)
		}
	})
	if repo, _ := s.queries.GetRepositoryByProviderID(ctx, org.ID, org.Provider, inv.ProviderKey); repo != nil {
		t.Fatal("bootstrap must not enroll discovered repositories")
	}
	repo, err := s.queries.CreateRepository(ctx, org.ID, nil, inv.Name, "app", org.Provider, inv.ProviderKey, "main", "enrolled")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.queries.BootstrapSCA(ctx, org.ID, 100); err != nil {
		t.Fatal(err)
	}
	job, err := s.queries.GetLatestDepExtractionJobForRef(ctx, repo.ID, "main")
	if err != nil || job == nil {
		t.Fatalf("initial extraction not repaired: job=%v err=%v", job, err)
	}
	if _, err := s.queries.ListSCAObservations(ctx, org.ID, uuid.Nil, "", store.RefTypeBranch); err != nil {
		t.Fatalf("batched coverage query: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE dep_extraction_jobs SET status='failed',finished_at=now(),last_error='denied' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := s.queries.BootstrapSCA(ctx, org.ID, 100); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := s.queries.ListDepExtractionJobsByRepo(ctx, repo.ID, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("bootstrap retried exhausted failure: jobs=%d err=%v", len(jobs), err)
	}
	coverage, err := s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.State != "failed" || coverage.Detail != "denied" {
		t.Fatalf("coverage=%+v err=%v", coverage, err)
	}
}

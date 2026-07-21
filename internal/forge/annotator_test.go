package forge

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/events"
	storepkg "github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type mockForgeProvider struct {
	statuses []commitStatusCall
}

type mockRepoConfigLoader struct {
	weaknessGate      *delta.WeaknessGate
	enforcement       string
	err               error
	providerID        string
	owner             string
	repo              string
	defaultBranch     string
	targetBranch      string
	loadWeaknessCalls int
}

type commitStatusCall struct {
	owner  string
	repo   string
	sha    string
	status CommitStatus
}

func (m *mockForgeProvider) ID() string { return "github" }
func (m *mockForgeProvider) Installations(context.Context) ([]Installation, error) {
	return nil, nil
}
func (m *mockForgeProvider) ListRepositories(context.Context, ListReposOptions) ([]Repository, error) {
	return nil, ErrNotImplemented
}
func (m *mockForgeProvider) GetRepository(context.Context, string, string) (*Repository, error) {
	return nil, ErrNotImplemented
}
func (m *mockForgeProvider) ListBranches(context.Context, string, string) ([]Branch, error) {
	return nil, ErrNotImplemented
}
func (m *mockForgeProvider) GetBranch(context.Context, string, string, string) (*Branch, error) {
	return nil, ErrNotImplemented
}
func (m *mockForgeProvider) GetFileContent(context.Context, string, string, string, string) ([]byte, error) {
	return nil, ErrNotImplemented
}
func (m *mockForgeProvider) CreateOrUpdateFile(context.Context, string, string, string, string, string, []byte) error {
	return ErrNotImplemented
}
func (m *mockForgeProvider) CreateBranch(context.Context, string, string, string, string) error {
	return ErrNotImplemented
}
func (m *mockForgeProvider) CreatePullRequest(context.Context, string, string, CreatePROptions) (*PullRequest, error) {
	return nil, ErrNotImplemented
}
func (m *mockForgeProvider) ComparePatch(context.Context, string, string, string, string) (*PatchDiff, error) {
	return nil, nil
}

func (m *mockForgeProvider) CreateCommitStatus(_ context.Context, owner, repo, sha string, status CommitStatus) error {
	m.statuses = append(m.statuses, commitStatusCall{owner: owner, repo: repo, sha: sha, status: status})
	return nil
}
func (m *mockForgeProvider) ValidateWebhookPayload(*http.Request, string) ([]byte, error) {
	return nil, ErrNotImplemented
}
func (m *mockForgeProvider) ParseWebhookEvent(string, []byte) (WebhookEvent, error) {
	return nil, ErrNotImplemented
}
func (m *mockForgeProvider) OAuth2Config(string) *oauth2.Config { return nil }
func (m *mockForgeProvider) UserInfo(context.Context, *oauth2.Token) (*UserInfo, error) {
	return nil, ErrNotImplemented
}
func (m *mockForgeProvider) ListUserAccess(context.Context, *oauth2.Token) (UserAccess, error) {
	return UserAccess{}, nil
}

func (m *mockRepoConfigLoader) LoadWeaknessGate(_ context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (*delta.WeaknessGate, error) {
	m.loadWeaknessCalls++
	m.providerID = providerID
	m.owner = owner
	m.repo = repo
	m.defaultBranch = defaultBranch
	m.targetBranch = targetBranch
	return m.weaknessGate, m.err
}

func (m *mockRepoConfigLoader) LoadEnforcement(_ context.Context, _, _, _, _, _ string) (string, error) {
	return m.enforcement, nil
}

type annotatorStore struct {
	*deltaTestStore
	repos          map[uuid.UUID]dbgen.Repository
	snapshots      map[uuid.UUID]dbgen.Snapshot
	refs           map[uuid.UUID]dbgen.Ref
	latestSnapshot map[uuid.UUID]dbgen.Snapshot
	orgSlugs       map[uuid.UUID]string
	openPRRefs     map[uuid.UUID][]dbgen.Ref
	repoIDsByOrg   map[uuid.UUID][]uuid.UUID
	prChecks       []storepkg.UpsertPRCheckInput
}

type deltaTestStore struct {
	vulnsBySnapshot map[uuid.UUID][]storepkg.Vulnerability
	repoGates       map[uuid.UUID][]dbgen.QualityGate
	orgGates        map[uuid.UUID][]dbgen.QualityGate
}

func newAnnotatorStore() *annotatorStore {
	return &annotatorStore{
		deltaTestStore: &deltaTestStore{
			vulnsBySnapshot: map[uuid.UUID][]storepkg.Vulnerability{},
			repoGates:       map[uuid.UUID][]dbgen.QualityGate{},
			orgGates:        map[uuid.UUID][]dbgen.QualityGate{},
		},
		repos:          map[uuid.UUID]dbgen.Repository{},
		snapshots:      map[uuid.UUID]dbgen.Snapshot{},
		refs:           map[uuid.UUID]dbgen.Ref{},
		latestSnapshot: map[uuid.UUID]dbgen.Snapshot{},
		orgSlugs:       map[uuid.UUID]string{},
		openPRRefs:     map[uuid.UUID][]dbgen.Ref{},
		repoIDsByOrg:   map[uuid.UUID][]uuid.UUID{},
	}
}

func (m *deltaTestStore) ListAllVulnerabilitiesBySnapshot(_ context.Context, snapshotID uuid.UUID) ([]storepkg.Vulnerability, error) {
	return append([]storepkg.Vulnerability(nil), m.vulnsBySnapshot[snapshotID]...), nil
}

func (m *deltaTestStore) ListQualityGatesByRepo(_ context.Context, repoID uuid.UUID) ([]dbgen.QualityGate, error) {
	return append([]dbgen.QualityGate(nil), m.repoGates[repoID]...), nil
}

func (m *deltaTestStore) ListOrgWideQualityGates(_ context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error) {
	return append([]dbgen.QualityGate(nil), m.orgGates[orgID]...), nil
}

func (m *annotatorStore) GetRepoByID(_ context.Context, id uuid.UUID) (dbgen.Repository, error) {
	return m.repos[id], nil
}

func (m *annotatorStore) GetSnapshotByID(_ context.Context, id uuid.UUID) (dbgen.Snapshot, error) {
	return m.snapshots[id], nil
}

func (m *annotatorStore) GetRefByID(_ context.Context, id uuid.UUID) (dbgen.Ref, error) {
	return m.refs[id], nil
}

func (m *annotatorStore) GetLatestSnapshotByRef(_ context.Context, refID uuid.UUID) (dbgen.Snapshot, error) {
	return m.latestSnapshot[refID], nil
}

func (m *annotatorStore) UpsertPRCheck(_ context.Context, in storepkg.UpsertPRCheckInput) error {
	m.prChecks = append(m.prChecks, in)
	return nil
}

func (m *annotatorStore) GetOrgSlug(_ context.Context, orgID uuid.UUID) (string, error) {
	return m.orgSlugs[orgID], nil
}

func (m *annotatorStore) ListOpenPRRefs(_ context.Context, repoID uuid.UUID) ([]dbgen.Ref, error) {
	return m.openPRRefs[repoID], nil
}

func (m *annotatorStore) ListRepoIDsByOrg(_ context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	return m.repoIDsByOrg[orgID], nil
}

func (m *annotatorStore) ListUnsyncedPRCheckRefIDs(_ context.Context, _ int32) ([]uuid.UUID, error) {
	return nil, nil
}

func TestAnnotatorPostsFailureStatusForPRSnapshot(t *testing.T) {
	store := newAnnotatorStore()
	forgeProvider := &mockForgeProvider{}
	orgID := uuid.New()
	repoID := uuid.New()
	prRefID := uuid.New()
	targetRefID := uuid.New()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()

	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: orgID, Name: "acme/api", Slug: "api", Provider: "github", ProviderID: "acme/api"}
	store.refs[prRefID] = dbgen.Ref{ID: prRefID, RepoID: repoID, Name: "pr-1", RefType: dbgen.RefTypePullRequest, MergeTargetRefID: uuid.NullUUID{UUID: targetRefID, Valid: true}}
	store.refs[targetRefID] = dbgen.Ref{ID: targetRefID, RepoID: repoID, Name: "main", RefType: dbgen.RefTypeBranch}
	store.snapshots[prSnapshotID] = dbgen.Snapshot{ID: prSnapshotID, RefID: prRefID, CommitSha: "abc123", CreatedAt: time.Now().UTC()}
	store.latestSnapshot[targetRefID] = dbgen.Snapshot{ID: targetSnapshotID, RefID: targetRefID, CommitSha: "def456", CreatedAt: time.Now().UTC()}
	store.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{{ID: uuid.New(), Type: "dependency", Title: "CVE-2026-1234", Severity: storepkg.SeverityLevelCritical, Fingerprint: "fp-annotator"}}
	store.repoGates[repoID] = []dbgen.QualityGate{{ID: uuid.New(), OrgID: orgID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true}, Name: "strict", MaxCritical: 0, MaxHigh: 0, MaxMedium: sql.NullInt32{Int32: 0, Valid: true}, Enabled: true}}

	store.orgSlugs[orgID] = "acme-org"

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	// Blocking enforcement: a failing gate posts a real failure state.
	loader := &mockRepoConfigLoader{enforcement: "blocking"}
	annotator := NewAnnotator(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, loader, "https://hibou.example.com", zerolog.Nop())
	annotator.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": prSnapshotID.String()})

	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected 1 commit status call, got %d", len(forgeProvider.statuses))
	}
	call := forgeProvider.statuses[0]
	if call.owner != "acme" || call.repo != "api" {
		t.Fatalf("unexpected repo coordinates: %#v", call)
	}
	if call.status.State != "failure" || call.status.Context != securityStatusContext {
		t.Fatalf("unexpected commit status: %#v", call.status)
	}
	if len(store.prChecks) != 1 {
		t.Fatalf("expected 1 pr_check persisted, got %d", len(store.prChecks))
	}
	check := store.prChecks[0]
	if check.State != "failure" || check.Passed || check.Enforcement != "blocking" {
		t.Fatalf("unexpected persisted pr_check: %#v", check)
	}
	if check.ForgeSyncedAt == nil {
		t.Fatalf("expected pr_check to be marked forge-synced after a successful post")
	}
	if check.RefID == nil || *check.RefID != prRefID {
		t.Fatalf("expected pr_check ref_id %s, got %#v", prRefID, check.RefID)
	}
}

// TestAnnotatorAdvisoryDefaultNeverBlocks verifies the default (advisory) path
// posts a non-blocking success even when the gate fails, and records the neutral
// check-run conclusion in pr_checks. This is the "never break the build" default.
func TestAnnotatorAdvisoryDefaultNeverBlocks(t *testing.T) {
	store := newAnnotatorStore()
	forgeProvider := &mockForgeProvider{}
	orgID := uuid.New()
	repoID := uuid.New()
	prRefID := uuid.New()
	targetRefID := uuid.New()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()

	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: orgID, Name: "acme/api", Slug: "api", Provider: "github", ProviderID: "acme/api"}
	store.refs[prRefID] = dbgen.Ref{ID: prRefID, RepoID: repoID, Name: "refs/pull/7", RefType: dbgen.RefTypePullRequest, MergeTargetRefID: uuid.NullUUID{UUID: targetRefID, Valid: true}}
	store.refs[targetRefID] = dbgen.Ref{ID: targetRefID, RepoID: repoID, Name: "main", RefType: dbgen.RefTypeBranch}
	store.snapshots[prSnapshotID] = dbgen.Snapshot{ID: prSnapshotID, RefID: prRefID, CommitSha: "abc123", CreatedAt: time.Now().UTC()}
	store.latestSnapshot[targetRefID] = dbgen.Snapshot{ID: targetSnapshotID, RefID: targetRefID, CommitSha: "def456", CreatedAt: time.Now().UTC()}
	store.orgSlugs[orgID] = "acme-org"
	store.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{{ID: uuid.New(), Type: "dependency", Title: "CVE-2026-1234", Severity: storepkg.SeverityLevelCritical, Fingerprint: "fp-advisory"}}
	store.repoGates[repoID] = []dbgen.QualityGate{{ID: uuid.New(), OrgID: orgID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true}, Name: "strict", MaxCritical: 0, MaxHigh: 0, MaxMedium: sql.NullInt32{Int32: 0, Valid: true}, Enabled: true}}

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	// nil loader → enforcement defaults to advisory.
	annotator := NewAnnotator(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, "https://hibou.example.com", zerolog.Nop())
	annotator.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": prSnapshotID.String()})

	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected 1 commit status call, got %d", len(forgeProvider.statuses))
	}
	if got := forgeProvider.statuses[0].status.State; got != "success" {
		t.Fatalf("advisory gate must post non-blocking success, got %q", got)
	}
	if want := "https://hibou.example.com/orgs/github/acme-org/repos/api/pulls/7"; forgeProvider.statuses[0].status.TargetURL != want {
		t.Fatalf("unexpected target url: got %q want %q", forgeProvider.statuses[0].status.TargetURL, want)
	}
	if len(store.prChecks) != 1 {
		t.Fatalf("expected 1 pr_check persisted, got %d", len(store.prChecks))
	}
	check := store.prChecks[0]
	if check.State != "success" || check.Conclusion != "neutral" || check.Passed || check.Enforcement != "advisory" {
		t.Fatalf("unexpected advisory pr_check: %#v", check)
	}
}

// TestAnnotatorRecomputeForRef re-posts the gate for a PR ref on demand (the
// live-update path used by VEX dismissal / override / advisory re-eval).
func TestAnnotatorRecomputeForRef(t *testing.T) {
	store := newAnnotatorStore()
	forgeProvider := &mockForgeProvider{}
	orgID := uuid.New()
	repoID := uuid.New()
	prRefID := uuid.New()
	targetRefID := uuid.New()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()

	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: orgID, Name: "acme/api", Slug: "api", Provider: "github", ProviderID: "acme/api"}
	store.refs[prRefID] = dbgen.Ref{ID: prRefID, RepoID: repoID, Name: "refs/pull/9", RefType: dbgen.RefTypePullRequest, MergeTargetRefID: uuid.NullUUID{UUID: targetRefID, Valid: true}}
	store.refs[targetRefID] = dbgen.Ref{ID: targetRefID, RepoID: repoID, Name: "main", RefType: dbgen.RefTypeBranch}
	store.snapshots[prSnapshotID] = dbgen.Snapshot{ID: prSnapshotID, RefID: prRefID, CommitSha: "head99", CreatedAt: time.Now().UTC()}
	store.latestSnapshot[prRefID] = store.snapshots[prSnapshotID]
	store.latestSnapshot[targetRefID] = dbgen.Snapshot{ID: targetSnapshotID, RefID: targetRefID, CommitSha: "def456", CreatedAt: time.Now().UTC()}
	store.orgSlugs[orgID] = "acme-org"
	store.repoGates[repoID] = []dbgen.QualityGate{{ID: uuid.New(), OrgID: orgID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true}, Name: "strict", MaxCritical: 0, Enabled: true}}

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	annotator := NewAnnotator(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, "https://hibou.example.com", zerolog.Nop())

	annotator.handleRecomputeRequested(context.Background(), map[string]any{"ref_id": prRefID.String()})

	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected 1 commit status from ref recompute, got %d", len(forgeProvider.statuses))
	}
	if forgeProvider.statuses[0].sha != "head99" {
		t.Fatalf("recompute should target the PR head snapshot, got sha %q", forgeProvider.statuses[0].sha)
	}
}

func TestAnnotatorSkipsNonPRSnapshots(t *testing.T) {
	store := newAnnotatorStore()
	forgeProvider := &mockForgeProvider{}
	repoID := uuid.New()
	refID := uuid.New()
	snapshotID := uuid.New()
	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: uuid.New(), Name: "acme/api", Provider: "github", ProviderID: "acme/api"}
	store.refs[refID] = dbgen.Ref{ID: refID, RepoID: repoID, RefType: dbgen.RefTypeBranch}
	store.snapshots[snapshotID] = dbgen.Snapshot{ID: snapshotID, RefID: refID, CommitSha: "abc123"}
	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	annotator := NewAnnotator(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, "", zerolog.Nop())

	annotator.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": snapshotID.String()})

	if len(forgeProvider.statuses) != 0 {
		t.Fatalf("expected no commit status calls for non-PR snapshot, got %d", len(forgeProvider.statuses))
	}
}

func TestAnnotatorUsesRepoConfigWeaknessGateWhenAvailable(t *testing.T) {
	store := newAnnotatorStore()
	forgeProvider := &mockForgeProvider{}
	repoConfigLoader := &mockRepoConfigLoader{weaknessGate: &delta.WeaknessGate{MaxCritical: intTestPtr(1)}}
	orgID := uuid.New()
	repoID := uuid.New()
	prRefID := uuid.New()
	targetRefID := uuid.New()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()

	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: orgID, Name: "acme/api", Slug: "api", Provider: "github", ProviderID: "acme/api", DefaultBranch: "main"}
	store.refs[prRefID] = dbgen.Ref{ID: prRefID, RepoID: repoID, Name: "pr-1", RefType: dbgen.RefTypePullRequest, MergeTargetRefID: uuid.NullUUID{UUID: targetRefID, Valid: true}}
	store.refs[targetRefID] = dbgen.Ref{ID: targetRefID, RepoID: repoID, Name: "release/1.0", RefType: dbgen.RefTypeBranch}
	store.snapshots[prSnapshotID] = dbgen.Snapshot{ID: prSnapshotID, RefID: prRefID, CommitSha: "abc123", CreatedAt: time.Now().UTC()}
	store.latestSnapshot[targetRefID] = dbgen.Snapshot{ID: targetSnapshotID, RefID: targetRefID, CommitSha: "def456", CreatedAt: time.Now().UTC()}
	store.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{{ID: uuid.New(), Type: "sast", Title: "new", Severity: storepkg.SeverityLevelCritical, Fingerprint: "fp-1"}}
	store.repoGates[repoID] = []dbgen.QualityGate{{ID: uuid.New(), OrgID: orgID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true}, Name: "strict", MaxCritical: 10, MaxHigh: 10, MaxMedium: sql.NullInt32{Int32: 10, Valid: true}, MaxNewFindings: sql.NullInt32{Int32: 0, Valid: true}, Enabled: true}}

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	annotator := NewAnnotator(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, repoConfigLoader, "", zerolog.Nop())
	annotator.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": prSnapshotID.String()})

	if repoConfigLoader.loadWeaknessCalls != 1 {
		t.Fatalf("expected repo config loader to be called once, got %d", repoConfigLoader.loadWeaknessCalls)
	}
	if repoConfigLoader.providerID != "github" || repoConfigLoader.owner != "acme" || repoConfigLoader.repo != "api" {
		t.Fatalf("unexpected loader coordinates: %#v", repoConfigLoader)
	}
	if repoConfigLoader.defaultBranch != "main" || repoConfigLoader.targetBranch != "release/1.0" {
		t.Fatalf("unexpected branch inputs: %#v", repoConfigLoader)
	}
	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected 1 commit status call, got %d", len(forgeProvider.statuses))
	}
	if forgeProvider.statuses[0].status.State != "success" {
		t.Fatalf("expected file-based weakness gate to override DB findings gate, got %#v", forgeProvider.statuses[0].status)
	}
}

// TestAnnotatorBranchScanRecomputesTargetingPRs verifies that a new snapshot on a
// base branch refreshes the gate check of open PRs that target that branch (the
// "base moved" path), without a CI re-run on the PR.
func TestAnnotatorBranchScanRecomputesTargetingPRs(t *testing.T) {
	store := newAnnotatorStore()
	forgeProvider := &mockForgeProvider{}
	orgID := uuid.New()
	repoID := uuid.New()
	baseRefID := uuid.New()
	baseSnapshotID := uuid.New()
	prRefID := uuid.New()
	prSnapshotID := uuid.New()

	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: orgID, Name: "acme/api", Slug: "api", Provider: "github", ProviderID: "acme/api"}
	// The scanned snapshot is on the base branch "main".
	store.refs[baseRefID] = dbgen.Ref{ID: baseRefID, RepoID: repoID, Name: "main", RefType: dbgen.RefTypeBranch}
	store.snapshots[baseSnapshotID] = dbgen.Snapshot{ID: baseSnapshotID, RefID: baseRefID, CommitSha: "base-new", CreatedAt: time.Now().UTC()}
	store.latestSnapshot[baseRefID] = store.snapshots[baseSnapshotID]
	// An open PR targeting main.
	store.refs[prRefID] = dbgen.Ref{ID: prRefID, RepoID: repoID, Name: "refs/pull/12", RefType: dbgen.RefTypePullRequest, MergeTargetRefID: uuid.NullUUID{UUID: baseRefID, Valid: true}}
	store.snapshots[prSnapshotID] = dbgen.Snapshot{ID: prSnapshotID, RefID: prRefID, CommitSha: "pr-head", CreatedAt: time.Now().UTC()}
	store.latestSnapshot[prRefID] = store.snapshots[prSnapshotID]
	store.orgSlugs[orgID] = "acme-org"
	store.openPRRefs[repoID] = []dbgen.Ref{{ID: prRefID, MergeTargetRefID: uuid.NullUUID{UUID: baseRefID, Valid: true}}}
	store.repoGates[repoID] = []dbgen.QualityGate{{ID: uuid.New(), OrgID: orgID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true}, Name: "strict", MaxCritical: 0, Enabled: true}}

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	annotator := NewAnnotator(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, "https://hibou.example.com", zerolog.Nop())

	// Scan completed on the BASE branch snapshot.
	annotator.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": baseSnapshotID.String()})

	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected the targeting PR's gate to be re-posted, got %d statuses", len(forgeProvider.statuses))
	}
	if forgeProvider.statuses[0].sha != "pr-head" {
		t.Fatalf("expected re-post on the PR head snapshot, got sha %q", forgeProvider.statuses[0].sha)
	}
}

func intTestPtr(value int) *int {
	return &value
}

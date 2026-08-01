package forge

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
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
func (m *mockForgeProvider) ListTreePaths(context.Context, string, string, string) ([]string, error) {
	return nil, nil
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

func (m *mockRepoConfigLoader) LoadGateConfig(_ context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (*delta.GateConfig, error) {
	m.loadWeaknessCalls++
	m.providerID = providerID
	m.owner = owner
	m.repo = repo
	m.defaultBranch = defaultBranch
	m.targetBranch = targetBranch
	if m.err != nil {
		return nil, m.err
	}
	if m.weaknessGate == nil {
		return nil, nil
	}
	return &delta.GateConfig{Weakness: m.weaknessGate}, nil
}

func (m *mockRepoConfigLoader) LoadEnforcement(_ context.Context, _, _, _, _, _ string) (string, error) {
	return m.enforcement, nil
}

type gatePublisherStore struct {
	*deltaTestStore
	repos          map[uuid.UUID]dbgen.Repository
	snapshots      map[uuid.UUID]dbgen.Snapshot
	refs           map[uuid.UUID]dbgen.Ref
	latestSnapshot map[uuid.UUID]dbgen.Snapshot
	orgSlugs       map[uuid.UUID]string
	openPRRefs     map[uuid.UUID][]dbgen.Ref
	repoIDsByOrg   map[uuid.UUID][]uuid.UUID
	overrides      map[string][2]string // headSHA -> {state, reason}
	prChecks       []storepkg.UpsertPRCheckInput
}

type deltaTestStore struct {
	vulnsBySnapshot map[uuid.UUID][]storepkg.Vulnerability
	repoGates       map[uuid.UUID][]dbgen.QualityGate
	orgGates        map[uuid.UUID][]dbgen.QualityGate
}

func newGatePublisherStore() *gatePublisherStore {
	return &gatePublisherStore{
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
		overrides:      map[string][2]string{},
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

func (m *gatePublisherStore) GetRepoByID(_ context.Context, id uuid.UUID) (dbgen.Repository, error) {
	return m.repos[id], nil
}

func (m *gatePublisherStore) GetSnapshotByID(_ context.Context, id uuid.UUID) (dbgen.Snapshot, error) {
	return m.snapshots[id], nil
}

func (m *gatePublisherStore) GetRefByID(_ context.Context, id uuid.UUID) (dbgen.Ref, error) {
	return m.refs[id], nil
}

func (m *gatePublisherStore) GetLatestSnapshotByRef(_ context.Context, refID uuid.UUID) (dbgen.Snapshot, error) {
	return m.latestSnapshot[refID], nil
}

func (m *gatePublisherStore) UpsertPRCheck(_ context.Context, in storepkg.UpsertPRCheckInput) error {
	m.prChecks = append(m.prChecks, in)
	return nil
}

func (m *gatePublisherStore) GetOrgSlug(_ context.Context, orgID uuid.UUID) (string, error) {
	return m.orgSlugs[orgID], nil
}

func (m *gatePublisherStore) ListOpenPRRefs(_ context.Context, repoID uuid.UUID) ([]dbgen.Ref, error) {
	return m.openPRRefs[repoID], nil
}

func (m *gatePublisherStore) ListRepoIDsByOrg(_ context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	return m.repoIDsByOrg[orgID], nil
}

func (m *gatePublisherStore) ListUnsyncedPRCheckRefIDs(_ context.Context, _ int32) ([]uuid.UUID, error) {
	return nil, nil
}

func (m *gatePublisherStore) GetGateOverride(_ context.Context, _ uuid.UUID, headSha string) (string, string, bool, error) {
	o, ok := m.overrides[headSha]
	if !ok || o[0] == "" {
		return "", "", false, nil
	}
	return o[0], o[1], true, nil
}

func TestGatePublisherPostsFailureStatusForPRSnapshot(t *testing.T) {
	store := newGatePublisherStore()
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
	store.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{{ID: uuid.New(), Type: "dependency", Title: "CVE-2026-1234", Severity: storepkg.SeverityLevelCritical, Fingerprint: "fp-gatePublisher"}}
	store.repoGates[repoID] = []dbgen.QualityGate{{ID: uuid.New(), OrgID: orgID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true}, Name: "strict", MaxCritical: 0, MaxHigh: 0, MaxMedium: sql.NullInt32{Int32: 0, Valid: true}, Enabled: true}}

	store.orgSlugs[orgID] = "acme-org"

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	// Blocking enforcement: a failing gate posts a real failure state.
	loader := &mockRepoConfigLoader{enforcement: "blocking"}
	gatePublisher := NewGatePublisher(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, loader, nil, "https://hibou.example.com", zerolog.Nop())
	gatePublisher.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": prSnapshotID.String()})

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

// TestGatePublisherAdvisoryDefaultNeverBlocks verifies the default (advisory) path
// posts a non-blocking success even when the gate fails, and records the neutral
// check-run conclusion in pr_checks. This is the "never break the build" default.
func TestGatePublisherAdvisoryDefaultNeverBlocks(t *testing.T) {
	store := newGatePublisherStore()
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
	gatePublisher := NewGatePublisher(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, nil, "https://hibou.example.com", zerolog.Nop())
	gatePublisher.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": prSnapshotID.String()})

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

// TestGatePublisherRecomputeForRef re-posts the gate for a PR ref on demand (the
// live-update path used by VEX dismissal / override / advisory re-eval).
func TestGatePublisherRecomputeForRef(t *testing.T) {
	store := newGatePublisherStore()
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
	gatePublisher := NewGatePublisher(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, nil, "https://hibou.example.com", zerolog.Nop())

	gatePublisher.handleRecomputeRequested(context.Background(), map[string]any{"ref_id": prRefID.String()})

	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected 1 commit status from ref recompute, got %d", len(forgeProvider.statuses))
	}
	if forgeProvider.statuses[0].sha != "head99" {
		t.Fatalf("recompute should target the PR head snapshot, got sha %q", forgeProvider.statuses[0].sha)
	}
}

func TestGatePublisherSkipsNonPRSnapshots(t *testing.T) {
	store := newGatePublisherStore()
	forgeProvider := &mockForgeProvider{}
	repoID := uuid.New()
	refID := uuid.New()
	snapshotID := uuid.New()
	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: uuid.New(), Name: "acme/api", Provider: "github", ProviderID: "acme/api"}
	store.refs[refID] = dbgen.Ref{ID: refID, RepoID: repoID, RefType: dbgen.RefTypeBranch}
	store.snapshots[snapshotID] = dbgen.Snapshot{ID: snapshotID, RefID: refID, CommitSha: "abc123"}
	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	gatePublisher := NewGatePublisher(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, nil, "", zerolog.Nop())

	gatePublisher.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": snapshotID.String()})

	if len(forgeProvider.statuses) != 0 {
		t.Fatalf("expected no commit status calls for non-PR snapshot, got %d", len(forgeProvider.statuses))
	}
}

func TestGatePublisherUsesRepoConfigWeaknessGateWhenAvailable(t *testing.T) {
	store := newGatePublisherStore()
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
	gatePublisher := NewGatePublisher(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, repoConfigLoader, nil, "", zerolog.Nop())
	gatePublisher.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": prSnapshotID.String()})

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

// TestGatePublisherBranchScanRecomputesTargetingPRs verifies that a new snapshot on a
// base branch refreshes the gate check of open PRs that target that branch (the
// "base moved" path), without a CI re-run on the PR.
func TestGatePublisherBranchScanRecomputesTargetingPRs(t *testing.T) {
	store := newGatePublisherStore()
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
	gatePublisher := NewGatePublisher(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, nil, "https://hibou.example.com", zerolog.Nop())

	// Scan completed on the BASE branch snapshot.
	gatePublisher.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": baseSnapshotID.String()})

	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected the targeting PR's gate to be re-posted, got %d statuses", len(forgeProvider.statuses))
	}
	if forgeProvider.statuses[0].sha != "pr-head" {
		t.Fatalf("expected re-post on the PR head snapshot, got sha %q", forgeProvider.statuses[0].sha)
	}
}

// TestGatePublisherAppliesGateOverride verifies a persisted "pass" override flips a
// blocking, failing gate to success on the published check.
func TestGatePublisherAppliesGateOverride(t *testing.T) {
	store := newGatePublisherStore()
	forgeProvider := &mockForgeProvider{}
	orgID := uuid.New()
	repoID := uuid.New()
	prRefID := uuid.New()
	targetRefID := uuid.New()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()

	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: orgID, Name: "acme/api", Slug: "api", Provider: "github", ProviderID: "acme/api"}
	store.refs[prRefID] = dbgen.Ref{ID: prRefID, RepoID: repoID, Name: "refs/pull/5", RefType: dbgen.RefTypePullRequest, MergeTargetRefID: uuid.NullUUID{UUID: targetRefID, Valid: true}}
	store.refs[targetRefID] = dbgen.Ref{ID: targetRefID, RepoID: repoID, Name: "main", RefType: dbgen.RefTypeBranch}
	store.snapshots[prSnapshotID] = dbgen.Snapshot{ID: prSnapshotID, RefID: prRefID, CommitSha: "ovr-head", CreatedAt: time.Now().UTC()}
	store.latestSnapshot[targetRefID] = dbgen.Snapshot{ID: targetSnapshotID, RefID: targetRefID, CommitSha: "def456", CreatedAt: time.Now().UTC()}
	store.orgSlugs[orgID] = "acme-org"
	store.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{{ID: uuid.New(), Type: "dependency", Title: "CVE-2026-9", Severity: storepkg.SeverityLevelCritical, Fingerprint: "fp-ovr"}}
	store.repoGates[repoID] = []dbgen.QualityGate{{ID: uuid.New(), OrgID: orgID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true}, Name: "strict", MaxCritical: 0, Enabled: true}}
	// A release_manager overrode this head to pass.
	store.overrides["ovr-head"] = [2]string{"pass", "confirmed false positive"}

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	loader := &mockRepoConfigLoader{enforcement: "blocking"}
	gatePublisher := NewGatePublisher(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, loader, nil, "https://hibou.example.com", zerolog.Nop())
	gatePublisher.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": prSnapshotID.String()})

	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected 1 commit status, got %d", len(forgeProvider.statuses))
	}
	if got := forgeProvider.statuses[0].status.State; got != "success" {
		t.Fatalf("override to pass must flip a blocking failure to success, got %q", got)
	}
	if len(store.prChecks) != 1 || !store.prChecks[0].Passed {
		t.Fatalf("expected persisted pr_check to be passed, got %#v", store.prChecks)
	}
	if len(store.prChecks[0].Reasons) == 0 || !strings.Contains(store.prChecks[0].Reasons[0], "overridden") {
		t.Fatalf("expected override note in reasons, got %#v", store.prChecks[0].Reasons)
	}
}

func TestGateAnnotationsFromNewFindings(t *testing.T) {
	file := "internal/app/handler.go"
	start := int32(42)
	end := int32(44)
	deltaResult := &delta.DeltaResult{New: []storepkg.Vulnerability{
		{Title: "SQL injection", Severity: storepkg.SeverityLevelCritical, FilePath: &file, StartLine: &start, EndLine: &end},
		{Title: "no location", Severity: storepkg.SeverityLevelHigh}, // skipped: no file/line
	}}

	annotations := gateAnnotations(deltaResult)
	if len(annotations) != 1 {
		t.Fatalf("expected 1 annotation (location-bearing finding only), got %d", len(annotations))
	}
	a := annotations[0]
	if a.Path != file || a.StartLine != 42 || a.EndLine != 44 {
		t.Fatalf("unexpected annotation location: %#v", a)
	}
	if a.Level != "failure" {
		t.Fatalf("critical finding should map to failure level, got %q", a.Level)
	}
	if a.Message != "SQL injection" {
		t.Fatalf("unexpected annotation message: %q", a.Message)
	}
	if annotationLevel("medium") != "warning" || annotationLevel("low") != "notice" {
		t.Fatalf("severity->level mapping wrong")
	}
}

func intTestPtr(value int) *int {
	return &value
}

// A PR snapshot whose target branch has no snapshot yet cannot be evaluated.
// Before this, nothing was posted at all and the PR showed no Hibou check —
// now an in-progress check says "working on it" and no verdict is persisted.
func TestGatePublisherPostsPendingWhenTargetSnapshotMissing(t *testing.T) {
	store := newGatePublisherStore()
	forgeProvider := &mockForgeProvider{}
	orgID := uuid.New()
	repoID := uuid.New()
	prRefID := uuid.New()
	targetRefID := uuid.New()
	prSnapshotID := uuid.New()

	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: orgID, Name: "acme/api", Slug: "api", Provider: "github", ProviderID: "acme/api"}
	store.refs[prRefID] = dbgen.Ref{ID: prRefID, RepoID: repoID, Name: "pr-1", RefType: dbgen.RefTypePullRequest, MergeTargetRefID: uuid.NullUUID{UUID: targetRefID, Valid: true}}
	store.refs[targetRefID] = dbgen.Ref{ID: targetRefID, RepoID: repoID, Name: "main", RefType: dbgen.RefTypeBranch}
	store.snapshots[prSnapshotID] = dbgen.Snapshot{ID: prSnapshotID, RefID: prRefID, CommitSha: "abc123", CreatedAt: time.Now().UTC()}
	// Deliberately no latestSnapshot[targetRefID]: nothing to compare against.
	store.orgSlugs[orgID] = "acme-org"

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	gatePublisher := NewGatePublisher(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, &mockRepoConfigLoader{}, nil, "https://hibou.example.com", zerolog.Nop())
	gatePublisher.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": prSnapshotID.String()})

	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected 1 commit status call, got %d", len(forgeProvider.statuses))
	}
	if state := forgeProvider.statuses[0].status.State; state != "pending" {
		t.Fatalf("status state = %q, want pending", state)
	}
	// No outcome yet, so nothing may be recorded as a verdict.
	if len(store.prChecks) != 0 {
		t.Fatalf("expected no pr_check persisted for a pending gate, got %#v", store.prChecks)
	}
}

// The gate must not depend on the advisory scan: artifact processing publishes
// GateRecomputeRequested with a snapshot_id, which has to route exactly like a
// completed scan.
func TestGatePublisherRecomputeBySnapshotIDPublishesGate(t *testing.T) {
	store := newGatePublisherStore()
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
	store.orgSlugs[orgID] = "acme-org"

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	gatePublisher := NewGatePublisher(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, &mockRepoConfigLoader{}, nil, "https://hibou.example.com", zerolog.Nop())
	gatePublisher.handleRecomputeRequested(context.Background(), map[string]any{"snapshot_id": prSnapshotID.String()})

	if len(forgeProvider.statuses) != 1 {
		t.Fatalf("expected the recompute to post a status, got %d calls", len(forgeProvider.statuses))
	}
	if state := forgeProvider.statuses[0].status.State; state == "pending" {
		t.Fatal("expected a resolved verdict, not pending: the comparison was available")
	}
	if len(store.prChecks) != 1 {
		t.Fatalf("expected the verdict persisted, got %d pr_checks", len(store.prChecks))
	}
}

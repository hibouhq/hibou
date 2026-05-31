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

	"github.com/hibouhq/lehibou/internal/delta"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type mockForgeProvider struct {
	statuses []commitStatusCall
}

type mockRepoConfigLoader struct {
	weaknessGate      *delta.WeaknessGate
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

func (m *mockRepoConfigLoader) LoadWeaknessGate(_ context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (*delta.WeaknessGate, error) {
	m.loadWeaknessCalls++
	m.providerID = providerID
	m.owner = owner
	m.repo = repo
	m.defaultBranch = defaultBranch
	m.targetBranch = targetBranch
	return m.weaknessGate, m.err
}

type annotatorStore struct {
	*deltaTestStore
	repos          map[uuid.UUID]dbgen.Repository
	snapshots      map[uuid.UUID]dbgen.Snapshot
	refs           map[uuid.UUID]dbgen.Ref
	latestSnapshot map[uuid.UUID]dbgen.Snapshot
}

type deltaTestStore struct {
	vulnsBySnapshot    map[uuid.UUID][]dbgen.VulnMatch
	findingsBySnapshot map[uuid.UUID][]dbgen.Finding
	advisories         map[uuid.UUID]dbgen.Advisory
	repoGates          map[uuid.UUID][]dbgen.QualityGate
	orgGates           map[uuid.UUID][]dbgen.QualityGate
}

func newAnnotatorStore() *annotatorStore {
	return &annotatorStore{
		deltaTestStore: &deltaTestStore{
			vulnsBySnapshot:    map[uuid.UUID][]dbgen.VulnMatch{},
			findingsBySnapshot: map[uuid.UUID][]dbgen.Finding{},
			advisories:         map[uuid.UUID]dbgen.Advisory{},
			repoGates:          map[uuid.UUID][]dbgen.QualityGate{},
			orgGates:           map[uuid.UUID][]dbgen.QualityGate{},
		},
		repos:          map[uuid.UUID]dbgen.Repository{},
		snapshots:      map[uuid.UUID]dbgen.Snapshot{},
		refs:           map[uuid.UUID]dbgen.Ref{},
		latestSnapshot: map[uuid.UUID]dbgen.Snapshot{},
	}
}

func (m *deltaTestStore) ListVulnMatchesBySnapshot(_ context.Context, snapshotID uuid.UUID) ([]dbgen.VulnMatch, error) {
	return append([]dbgen.VulnMatch(nil), m.vulnsBySnapshot[snapshotID]...), nil
}

func (m *deltaTestStore) ListFindingsBySnapshot(_ context.Context, arg dbgen.ListFindingsBySnapshotParams) ([]dbgen.Finding, error) {
	rows := append([]dbgen.Finding(nil), m.findingsBySnapshot[arg.SnapshotID]...)
	start := int(arg.Offset)
	if start >= len(rows) {
		return nil, nil
	}
	end := start + int(arg.Limit)
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], nil
}

func (m *deltaTestStore) GetAdvisoryByID(_ context.Context, id uuid.UUID) (dbgen.Advisory, error) {
	return m.advisories[id], nil
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

func TestAnnotatorPostsFailureStatusForPRSnapshot(t *testing.T) {
	store := newAnnotatorStore()
	forgeProvider := &mockForgeProvider{}
	orgID := uuid.New()
	repoID := uuid.New()
	prRefID := uuid.New()
	targetRefID := uuid.New()
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()
	advisoryID := uuid.New()

	store.repos[repoID] = dbgen.Repository{ID: repoID, OrgID: orgID, Name: "acme/api", Slug: "api", Provider: "github", ProviderID: "acme/api"}
	store.refs[prRefID] = dbgen.Ref{ID: prRefID, RepoID: repoID, Name: "pr-1", RefType: dbgen.RefTypePullRequest, MergeTargetRefID: uuid.NullUUID{UUID: targetRefID, Valid: true}}
	store.refs[targetRefID] = dbgen.Ref{ID: targetRefID, RepoID: repoID, Name: "main", RefType: dbgen.RefTypeBranch}
	store.snapshots[prSnapshotID] = dbgen.Snapshot{ID: prSnapshotID, RefID: prRefID, CommitSha: "abc123", CreatedAt: time.Now().UTC()}
	store.latestSnapshot[targetRefID] = dbgen.Snapshot{ID: targetSnapshotID, RefID: targetRefID, CommitSha: "def456", CreatedAt: time.Now().UTC()}
	store.vulnsBySnapshot[prSnapshotID] = []dbgen.VulnMatch{{AdvisoryID: advisoryID}}
	store.advisories[advisoryID] = dbgen.Advisory{ID: advisoryID, CanonicalID: "CVE-2026-1234", Severity: dbgen.SeverityLevelCritical}
	store.repoGates[repoID] = []dbgen.QualityGate{{ID: uuid.New(), OrgID: orgID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true}, Name: "strict", MaxCritical: 0, MaxHigh: 0, MaxMedium: sql.NullInt32{Int32: 0, Valid: true}, Enabled: true}}

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	annotator := NewAnnotator(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, zerolog.Nop())
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
	annotator := NewAnnotator(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, nil, zerolog.Nop())

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
	store.findingsBySnapshot[prSnapshotID] = []dbgen.Finding{{Fingerprint: sql.NullString{String: "fp-1", Valid: true}, Tool: "semgrep", RuleID: "R1", Severity: dbgen.SeverityLevelCritical, FilePath: "main.go", Message: "new"}}
	store.repoGates[repoID] = []dbgen.QualityGate{{ID: uuid.New(), OrgID: orgID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true}, Name: "strict", MaxCritical: 10, MaxHigh: 10, MaxMedium: sql.NullInt32{Int32: 10, Valid: true}, MaxNewFindings: sql.NullInt32{Int32: 0, Valid: true}, Enabled: true}}

	deltaSvc := delta.NewService(store.deltaTestStore, zerolog.Nop())
	annotator := NewAnnotator(map[string]Provider{"github": forgeProvider}, deltaSvc, events.New(zerolog.Nop()), store, repoConfigLoader, zerolog.Nop())
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

func intTestPtr(value int) *int {
	return &value
}

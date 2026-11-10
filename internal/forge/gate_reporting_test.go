package forge

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type reportingConfigLoader struct {
	mockRepoConfigLoader
	enabled bool
}

func (l *reportingConfigLoader) HasGateReportingConfig(context.Context, string, string, string, string) (bool, error) {
	return l.enabled, l.err
}

type retiringForge struct {
	mockForgeProvider
	retired []string
	err     error
}

func (p *retiringForge) RetirePendingGate(_ context.Context, _, _, sha, name string) error {
	p.retired = append(p.retired, sha+"/"+name)
	return p.err
}

func TestGatePublisherRequiresIntegrationOnEveryPublishPath(t *testing.T) {
	for _, analyzed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending head", true: "analyzed head"}[analyzed], func(t *testing.T) {
			st := newGatePublisherStore()
			st.integrated = false
			repoID, refID, snapshotID := uuid.New(), uuid.New(), uuid.New()
			st.repos[repoID] = dbgen.Repository{ID: repoID, Provider: "github", ProviderID: "acme/app", DefaultBranch: "main"}
			st.refs[refID] = dbgen.Ref{ID: refID, RepoID: repoID, RefType: dbgen.RefTypePullRequest, LatestCommitSha: sql.NullString{String: "head", Valid: true}}
			status := dbgen.SnapshotStatusPending
			if analyzed {
				status = dbgen.SnapshotStatusComplete
				st.latestSnapshot[refID] = dbgen.Snapshot{ID: snapshotID, RefID: refID, CommitSha: "head", Status: status}
			}
			st.snapshots[snapshotID] = dbgen.Snapshot{ID: snapshotID, RefID: refID, CommitSha: "head", Status: status}
			provider := &retiringForge{}
			publisher := NewGatePublisher(map[string]Provider{"github": provider}, delta.NewService(st.deltaTestStore, zerolog.Nop()), nil, st, nil, nil, "", zerolog.Nop())
			publisher.PublishGateForRef(context.Background(), refID)
			publisher.publishForSnapshotID(context.Background(), snapshotID)
			if len(provider.statuses) != 0 || len(st.prChecks) != 0 {
				t.Fatal("SCA-only repository received a PR check")
			}
			st.openPRRefs[repoID] = []dbgen.Ref{{ID: refID}}
			if err := publisher.RetireUnintegratedChecks(context.Background(), repoID); err != nil {
				t.Fatal(err)
			}
			if len(provider.retired) != 1 || provider.retired[0] != "head/hibou/security" {
				t.Fatalf("existing pending check not retired: %v", provider.retired)
			}
		})
	}
}

func TestGateReportingIntegrationSourcesAndErrors(t *testing.T) {
	st := newGatePublisherStore()
	repoID := uuid.New()
	st.repos[repoID] = dbgen.Repository{ID: repoID, Provider: "github", ProviderID: "acme/app"}
	loader := &reportingConfigLoader{}
	publisher := NewGatePublisher(nil, nil, nil, st, loader, nil, "", zerolog.Nop())
	if enabled, err := publisher.RepositoryReportingEnabled(context.Background(), repoID); !enabled || err != nil {
		t.Fatalf("existing upload integration lost: %v %v", enabled, err)
	}
	st.integrated = false
	loader.enabled = true
	if enabled, err := publisher.RepositoryReportingEnabled(context.Background(), repoID); !enabled || err != nil {
		t.Fatalf("explicit gate configuration ignored: %v %v", enabled, err)
	}
	loader.enabled = false
	if enabled, err := publisher.RepositoryReportingEnabled(context.Background(), repoID); enabled || err != nil {
		t.Fatalf("enrollment alone enabled reporting: %v %v", enabled, err)
	}
	st.integrationErr = errors.New("database unavailable")
	if enabled, err := publisher.RepositoryReportingEnabled(context.Background(), repoID); enabled || err == nil {
		t.Fatal("eligibility error enabled reporting or was hidden")
	}
}

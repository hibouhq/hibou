package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/forge"
)

func TestForgePollingRetiresUnintegratedChecksEvenWithoutNewGateIntent(t *testing.T) {
	s, repo, provider := newReconciliationFixture(t)
	ctx := context.Background()
	deltaStore := delta.NewStoreAdapter(s.queries)
	s.gatePublisher = forge.NewGatePublisher(s.forges, delta.NewService(deltaStore, s.log, deltaStore), s.bus,
		forge.NewGatePublisherStoreAdapter(s.queries), nil, nil, "", s.log)
	head := strings.Repeat("a", 40)
	provider.prs = []forge.PullRequestEvent{{
		Number: 1, Action: "opened", HeadSHA: head, SourceBranch: "docs", TargetBranch: "main", BaseSHA: strings.Repeat("b", 40),
	}}
	for range 2 {
		if err := reconcileTestScope(t, s, repo, "pull_requests"); err != nil {
			t.Fatal(err)
		}
		var pending bool
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE((state->>'gate_pending')::boolean,false)
			FROM forge_reconciliation WHERE repo_id=$1 AND kind='pull_requests'`, repo.ID).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if pending {
			t.Fatal("unintegrated repository kept a gate publication intent")
		}
	}
	if len(provider.checks) != 0 || len(provider.retired) != 2 || provider.retired[0] != head+"/hibou/security" {
		t.Fatalf("unexpected reporting side effects: checks=%+v retired=%v", provider.checks, provider.retired)
	}
	provider.retireErr = errors.New("check update denied")
	if err := reconcileTestScope(t, s, repo, "pull_requests"); err == nil {
		t.Fatal("polling swallowed cleanup failure instead of retrying")
	}
	provider.retireErr = nil
	if err := reconcileTestScope(t, s, repo, "pull_requests"); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
}

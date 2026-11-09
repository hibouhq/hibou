package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/cache"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/provider"
	"github.com/hibouhq/hibou/internal/scanner"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type scaObservedScanner struct {
	*scanner.Service
	done chan error
}

func (s *scaObservedScanner) RunQueuedScan(ctx context.Context, queued dbgen.Scan) (uuid.UUID, error) {
	id, err := s.Service.RunQueuedScan(ctx, queued)
	s.done <- err
	return id, err
}

func TestSCAWaitingAdvisoryScanRemainsMatching(t *testing.T) {
	s, org, _, _, inv := newSCAFixture(t)
	ctx := context.Background()
	result, repo, _, err := s.enableSCA(ctx, org, inv.ProviderKey)
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.Repeat("a", 40)
	ref, err := s.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{LatestCommitSHA: &commit})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.queries.CreatePlaceholderSnapshot(ctx, ref.ID, commit)
	if err != nil {
		t.Fatal(err)
	}
	s.bus = events.New(s.log)
	done := make(chan error, 1)
	s.advisoryScanner = &scaObservedScanner{
		Service: scanner.New(s.queries, cache.New(s.queries, cache.Config{DefaultTTL: time.Hour}, s.log),
			advisory.NewIngester(s.queries, s.log), s.bus, map[string]provider.AdvisoryProvider{"sca-fixture": scaFixtureProvider{}}, s.log),
		done: done,
	}
	s.advisoryProviders = []string{"sca-fixture"}
	s.advisoryScanSlots = make(chan struct{}, 1)
	s.advisoryScanSlots <- struct{}{}
	lifecycle, cancel := context.WithCancel(ctx)
	s.lifecycleCtx = lifecycle
	t.Cleanup(cancel)
	if err := s.ingestExtractedInventory(ctx, snapshot, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE dep_extraction_jobs SET status='complete',snapshot_id=$2,finished_at=now() WHERE id=$1`, result.JobID, snapshot.ID); err != nil {
		t.Fatal(err)
	}
	coverage, err := s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.State != "matching" {
		t.Fatalf("waiting coverage=%+v err=%v", coverage, err)
	}
	scans, err := s.queries.ListScansBySnapshot(ctx, snapshot.ID)
	if err != nil || len(scans) != 1 || scans[0].Status != "pending" {
		t.Fatalf("queued scan not persisted: scans=%+v err=%v", scans, err)
	}
	<-s.advisoryScanSlots
	select {
	case err := <-done:
		if err != nil {
			var detail string
			lookupErr := s.db.QueryRow(`SELECT COALESCE(sp.error_message,'') FROM scan_providers sp JOIN scans sc ON sc.id=sp.scan_id WHERE sc.snapshot_id=$1 ORDER BY sc.created_at DESC LIMIT 1`, snapshot.ID).Scan(&detail)
			t.Fatalf("advisory matching: %v, detail=%s, lookup=%v", err, detail, lookupErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("queued advisory scan did not finish")
	}
	scans, err = s.queries.ListScansBySnapshot(ctx, snapshot.ID)
	if err != nil || len(scans) != 1 || scans[0].Status != "complete" {
		t.Fatalf("queued execution created another scan: scans=%+v err=%v", scans, err)
	}
	coverage, err = s.dependencyCoverageForRepo(ctx, repo, "main")
	if err != nil || coverage.State != "complete" {
		t.Fatalf("completed coverage=%+v err=%v", coverage, err)
	}
}

type scaDeniedTokenForge struct{ scaContentForge }

func (*scaDeniedTokenForge) CloneToken(context.Context, string, string) (string, error) {
	return "", errors.New("installation access revoked")
}

func TestSCARejectsLiveIdentityReuseAndTokenDenial(t *testing.T) {
	for _, mode := range []string{"repository reuse", "account reuse", "token denial"} {
		t.Run(mode, func(t *testing.T) {
			s, org, _, _, inv := newSCAFixture(t)
			ctx := context.Background()
			result, _, _, err := s.enableSCA(ctx, org, inv.ProviderKey)
			if err != nil {
				t.Fatal(err)
			}
			live := forge.Repository{Owner: inv.Owner, OwnerID: org.ForgeAccountID, Name: inv.Name,
				ProviderRepoID: *inv.ProviderRepoID, CloneURL: "https://example.invalid/app.git"}
			want := "live repository identity"
			switch mode {
			case "repository reuse":
				live.ProviderRepoID = uuid.NewString()
			case "account reuse":
				live.OwnerID = uuid.NewString()
			}
			fake := scaContentForge{discoveryTestForgeProvider: discoveryTestForgeProvider{id: org.Provider}, repository: live}
			if mode == "token denial" {
				s.forges[org.Provider] = &scaDeniedTokenForge{fake}
				want = "clone token"
			} else {
				s.forges[org.Provider] = &fake
			}
			job, err := s.queries.GetDepExtractionJob(ctx, *result.JobID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.executeDepExtractionJob(ctx, job); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("must fail before checkout, got %v want %q", err, want)
			}
		})
	}
}

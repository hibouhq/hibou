package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store"
)

func releaseInventoryFixture(t *testing.T) (*Server, *store.Repository, *store.Organization, *store.User, *store.User) {
	t.Helper()
	s, org, admin, viewer, inv := newSCAFixture(t)
	repo, err := s.queries.CreateRepository(context.Background(), org.ID, nil, inv.Name, "app", org.Provider, inv.ProviderKey, "main", "enrolled")
	if err != nil {
		t.Fatal(err)
	}
	s.bus = events.New(s.log)
	return s, repo, org, admin, viewer
}

func createInventoryRelease(t *testing.T, s *Server, repo *store.Repository, n int, pinned bool) *store.Release {
	t.Helper()
	ctx := context.Background()
	version := fmt.Sprintf("v1.0.%d", n)
	commit := fmt.Sprintf("%040x", n+1)
	ref, err := s.queries.UpsertRef(ctx, repo.ID, version, store.RefTypeTag, store.UpsertRefOptions{LatestCommitSHA: &commit})
	if err != nil {
		t.Fatal(err)
	}
	var snapshotID *uuid.UUID
	if pinned {
		snapshot, err := s.queries.CreatePlaceholderSnapshot(ctx, ref.ID, commit)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.queries.UpdateSnapshotRetentionFlags(ctx, snapshot.ID, true, false); err != nil {
			t.Fatal(err)
		}
		snapshotID = &snapshot.ID
	}
	published := time.Now().Add(time.Duration(n) * time.Minute)
	release, err := s.queries.UpsertRelease(ctx, store.UpsertReleaseParams{
		RepoID: repo.ID, RefID: ref.ID, Version: version, SnapshotID: snapshotID,
		Source: store.ReleaseSourceForge, PublishedAt: &published,
	})
	if err != nil {
		t.Fatal(err)
	}
	return release
}

func releaseInventoryRequest(t *testing.T, user *store.User, org *store.Organization, repo *store.Repository, releaseID *uuid.UUID) *http.Request {
	t.Helper()
	r := newEnrollRequest(t, user, org.Provider, org.Slug, nil)
	params := chi.RouteContext(r.Context())
	params.URLParams.Add("repoSlug", repo.Slug)
	if releaseID != nil {
		params.URLParams.Add("releaseID", releaseID.String())
	}
	return r
}

func TestReleaseInventoryActionsOnlyWhenNeeded(t *testing.T) {
	s, repo, org, admin, viewer := releaseInventoryFixture(t)
	ctx := context.Background()
	missing := createInventoryRelease(t, s, repo, 1, true)
	covered := createInventoryRelease(t, s, repo, 2, true)
	// Any valid SBOM inventory is sufficient; no built-in extraction run is
	// required for an uploaded or delivered inventory to suppress backfill.
	snapshot, err := s.queries.GetSnapshotByID(ctx, *covered.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ingestExtractedInventory(ctx, snapshot, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}`)); err != nil {
		t.Fatal(err)
	}
	items, err := s.queries.ListReleaseInventories(ctx, repo.ID, []uuid.UUID{missing.ID, covered.ID})
	if err != nil || !items[missing.ID].CanExtract || items[covered.ID].CanExtract || !items[covered.ID].HasInventory {
		t.Fatalf("inventory statuses=%+v err=%v", items, err)
	}
	for _, tc := range []struct {
		user    *store.User
		release *store.Release
		want    int
	}{
		{viewer, missing, http.StatusForbidden},
		{admin, covered, http.StatusConflict},
		{admin, missing, http.StatusAccepted},
		{admin, missing, http.StatusAccepted},
	} {
		w := httptest.NewRecorder()
		s.handleExtractReleaseDependencies(w, releaseInventoryRequest(t, tc.user, org, repo, &tc.release.ID))
		if w.Code != tc.want {
			t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body)
		}
	}
	items, err = s.queries.ListReleaseInventories(ctx, repo.ID, []uuid.UUID{missing.ID})
	if err != nil || items[missing.ID].State != "queued" || items[missing.ID].CanExtract {
		t.Fatalf("queued button still eligible: statuses=%+v err=%v", items, err)
	}
	jobs, err := s.queries.ListDepExtractionJobsByRepo(ctx, repo.ID, 10)
	if err != nil || len(jobs) != 1 || jobs[0].RefName != "refs/tags/"+missing.Version {
		t.Fatalf("jobs=%+v err=%v", jobs, err)
	}
	// A completed no-files attempt is an outcome, not a reason to offer the
	// same unsupported extraction on every render.
	if _, err := s.db.Exec(`UPDATE dep_extraction_jobs SET status='complete',finished_at=now() WHERE id=$1`, jobs[0].ID); err != nil {
		t.Fatal(err)
	}
	items, err = s.queries.ListReleaseInventories(ctx, repo.ID, []uuid.UUID{missing.ID})
	if err != nil || items[missing.ID].State != "unsupported" || items[missing.ID].CanExtract {
		t.Fatalf("completed empty attempt became eligible: %+v err=%v", items, err)
	}
	if _, err := s.db.Exec(`UPDATE dep_extraction_jobs SET status='failed',finished_at=now(),last_error='clone denied' WHERE id=$1`, jobs[0].ID); err != nil {
		t.Fatal(err)
	}
	items, err = s.queries.ListReleaseInventories(ctx, repo.ID, []uuid.UUID{missing.ID})
	if err != nil || !items[missing.ID].CanExtract || items[missing.ID].Detail != "clone denied" {
		t.Fatalf("terminal failure cannot retry: %+v err=%v", items, err)
	}
	s.cfg.DepInventory.Enabled = false
	w := httptest.NewRecorder()
	s.handleExtractReleaseDependencies(w, releaseInventoryRequest(t, admin, org, repo, &missing.ID))
	if w.Code != http.StatusConflict {
		t.Fatalf("disabled extraction status=%d", w.Code)
	}
}

func TestReleaseBackfillBoundedAndIdempotent(t *testing.T) {
	s, repo, org, admin, _ := releaseInventoryFixture(t)
	for i := range 105 {
		createInventoryRelease(t, s, repo, i, false)
	}
	ctx := context.Background()
	candidates, err := s.queries.ListReleaseInventoryCandidates(ctx, repo.ID, 1)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("candidates=%v err=%v", candidates, err)
	}
	newest, err := s.queries.GetReleaseByID(ctx, candidates[0])
	if err != nil || newest.Version != "v1.0.104" {
		t.Fatalf("newest-first selection=%+v err=%v", newest, err)
	}
	for _, want := range []int{100, 5, 0} {
		w := httptest.NewRecorder()
		s.handleExtractAllReleases(w, releaseInventoryRequest(t, admin, org, repo, nil))
		var response struct {
			Data struct {
				Queued    int `json:"queued"`
				Failed    int `json:"failed"`
				Remaining int `json:"remaining"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusAccepted || response.Data.Queued != want || response.Data.Failed != 0 {
			t.Fatalf("backfill want=%d body=%s status=%d", want, w.Body, w.Code)
		}
	}
	summary, err := s.queries.GetReleaseInventorySummary(ctx, repo.ID)
	if err != nil || summary.Eligible != 0 || summary.Queued != 105 {
		t.Fatalf("bulk button should be hidden: summary=%+v err=%v", summary, err)
	}
}

func TestReleaseExtractionKeepsPinnedCommitAndCoalesces(t *testing.T) {
	s, repo, _, _, _ := releaseInventoryFixture(t)
	ctx := context.Background()
	release := createInventoryRelease(t, s, repo, 1, true)
	old, err := s.queries.GetSnapshotByID(ctx, *release.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	newHead := strings.Repeat("b", 40)
	if _, err := s.queries.UpsertRef(ctx, repo.ID, release.Version, store.RefTypeTag, store.UpsertRefOptions{LatestCommitSHA: &newHead}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, _, err := s.queueReleaseInventory(ctx, repo, release.ID)
			if err != nil || job == nil || job.SnapshotID == nil || *job.SnapshotID != old.ID || job.CommitSHA != old.CommitSHA {
				t.Errorf("changed shipped target: job=%+v err=%v", job, err)
			}
		}()
	}
	wg.Wait()
	jobs, err := s.queries.ListDepExtractionJobsByRepo(ctx, repo.ID, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("duplicate release jobs=%v err=%v", jobs, err)
	}
	// Pinning an extracted snapshot must not adopt a newer tag on a release
	// whose shipped snapshot was already recorded.
	newer, err := s.queries.CreatePlaceholderSnapshot(ctx, release.RefID, newHead)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := s.queries.GetRefByID(ctx, release.RefID)
	if err := s.pinReleaseInventorySnapshot(ctx, ref, newer); err != nil {
		t.Fatal(err)
	}
	current, err := s.queries.GetReleaseByID(ctx, release.ID)
	if err != nil || current.SnapshotID == nil || *current.SnapshotID != old.ID {
		t.Fatalf("release was repointed: release=%+v err=%v", current, err)
	}
	if _, _, err := s.queueReleaseInventory(ctx, repo, uuid.New()); err == nil || errors.Is(err, errReleaseInventoryNotNeeded) {
		t.Fatalf("foreign/missing release must fail explicitly, got %v", err)
	}
}

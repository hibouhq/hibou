package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
)

func TestReleaseInventoryDoesNotConfuseSameNamedBranch(t *testing.T) {
	s, repo, _, _, _ := releaseInventoryFixture(t)
	ctx := context.Background()
	release := createInventoryRelease(t, s, repo, 1, true)
	if _, err := s.queries.UpsertRef(ctx, repo.ID, release.Version, store.RefTypeBranch, store.UpsertRefOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.queries.EnqueueDepExtractionJob(ctx, store.EnqueueDepExtractionJobParams{
		RepoID: repo.ID, RefName: release.Version, Reason: store.DepExtractionReasonPush,
	}); err != nil {
		t.Fatal(err)
	}
	statuses, err := s.queries.ListReleaseInventories(ctx, repo.ID, []uuid.UUID{release.ID})
	if err != nil || !statuses[release.ID].CanExtract {
		t.Fatalf("branch job hid required release action: statuses=%+v err=%v", statuses, err)
	}
	job, queued, err := s.queueReleaseInventory(ctx, repo, release.ID)
	if err != nil || !queued || job.RefName != "refs/tags/"+release.Version {
		t.Fatalf("release job=%+v queued=%v err=%v", job, queued, err)
	}
}

func TestReleaseInventoryListingAndInitialPin(t *testing.T) {
	s, repo, org, _, viewer := releaseInventoryFixture(t)
	ctx := context.Background()
	release := createInventoryRelease(t, s, repo, 1, false)
	r := releaseInventoryRequest(t, viewer, org, repo, nil)
	r.Method = http.MethodGet
	w := httptest.NewRecorder()
	s.handleListReleases(w, r)
	var response struct {
		Data      []store.ReleaseWithRisk       `json:"data"`
		Inventory store.ReleaseInventorySummary `json:"inventory"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || len(response.Data) != 1 || !response.Data[0].Inventory.CanExtract ||
		response.Inventory.Eligible != 1 || !response.Inventory.Enabled {
		t.Fatalf("missing inventory response status=%d body=%s", w.Code, w.Body)
	}
	ref, err := s.queries.GetRefByID(ctx, release.RefID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.queries.CreatePlaceholderSnapshot(ctx, ref.ID, *ref.LatestCommitSHA)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.pinReleaseInventorySnapshot(ctx, ref, snapshot); err != nil {
		t.Fatal(err)
	}
	current, err := s.queries.GetReleaseByID(ctx, release.ID)
	if err != nil || current.SnapshotID == nil || *current.SnapshotID != snapshot.ID {
		t.Fatalf("first observed release commit not attached: release=%+v err=%v", current, err)
	}
	pinned, err := s.queries.GetSnapshotByID(ctx, snapshot.ID)
	if err != nil || !pinned.Pinned {
		t.Fatalf("release snapshot not protected from retention: snapshot=%+v err=%v", pinned, err)
	}
	s.cfg.DepInventory.Enabled = false
	w = httptest.NewRecorder()
	s.handleListReleases(w, r)
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Inventory.Enabled || response.Data[0].Inventory.CanExtract {
		t.Fatalf("disabled extraction offered actions: %s", w.Body)
	}
}

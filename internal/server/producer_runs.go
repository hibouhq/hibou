package server

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
)

// sbomMatchingProducer is the producer key of SBOM advisory matching.
const sbomMatchingProducer = store.ProducerSBOMMatching

// Producer coverage statuses, comparing a snapshot with its predecessor.
const (
	producerStatusRan     = "ran"     // ran here and in the previous snapshot
	producerStatusNew     = "new"     // ran here, not in the previous snapshot
	producerStatusMissing = "missing" // ran in the previous snapshot, not here
	producerStatusPending = "pending" // started here but has not finished
)

// producerCoverage is one producer's line in the scan coverage panel.
type producerCoverage struct {
	Producer        string              `json:"producer"`
	Status          string              `json:"status"`
	Outcome         string              `json:"outcome,omitempty"`
	Version         *string             `json:"version,omitempty"`
	PreviousVersion *string             `json:"previous_version,omitempty"`
	Scope           string              `json:"scope,omitempty"`
	ScopeDeclared   bool                `json:"scope_declared"`
	ScopePaths      []string            `json:"scope_paths"`
	FindingCount    int                 `json:"finding_count"`
	SkippedFiles    []store.SkippedFile `json:"skipped_files"`
	Detail          string              `json:"detail,omitempty"`
	Runs            []store.ProducerRun `json:"runs"`
}

type producerRunsResponse struct {
	SnapshotID         string             `json:"snapshot_id"`
	CommitSHA          string             `json:"commit_sha"`
	PreviousSnapshotID *string            `json:"previous_snapshot_id,omitempty"`
	PreviousCommitSHA  *string            `json:"previous_commit_sha,omitempty"`
	Producers          []producerCoverage `json:"producers"`
}

// @Summary      Scan coverage of a snapshot
// @Description  Lists each producer (SARIF tool, secret scanning, SBOM matching) with what it covered on this snapshot — outcome, version, full or partial scope, files it did not analyse — compared with the previous finished snapshot of the same ref. A producer that ran before but not here is "missing": its findings were not re-checked (ADR-034).
// @Tags         snapshots
// @Produce      json
// @Param        provider    path      string  true   "Forge provider"
// @Param        slug        path      string  true   "Organization slug"
// @Param        repoSlug    path      string  true   "Repository slug"
// @Param        snapshotID  path      string  true   "Snapshot ID"
// @Success      200  {object}  api.Response{data=server.producerRunsResponse}
// @Failure      400  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/snapshots/{snapshotID}/producer-runs [get]
func (s *Server) handleGetSnapshotProducerRuns(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	snapshot, status, message := s.loadSnapshotForRepoByID(r, repo, chi.URLParam(r, "snapshotID"))
	if status != 0 {
		api.JSONError(w, status, message)
		return
	}
	ctx := r.Context()
	current, err := snapshotProducerRuns(ctx, s.queries, snapshot)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load producer runs")
		return
	}
	response := producerRunsResponse{SnapshotID: snapshot.ID.String(), CommitSHA: snapshot.CommitSHA}
	previous, err := s.queries.GetPreviousCompleteSnapshotByRef(ctx, snapshot)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load previous snapshot")
		return
	}
	var previousRuns []store.ProducerRun
	if previous != nil {
		previousRuns, err = snapshotProducerRuns(ctx, s.queries, previous)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load previous producer runs")
			return
		}
		id := previous.ID.String()
		commit := previous.CommitSHA
		response.PreviousSnapshotID = &id
		response.PreviousCommitSHA = &commit
	}
	response.Producers = compareProducerRuns(current, previousRuns)
	api.JSON(w, http.StatusOK, response)
}

// snapshotProducerRuns returns the recorded runs plus the SBOM matching run
// derived from the snapshot's latest advisory scan.
func snapshotProducerRuns(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot) ([]store.ProducerRun, error) {
	return queries.SnapshotProducerRuns(ctx, snapshot.ID)
}

// compareProducerRuns groups runs by producer and compares them with the
// previous snapshot's. Several artifacts can carry the same producer (one
// SARIF per module): the producer's outcome is the worst of its runs, its
// scope partial if any run was, and its skipped files the union.
func compareProducerRuns(current, previous []store.ProducerRun) []producerCoverage {
	group := func(runs []store.ProducerRun) map[string][]store.ProducerRun {
		out := make(map[string][]store.ProducerRun)
		for _, run := range runs {
			out[run.Producer] = append(out[run.Producer], run)
		}
		return out
	}
	currentByProducer := group(current)
	previousByProducer := group(previous)

	out := make([]producerCoverage, 0, len(currentByProducer)+len(previousByProducer))
	for producer, runs := range currentByProducer {
		coverage := summarizeProducerRuns(producer, runs)
		_, ranBefore := previousByProducer[producer]
		switch {
		case coverage.Outcome == "":
			coverage.Status = producerStatusPending
		case ranBefore:
			coverage.Status = producerStatusRan
		default:
			coverage.Status = producerStatusNew
		}
		if before, ok := previousByProducer[producer]; ok {
			coverage.PreviousVersion = summarizeProducerRuns(producer, before).Version
		}
		out = append(out, coverage)
	}
	for producer, runs := range previousByProducer {
		if _, ok := currentByProducer[producer]; ok {
			continue
		}
		before := summarizeProducerRuns(producer, runs)
		out = append(out, producerCoverage{
			Producer:        producer,
			Status:          producerStatusMissing,
			PreviousVersion: before.Version,
			ScopePaths:      []string{},
			SkippedFiles:    []store.SkippedFile{},
			Runs:            []store.ProducerRun{},
		})
	}
	sort.Slice(out, func(i, j int) bool {
		// Missing producers first: they are the gap the panel exists to show.
		if (out[i].Status == producerStatusMissing) != (out[j].Status == producerStatusMissing) {
			return out[i].Status == producerStatusMissing
		}
		return out[i].Producer < out[j].Producer
	})
	return out
}

var producerOutcomeRank = map[string]int{
	store.ProducerOutcomeCompleted: 1,
	store.ProducerOutcomePartial:   2,
	store.ProducerOutcomeFailed:    3,
}

func summarizeProducerRuns(producer string, runs []store.ProducerRun) producerCoverage {
	coverage := producerCoverage{
		Producer:     producer,
		Scope:        store.ProducerScopeFull,
		ScopePaths:   []string{},
		SkippedFiles: []store.SkippedFile{},
		Runs:         runs,
	}
	seenSkipped := map[string]struct{}{}
	seenPaths := map[string]struct{}{}
	details := make([]string, 0)
	declared := true
	pending := false
	for _, run := range runs {
		if run.Outcome == "" {
			pending = true
		} else if producerOutcomeRank[run.Outcome] > producerOutcomeRank[coverage.Outcome] {
			coverage.Outcome = run.Outcome
		}
		if run.Version != nil && coverage.Version == nil {
			coverage.Version = run.Version
		}
		if run.Scope == store.ProducerScopePartial {
			coverage.Scope = store.ProducerScopePartial
		}
		declared = declared && run.ScopeDeclared
		coverage.FindingCount += run.FindingCount
		for _, path := range run.ScopePaths {
			if _, dup := seenPaths[path]; !dup {
				seenPaths[path] = struct{}{}
				coverage.ScopePaths = append(coverage.ScopePaths, path)
			}
		}
		for _, skipped := range run.SkippedFiles {
			if _, dup := seenSkipped[skipped.Path]; !dup {
				seenSkipped[skipped.Path] = struct{}{}
				coverage.SkippedFiles = append(coverage.SkippedFiles, skipped)
			}
		}
		if run.Detail != nil && *run.Detail != "" {
			details = append(details, *run.Detail)
		}
	}
	// A producer with one run still going is not finished, whatever its
	// other runs say.
	if pending {
		coverage.Outcome = ""
	}
	coverage.ScopeDeclared = declared && len(runs) > 0
	coverage.Detail = strings.Join(details, "; ")
	return coverage
}

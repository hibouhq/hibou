package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/store"
)

// reachabilityRequest is a CI analyzer's verdict for one snapshot: which
// advisories are actually reachable from the built code and which are not.
// Identifiers are the human ids analyzers speak (GO-/CVE-/GHSA-…); the server
// matches them against advisory canonical ids and aliases.
type reachabilityRequest struct {
	CommitSHA string `json:"commit_sha"`
	Analyzer  string `json:"analyzer"`
	// Identifier mode (Go / govulncheck, symbol-level): advisory ids.
	Reachable   []string `json:"reachable"`
	Unreachable []string `json:"unreachable"`
	// Reference-inventory mode (Java class-level, Rust crate-level): what the
	// built code names. Persisted per snapshot so a NEWLY PUBLISHED CVE on
	// unchanged code is classified by the daily advisory scan immediately,
	// without waiting for the next CI run.
	GoSymbols      []string `json:"go_symbols"`
	JavaPackages   []string `json:"java_packages"`
	RustReferenced []string `json:"rust_referenced"`
	RustPresent    []string `json:"rust_present"`
}

type reachabilityResponse struct {
	SnapshotID         string `json:"snapshot_id"`
	ReachableUpdated   int64  `json:"reachable_updated"`
	UnreachableUpdated int64  `json:"unreachable_updated"`
}

// @Summary      Submit reachability analysis
// @Description  Applies CI-side reachability verdicts (e.g. govulncheck call-graph analysis) to the snapshot identified by the commit SHA. Findings named in `reachable` are marked reachable, `unreachable` ones not_reachable; anything unmentioned stays unknown. With the org's reachability setting on, unreachable findings stop counting toward gate severity ceilings.
// @Tags         vulnerabilities
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Param        payload   body  server.reachabilityRequest  true  "Analyzer verdicts"
// @Success      200  {object}  api.Response{data=server.reachabilityResponse}
// @Failure      400  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/reachability [post]
func (s *Server) handleSubmitReachability(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapUploads, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}

	var input reachabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	input.CommitSHA = strings.TrimSpace(input.CommitSHA)
	if input.CommitSHA == "" {
		api.JSONError(w, http.StatusBadRequest, "commit_sha is required")
		return
	}
	refs := store.SnapshotCodeRefs{
		GoSymbols:      normalizeIdentifiers(input.GoSymbols),
		JavaPackages:   normalizeIdentifiers(input.JavaPackages),
		RustReferenced: normalizeIdentifiers(input.RustReferenced),
		RustPresent:    normalizeIdentifiers(input.RustPresent),
	}
	if len(input.Reachable) == 0 && len(input.Unreachable) == 0 && refs.Empty() {
		api.JSONError(w, http.StatusBadRequest, "no verdicts supplied")
		return
	}

	snapshot, err := s.queries.GetLatestSnapshotByRepoAndSHA(r.Context(), repo.ID, input.CommitSHA)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve snapshot")
		return
	}
	if snapshot == nil {
		api.JSONError(w, http.StatusNotFound, "no snapshot for this commit — upload artifacts first")
		return
	}

	reachable, err := s.queries.SetVulnerabilityReachability(r.Context(), snapshot.ID, "reachable", normalizeIdentifiers(input.Reachable))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record reachability")
		return
	}
	unreachable, err := s.queries.SetVulnerabilityReachability(r.Context(), snapshot.ID, "not_reachable", normalizeIdentifiers(input.Unreachable))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record reachability")
		return
	}

	// Reference-inventory mode: persist the refs (for future advisories on
	// this snapshot), then classify the current findings from them.
	if !refs.Empty() {
		if err := s.queries.UpsertSnapshotCodeRefs(r.Context(), snapshot.ID, refs); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to store code references")
			return
		}
		refReachable, refUnreachable, err := s.queries.ApplyReachabilityFromCodeRefs(r.Context(), snapshot.ID, refs)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to classify from code references")
			return
		}
		reachable += refReachable
		unreachable += refUnreachable
	}

	// The gate may weigh reachability (org setting); the verdicts just
	// changed, so re-publish.
	s.publishGateRecompute(r.Context(), repo.ID)

	api.JSON(w, http.StatusOK, reachabilityResponse{
		SnapshotID:         snapshot.ID.String(),
		ReachableUpdated:   reachable,
		UnreachableUpdated: unreachable,
	})
}

func normalizeIdentifiers(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

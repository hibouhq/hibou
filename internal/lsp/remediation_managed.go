package lsp

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/remediation"
)

type managedRemediationJob struct {
	ID           string `json:"id"`
	Revision     int    `json:"revision"`
	State        string `json:"state"`
	BaseSHA      string `json:"base_sha"`
	TargetBranch string `json:"target_branch"`
	Error        string `json:"error"`
	Result       struct {
		Modules []struct {
			Unit        *remediation.Unit `json:"unit"`
			Unavailable string            `json:"unavailable"`
		} `json:"modules"`
		Artifact *remediation.Artifact `json:"artifact"`
	} `json:"result"`
}

type managedRemediationReady struct {
	JobID          string               `json:"job_id"`
	Revision       int                  `json:"revision"`
	TargetBranch   string               `json:"target_branch"`
	ProposalBranch string               `json:"proposal_branch"`
	Repository     string               `json:"repository"`
	Artifact       remediation.Artifact `json:"artifact"`
	ref            repoRef
	root           string
}

type managedRemediationParams struct {
	Root           string `json:"root"`
	LocalID        string `json:"local_id"`
	TargetBranch   string `json:"target_branch"`
	ConsentManaged bool   `json:"consent_managed"`
	JobID          string `json:"job_id"`
	Revision       int    `json:"revision"`
	SHA256         string `json:"sha256"`
}

func (s *Server) remediationManagedGenerate(ctx context.Context, p managedRemediationParams) (ready *managedRemediationReady, retErr error) {
	if !p.ConsentManaged {
		return nil, errors.New("managed regeneration requires explicit consent; local artifacts are never uploaded automatically")
	}
	ws, err := s.remediationWorkspace(p.Root)
	if err != nil {
		return nil, err
	}
	s.remediationMu.Lock()
	draft := s.remediationDrafts[p.LocalID]
	if draft == nil || draft.prepared.Root != ws.root || draft.artifact == nil || time.Now().After(draft.prepared.ExpiresAt) {
		s.remediationMu.Unlock()
		return nil, errors.New("generate and review a current local artifact first")
	}
	selection := draft.generatedSelection
	base := draft.prepared.BaseSHA
	selectedUnits := slices.Clone(draft.prepared.Units)
	s.remediationMu.Unlock()
	head, err := ws.git.head(ctx)
	if err != nil {
		return nil, err
	}
	if head != base {
		return nil, errors.New("local HEAD changed; prepare a new batch")
	}
	if p.TargetBranch == "" {
		return nil, errors.New("choose the existing PR target branch explicitly")
	}
	client, err := s.api()
	if err != nil {
		return nil, err
	}
	ref, err := ws.resolveRepo(ctx, client, ws.git.branch(ctx))
	if err != nil {
		return nil, err
	}
	path := repoPath(*ref) + "/remediation"
	var capabilities struct {
		CanGenerate       bool   `json:"can_generate"`
		GenerationReason  string `json:"generation_reason"`
		CanPublish        bool   `json:"publication_available"`
		PublicationReason string `json:"publication_reason"`
	}
	if err := client.get(ctx, path+"/capabilities", nil, &capabilities); err != nil {
		return nil, err
	}
	if !capabilities.CanGenerate {
		return nil, fmt.Errorf("managed generation unavailable: %s", capabilities.GenerationReason)
	}
	if !capabilities.CanPublish {
		return nil, fmt.Errorf("hibou publication unavailable: %s", capabilities.PublicationReason)
	}
	var vulns []string
	for _, u := range selectedUnits {
		if slices.Contains(selection.UnitIDs, u.ID) {
			vulns = append(vulns, u.Vulns...)
		}
	}
	slices.Sort(vulns)
	vulns = slices.Compact(vulns)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var job managedRemediationJob
	if err := client.do(ctx, http.MethodPost, path+"/prepare", nil, map[string]any{
		"target_branch": p.TargetBranch, "expected_head_sha": base, "vulns": vulns,
	}, &job, nil); err != nil {
		return nil, err
	}
	if _, err := uuid.Parse(job.ID); err != nil {
		return nil, errors.New("managed prepare returned an invalid job identity")
	}
	jobPath := path + "/" + job.ID
	completed := false
	defer func() {
		if !completed {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// Cancellation is best-effort once the client connection is gone;
			// the job's own deadline and lease fencing remain authoritative.
			if err := client.do(cleanup, http.MethodPost, jobPath+"/cancel", nil, map[string]any{}, nil, nil); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("managed job %s cancellation could not be confirmed: %w", job.ID, err))
			}
		}
	}()
	if job.BaseSHA != base {
		return nil, errors.New("managed source differs from the reviewed local base")
	}
	if err := waitManaged(ctx, client, jobPath, &job, "awaiting_selection"); err != nil {
		return nil, err
	}
	var units []map[string]any
	for _, id := range selection.UnitIDs {
		found := false
		for _, module := range job.Result.Modules {
			if module.Unit != nil && module.Unit.ID == id {
				level := module.Unit.UpgradeLevel
				if selection.UpgradeLevel != "" {
					level = selection.UpgradeLevel
				}
				units = append(units, map[string]any{"id": id, "upgrade_level": level, "version_targets": selection.VersionTargets[id]})
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("managed profile cannot prepare selected module %s; review its job in the website", id)
		}
	}
	if err := client.do(ctx, http.MethodPost, jobPath+"/generate", nil, map[string]any{"revision": job.Revision, "units": units}, &job, nil); err != nil {
		return nil, err
	}
	if err := waitManaged(ctx, client, jobPath, &job, "ready"); err != nil {
		return nil, err
	}
	if job.Result.Artifact == nil || job.BaseSHA != base {
		return nil, errors.New("managed job is missing its verified artifact")
	}
	patch, err := client.remediationPatch(ctx, jobPath+"/patch")
	if err != nil {
		return nil, err
	}
	artifact := *job.Result.Artifact
	artifact.Patch = patch
	if fmt.Sprintf("%x", sha256.Sum256(patch)) != artifact.SHA256 {
		return nil, errors.New("managed patch does not match the reviewed artifact digest")
	}
	branch, err := remediation.BranchName(job.TargetBranch, base, artifact.SHA256)
	if err != nil {
		return nil, err
	}
	result := &managedRemediationReady{JobID: job.ID, Revision: job.Revision, TargetBranch: job.TargetBranch, ProposalBranch: branch,
		Repository: ref.Provider + "/" + ref.Org + "/" + ref.Repo, Artifact: artifact, ref: *ref, root: ws.root}
	s.mu.Lock()
	if s.managedArtifacts == nil {
		s.managedArtifacts = map[string]*managedRemediationReady{}
	}
	if len(s.managedArtifacts) >= 4 {
		clear(s.managedArtifacts)
	}
	s.managedArtifacts[job.ID] = result
	s.mu.Unlock()
	completed = true
	return result, nil
}

func (s *Server) remediationManagedPublish(ctx context.Context, p managedRemediationParams) (*forge.PullRequest, error) {
	s.mu.Lock()
	ready := s.managedArtifacts[p.JobID]
	s.mu.Unlock()
	if ready == nil || ready.root != p.Root || ready.Revision != p.Revision || ready.Artifact.SHA256 != p.SHA256 {
		return nil, errors.New("review the managed artifact before requesting publication")
	}
	if _, err := s.remediationWorkspace(p.Root); err != nil {
		return nil, err
	}
	client, err := s.api()
	if err != nil {
		return nil, err
	}
	path := repoPath(ready.ref) + "/remediation/" + ready.JobID
	var current managedRemediationJob
	if err := client.get(ctx, path, nil, &current); err != nil {
		return nil, err
	}
	if current.State != "ready" || current.Revision != ready.Revision || current.Result.Artifact == nil || current.Result.Artifact.SHA256 != p.SHA256 {
		return nil, errors.New("managed artifact is no longer ready at the reviewed revision")
	}
	var pr forge.PullRequest
	if err := client.do(ctx, http.MethodPost, path+"/publish", nil, map[string]any{"revision": ready.Revision}, &pr, nil); err != nil {
		return nil, err
	}
	return &pr, nil
}

func waitManaged(ctx context.Context, client *apiClient, path string, job *managedRemediationJob, wanted string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if job.State == wanted {
			return nil
		}
		switch job.State {
		case "failed", "cancelled", "expired":
			return fmt.Errorf("managed remediation %s: %s", job.State, job.Error)
		case "queued_prepare", "preparing", "awaiting_selection", "queued_generate", "generating", "ready":
		default:
			return errors.New("managed job returned an unknown state")
		}
		if job.State == "ready" || (job.State == "awaiting_selection" && wanted == "ready") {
			return errors.New("managed job is not in the expected generation phase")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if err := client.get(ctx, path, nil, job); err != nil {
			return err
		}
	}
}

func (c *apiClient) remediationPatch(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+"/api/v1"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "text/x-diff")
	req.Header.Set("User-Agent", c.agent)
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("artifact redirects are not accepted") }
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("managed patch download returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, remediation.MaxPatchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > remediation.MaxPatchBytes {
		return nil, errors.New("managed patch is empty or too large")
	}
	return data, nil
}

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/remediation"
	"github.com/hibouhq/hibou/internal/secretscan"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/workload"
)

type ManagedWorkloadRunner interface {
	Ready(context.Context) error
	Run(context.Context, workload.Request) (workload.Result, error)
	Cleanup(context.Context) error
}

func managedTool(cfg config.ManagedExecutionConfig) remediation.Tool {
	return remediation.Tool{
		Path: cfg.NPMPath, VersionOutput: cfg.NPMVersion, PATH: cfg.ToolPath,
		RuntimePath: cfg.NodePath, RuntimeVersionOutput: cfg.NodeVersion,
		RegistryOrigin: cfg.RegistryURL,
	}
}

// RunManagedController belongs to the separately deployed controller, never
// the API background loops. Only the shared runner creates Kubernetes Jobs.
func (s *Server) RunManagedController(ctx context.Context, runner ManagedWorkloadRunner, cfg config.ManagedExecutionConfig, jobTimeout time.Duration) error {
	if !cfg.Enabled || runner == nil || s.objStore == nil || jobTimeout <= 0 {
		return errors.New("managed controller requires enabled execution, a runner and private artifact storage")
	}
	if err := runner.Ready(ctx); err != nil {
		return err
	}
	if err := runner.Cleanup(ctx); err != nil {
		return err
	}
	registry, err := remediation.NewNPMMirrorClient(remediation.NPMMirrorConfig{
		URL: cfg.RegistryURL, CAFile: cfg.RegistryCAFile, TokenFile: cfg.RegistryTokenFile,
	})
	if err != nil {
		return err
	}
	defer registry.CloseIdleConnections()
	id := uuid.New()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.queries.RemoveRemediationController(cleanupCtx, id); err != nil {
			s.log.Error().Err(err).Msg("remove Kubernetes remediation controller heartbeat")
		}
	}()
	group, runCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			if err := runner.Ready(runCtx); err != nil {
				return fmt.Errorf("kubernetes workload readiness: %w", err)
			}
			if err := s.queries.HeartbeatRemediationController(runCtx, id, cfg.Profile()); err != nil {
				return err
			}
			select {
			case <-runCtx.Done():
				return runCtx.Err()
			case <-ticker.C:
			}
		}
	})
	group.Go(func() error {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			if err := s.cleanupManagedArtifacts(runCtx); err != nil {
				return err
			}
			if err := runner.Cleanup(runCtx); err != nil {
				return err
			}
			select {
			case <-runCtx.Done():
				return runCtx.Err()
			case <-ticker.C:
			}
		}
	})
	group.Go(func() error {
		for {
			job, err := s.queries.ClaimRemediationJob(runCtx, uuid.New())
			if err != nil {
				return err
			}
			if job != nil {
				if err := s.runManagedClaim(runCtx, runner, cfg, job, registry, jobTimeout); err != nil {
					s.log.Error().Err(err).Str("job_id", job.ID.String()).Msg("managed Kubernetes remediation failed")
				}
				continue
			}
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-runCtx.Done():
				timer.Stop()
				return runCtx.Err()
			case <-timer.C:
			}
		}
	})
	err = group.Wait()
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) runManagedClaim(ctx context.Context, runner ManagedWorkloadRunner, cfg config.ManagedExecutionConfig, job *store.RemediationJob, registry *http.Client, jobTimeout time.Duration) (returnErr error) {
	workCtx, cancel := context.WithTimeout(ctx, min(jobTimeout, time.Until(job.ExpiresAt)))
	defer cancel()
	renewDone := make(chan struct{})
	go func() {
		defer close(renewDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case <-ticker.C:
				ok, err := s.queries.RenewRemediationLease(workCtx, job.ID, job.LeaseToken.UUID)
				if err != nil || !ok {
					if err != nil {
						s.log.Error().Err(err).Str("job_id", job.ID.String()).Msg("renew remediation claim")
					}
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-renewDone }()
	defer func() {
		if returnErr != nil && ctx.Err() == nil {
			finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer finishCancel()
			_, finishErr := s.queries.FinishRemediationJob(finishCtx, job.ID, job.LeaseToken.UUID, "failed", json.RawMessage(`{}`), "", "Kubernetes remediation failed; inspect the controller audit/logs and prepare a new draft.")
			returnErr = errors.Join(returnErr, finishErr)
		}
	}()
	result, err := s.executeManagedClaim(workCtx, runner, cfg, job, registry)
	if workCtx.Err() != nil {
		return workCtx.Err()
	}
	if err != nil {
		return err
	}
	state, key := "awaiting_selection", ""
	if job.State == "generating" {
		state = "ready"
		payload, err := json.Marshal(result)
		if err != nil || len(payload) > remediation.MaxInputBytes {
			return errors.New("verified private artifact exceeds storage limits")
		}
		key = "remediation/" + job.RepoID.String() + "/" + job.ID.String() + "/" + job.LeaseToken.UUID.String() + ".json"
		if err := s.queries.RegisterRemediationArtifact(workCtx, key, job.ID, job.ExpiresAt); err != nil {
			return err
		}
		if err := s.objStore.Put(workCtx, key, bytes.NewReader(payload), "application/json"); err != nil {
			return err
		}
		result.Files = nil
		result.Artifact.Patch = nil
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	ok, err := s.queries.FinishRemediationJob(workCtx, job.ID, job.LeaseToken.UUID, state, data, key, "")
	if err != nil || !ok {
		if key != "" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cleanupCancel()
			if cleanupErr := s.queries.ScheduleRemediationArtifactCleanup(cleanupCtx, key); cleanupErr != nil {
				s.log.Error().Err(cleanupErr).Msg("schedule rejected remediation artifact cleanup")
			}
		}
		return errors.Join(err, store.ErrRemediationConflict)
	}
	return nil
}

func (s *Server) executeManagedClaim(ctx context.Context, runner ManagedWorkloadRunner, cfg config.ManagedExecutionConfig, job *store.RemediationJob, registry *http.Client) (*remediation.ManagedResult, error) {
	var input remediation.ManagedInput
	if err := json.Unmarshal(job.Request, &input); err != nil {
		return nil, err
	}
	if input.BaseSHA != job.BaseSHA || input.Profile != cfg.Profile() {
		return nil, errors.New("managed source/profile changed; prepare a new draft")
	}
	input.Tool = managedTool(cfg)
	repo, err := s.queries.GetRepositoryByID(ctx, job.RepoID)
	if err != nil || repo == nil {
		return nil, errors.New("managed repository unavailable")
	}
	scratch, err := os.MkdirTemp("", "hibou-controller-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	checkout, err := s.managedCheckout(ctx, repo, job, scratch)
	if err != nil {
		return nil, err
	}
	defer checkout.Close()
	snapshot, err := remediation.CaptureManagedSnapshot(ctx, checkout.Dir, job.BaseSHA)
	if err != nil {
		return nil, err
	}
	match := s.managedMatch(repo)
	if job.State == "preparing" {
		return remediation.PrepareManagedModules(ctx, checkout.Dir, input, snapshot, match)
	}
	if job.State != "generating" || input.Operation != "generate" {
		return nil, errors.New("managed job is not an executable generation claim")
	}
	snapshot, err = remediation.SelectManagedSnapshot(snapshot, input.Units)
	if err != nil {
		return nil, err
	}
	handler, closeBroker, err := remediation.ManagedBrokerHandler(ctx, match, registry)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := closeBroker(); err != nil {
			s.log.Error().Err(err).Str("job_id", job.ID.String()).Msg("close managed registry broker")
		}
	}()
	request := remediation.ManagedWorkload{Input: input, Snapshot: snapshot}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	run := workload.Request{
		ID: job.ID.String(), Fence: job.LeaseToken.UUID.String(), Class: workload.ClassRemediation, Input: payload, Handler: handler,
		OnIdentity: func(ctx context.Context, identity workload.Identity) error {
			return s.queries.BindRemediationWorkload(ctx, job.ID, job.LeaseToken.UUID, identity.Attempt, identity.JobUID, identity.PodUID)
		},
	}
	completed, err := runner.Run(ctx, run)
	if err != nil {
		return nil, err
	}
	var result remediation.ManagedResult
	if err := json.Unmarshal(completed.Output, &result); err != nil {
		return nil, err
	}
	backend := remediation.NPMBackend{Tool: input.Tool, Match: match}
	if err := remediation.VerifyManagedCandidate(ctx, checkout.Dir, input, &result, backend, false); err != nil {
		return nil, err
	}
	if err := s.queries.RecordRemediationEvent(ctx, job.ID, "candidate_checked", map[string]string{
		"job_uid": completed.JobUID, "pod_uid": completed.PodUID, "profile": cfg.Profile(),
	}); err != nil {
		return nil, err
	}
	request.Input.Operation, request.Input.Candidate = "verify", &result
	run.ID += "-verify"
	run.Input, err = json.Marshal(request)
	if err != nil {
		return nil, err
	}
	verified, err := runner.Run(ctx, run)
	if err != nil {
		return nil, err
	}
	var verification remediation.ManagedResult
	if err := json.Unmarshal(verified.Output, &verification); err != nil || verification.Artifact == nil ||
		verification.Artifact.SHA256 != result.Artifact.SHA256 || verification.Error != "" {
		return nil, errors.New("independent Kubernetes verifier did not confirm the reviewed candidate")
	}
	if err := remediation.ValidateManagedArtifact(input, verification.Artifact); err != nil {
		return nil, err
	}
	if _, _, _, err := s.managedLiveTarget(ctx, repo); err != nil {
		return nil, err
	}
	if err := remediation.VerifyManagedCandidate(ctx, checkout.Dir, input, &result, backend, false); err != nil {
		return nil, err
	}
	if err := closeBroker(); err != nil {
		return nil, err
	}
	if err := s.queries.RecordRemediationEvent(ctx, job.ID, "verified", map[string]string{
		"job_uid": verified.JobUID, "pod_uid": verified.PodUID, "profile": cfg.Profile(),
	}); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *Server) managedCheckout(ctx context.Context, repo *store.Repository, job *store.RemediationJob, scratch string) (*secretscan.ManifestCheckout, error) {
	ctx, provider, live, err := s.managedLiveTarget(ctx, repo)
	if err != nil || live.CloneURL == "" {
		return nil, errors.New("managed immutable source unavailable")
	}
	var token string
	if auth, ok := provider.(forge.CloneAuthProvider); ok {
		token, err = auth.CloneToken(ctx, live.Owner, live.Name)
		if err != nil {
			return nil, err
		}
	}
	checkout, err := secretscan.CheckoutManifests(ctx, scratch, live.CloneURL, job.SourceRef, job.BaseSHA, token, remediation.IsInputPath)
	if err != nil {
		return nil, err
	}
	if checkout.TreeTruncated || !strings.EqualFold(checkout.Commit, job.BaseSHA) {
		checkout.Close()
		return nil, errors.New("managed source checkout is incomplete or differs from pinned SHA")
	}
	return checkout, nil
}

func (s *Server) cleanupManagedArtifacts(ctx context.Context) error {
	keys, err := s.queries.ExpireRemediationJobs(ctx)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := s.queries.ScheduleRemediationArtifactCleanup(ctx, key); err != nil {
			return err
		}
	}
	expired, err := s.queries.ListExpiredRemediationArtifacts(ctx)
	if err != nil {
		return err
	}
	for _, key := range expired {
		if err := s.objStore.Delete(ctx, key); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := s.queries.ClearExpiredRemediationArtifact(ctx, key); err != nil {
			return err
		}
		if err := s.queries.ClearRemediationArtifactExpiry(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

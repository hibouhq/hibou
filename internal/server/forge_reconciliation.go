package server

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/depinventory"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/version"
)

type forgeCheckpoint struct {
	Cache            forge.ResponseCache               `json:"cache,omitempty"`
	Refs             []forge.RefObservation            `json:"refs,omitempty"`
	PRs              []forge.PullRequestEvent          `json:"prs,omitempty"`
	Releases         []forge.ReleaseObservation        `json:"releases,omitempty"`
	Installations    []store.ForgeInstallationSnapshot `json:"installations,omitempty"`
	Note             string                            `json:"note,omitempty"`
	GatePending      bool                              `json:"gate_pending,omitempty"`
	BuildOffset      int                               `json:"build_offset,omitempty"`
	Initialized      bool                              `json:"initialized,omitempty"`
	AnalysisRevision string                            `json:"analysis_revision,omitempty"`
}

type forgeObservationSourceKey struct{}

const forgeDeliveryLockTimeout = 5 * time.Second

func (s *Server) forgeEventConfig(id string) config.ForgeConfig {
	for _, fc := range s.cfg.Forges {
		if fc.ID == id {
			return fc
		}
	}
	return config.ForgeConfig{ID: id}
}

func (s *Server) lockForgeDelivery(ctx context.Context, provider string, try bool) (func(), error) {
	if s.db == nil || !s.forgeEventConfig(provider).PollingEnabled() {
		return func() {}, nil
	}
	acquire, cancel := context.WithTimeout(ctx, forgeDeliveryLockTimeout)
	defer cancel()
	conn, err := s.db.Conn(acquire)
	if err != nil {
		return nil, err
	}
	key := "forge-delivery:" + provider
	if try {
		var locked bool
		err = conn.QueryRowContext(acquire, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, key).Scan(&locked)
		if err == nil && !locked {
			_ = conn.Close()
			return nil, errors.New("another replica is processing this forge")
		}
	} else {
		_, err = conn.ExecContext(acquire, `SELECT pg_advisory_lock(hashtextextended($1,0))`, key)
	}
	if err != nil {
		// A cancelled query may already have acquired the session lock.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
		return nil, fmt.Errorf("acquire forge delivery lock: %w", errors.Join(err, acquire.Err()))
	}
	return func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), store.AdvisoryLockCleanupTimeout)
		defer cancel()
		var released bool
		err := conn.QueryRowContext(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, key).Scan(&released)
		if err == nil && !released {
			err = errors.New("connection no longer owns forge delivery lock")
		}
		if err != nil {
			s.log.Error().Err(err).Str("provider", provider).Msg("release forge delivery lock")
			// A connection with a session lock must never return to the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		_ = conn.Close()
	}, nil
}

func (s *Server) runForgeReconciliationLoop(ctx context.Context) {
	providers := []string{}
	for _, fc := range s.cfg.Forges {
		if !fc.PollingEnabled() {
			continue
		}
		providers = append(providers, fc.ID)
	}
	if len(providers) == 0 {
		return
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	initialized := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		for _, provider := range providers {
			if initialized[provider] {
				continue
			}
			if err := s.queries.EnsureForgeReconciliation(ctx, provider, "app", "inventory", uuid.NullUUID{}); err != nil {
				s.log.Error().Err(err).Str("provider", provider).Msg("initialize forge reconciliation; will retry")
			} else {
				initialized[provider] = true
			}
		}
		// One bounded scope per replica. Other replicas claim different
		// providers; per-provider locks also serialize hybrid deliveries.
		job, err := s.queries.ClaimForgeReconciliation(ctx, providers, uuid.New(), time.Now().UTC())
		if err != nil {
			s.log.Error().Err(err).Msg("claim forge reconciliation")
		}
		if job != nil {
			s.processForgeReconciliation(ctx, job)
		}
		if job != nil {
			timer.Reset(0)
		} else {
			timer.Reset(time.Second)
		}
	}
}

func (s *Server) processForgeReconciliation(parent context.Context, job *store.ForgeReconciliation) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	unlock, err := s.lockForgeDelivery(ctx, job.Provider, true)
	if err == nil {
		defer unlock()
		err = s.reconcileForgeScope(ctx, job)
	}
	if err == nil {
		return
	}
	s.log.Warn().Err(err).Str("provider", job.Provider).Str("scope", job.Scope).Str("kind", job.Kind).Msg("forge reconciliation incomplete")
	delay := time.Duration(min(job.Attempts, 10)) * 30 * time.Second
	due := time.Now().Add(delay + forgePollJitter(10*time.Second))
	var apiErr *forge.APIError
	if errors.As(err, &apiErr) && apiErr.RetryAt.After(due) {
		due = apiErr.RetryAt.Add(forgePollJitter(10 * time.Second))
	}
	finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer finishCancel()
	if apiErr != nil && !apiErr.RetryAt.IsZero() {
		if err := s.queries.DeferForgeProvider(finishCtx, job.Provider, due); err != nil {
			s.log.Error().Err(err).Str("provider", job.Provider).Msg("persist shared forge API backoff")
		}
	}
	var committed *forgePostCommitError
	if errors.As(err, &committed) {
		return
	}
	if finishErr := s.queries.FinishForgeReconciliation(finishCtx, job, job.State, due, truncateSecretScanError(err)); finishErr != nil {
		s.log.Error().Err(finishErr).Str("job", job.ID.String()).Msg("record forge reconciliation failure")
	}
}

// A forge write after the observation transaction cannot finish the already
// released lease again. The error is logged and the next PR poll retries it.
type forgePostCommitError struct{ err error }

func (e *forgePostCommitError) Error() string { return e.err.Error() }
func (e *forgePostCommitError) Unwrap() error { return e.err }

func (s *Server) reconcileForgeScope(ctx context.Context, job *store.ForgeReconciliation) error {
	ctx = context.WithValue(ctx, forgeObservationSourceKey{}, "poll")
	provider := s.forges[job.Provider]
	if provider == nil {
		return errors.New("reconciliation provider not configured")
	}
	var previous forgeCheckpoint
	if err := json.Unmarshal(job.State, &previous); err != nil {
		return fmt.Errorf("decode forge checkpoint: %w", err)
	}
	next := forgeCheckpoint{Cache: forge.ResponseCache{}, Initialized: true,
		AnalysisRevision: fmt.Sprintf("%s|%t|%t|%q|%t|%t|%s", version.Version, s.cfg.SecretScan.Enabled, s.cfg.SecretScan.OnPush,
			s.cfg.SecretScan.Providers, s.cfg.DepInventory.Enabled, s.cfg.DepInventory.OnPush, depinventory.Version)}
	// Copy cached pages so a failed observation cannot change the prior
	// checkpoint before the transaction commits.
	for path, value := range previous.Cache {
		next.Cache[path] = value
	}
	ctx = forge.WithResponseCache(ctx, next.Cache)
	var repo *store.Repository
	var pending []store.PendingForgeBuild
	var runs []forge.WorkflowRun
	if job.Kind == "inventory" {
		reader, ok := provider.(forge.InstallationRepositoryReader)
		if !ok {
			return errors.New("forge lacks installation repository reads")
		}
		installations, err := provider.Installations(ctx)
		if err != nil {
			return err
		}
		for _, inst := range installations {
			observed := store.ForgeInstallationSnapshot{ID: inst.ID, AccountID: inst.AccountID, Account: inst.AccountName, Suspended: inst.Suspended}
			if !inst.Suspended {
				repositories, err := reader.ListInstallationRepositories(ctx, inst.ID)
				if err != nil {
					return err
				}
				for _, r := range repositories {
					id := r.ProviderRepoID
					if id == "" {
						return errors.New("repository listing omitted immutable identity")
					}
					observed.Repositories = append(observed.Repositories, store.ForgeRepository{ProviderRepoID: &id, Owner: r.Owner, Name: r.Name, FullName: r.FullName, DefaultBranch: r.DefaultBranch, Private: r.Private, Archived: r.Archived, HTMLURL: r.HTMLURL})
				}
			}
			next.Installations = append(next.Installations, observed)
		}
		slices.SortFunc(next.Installations, func(a, b store.ForgeInstallationSnapshot) int {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
		for i := range next.Installations {
			slices.SortFunc(next.Installations[i].Repositories, func(a, b store.ForgeRepository) int { return strings.Compare(a.FullName, b.FullName) })
		}
	} else {
		var err error
		repo, err = s.queries.GetRepositoryByID(ctx, job.RepoID.UUID)
		if err != nil {
			return err
		}
		if repo == nil {
			return errors.New("enrolled repository no longer exists")
		}
		target, err := s.queries.VerifiedForgeRepositoryTarget(ctx, repo.ID)
		if err != nil {
			return err
		}
		owner, name := target.Owner, target.Name
		ctx = forge.WithRepositoryIdentity(ctx, target.AccountID, target.RepositoryID)
		switch job.Kind {
		case "refs":
			reader, ok := provider.(forge.RefReader)
			if !ok {
				return errors.New("forge lacks authoritative ref reads")
			}
			next.Refs, err = reader.ReadRefs(ctx, owner, name)
		case "pull_requests":
			reader, ok := provider.(forge.PullRequestReader)
			if !ok {
				return errors.New("forge lacks pull request reads")
			}
			next.PRs, err = reader.ReadOpenPullRequests(ctx, owner, name)
			if err != nil {
				return err
			}
			seen := map[int]bool{}
			for _, pr := range next.PRs {
				seen[pr.Number] = true
			}
			refs, err := s.allReconciliationRefs(ctx, repo.ID)
			if err != nil {
				return err
			}
			for _, ref := range refs {
				if ref.RefType != store.RefTypePullRequest || ref.PrState != nil && *ref.PrState != "open" {
					continue
				}
				number, e := strconv.Atoi(strings.TrimPrefix(ref.Name, "refs/pull/"))
				if e != nil {
					return fmt.Errorf("invalid canonical PR ref %q", ref.Name)
				}
				if seen[number] {
					continue
				}
				pr, e := reader.ReadPullRequest(ctx, owner, name, number)
				if e != nil {
					return e
				}
				next.PRs = append(next.PRs, pr)
			}
		case "releases":
			reader, ok := provider.(forge.ReleaseReader)
			if !ok {
				return errors.New("forge lacks release reads")
			}
			next.Releases, err = reader.ReadReleases(ctx, owner, name)
		case "builds":
			reader, ok := provider.(forge.WorkflowReader)
			if !ok {
				return errors.New("forge lacks Actions reads; pending builds rely on timeout")
			}
			pending, err = s.queries.PendingForgeBuilds(ctx, repo.ID, previous.BuildOffset)
			if err != nil {
				return err
			}
			if len(pending) > 100 {
				pending = pending[:100]
				next.BuildOffset = previous.BuildOffset + 100
				next.Note = "Pending build reconciliation is paged; additional identities are scheduled for the next cycle"
			}
			seen := map[string]bool{}
			for _, build := range pending {
				if build.RunID == "" || build.Attempt == "" {
					next.Note = "Some pending snapshots lack a workflow run/attempt identity; timeout policy applies"
					continue
				}
				if seen[build.RunID] {
					continue
				}
				seen[build.RunID] = true
				run, e := reader.ReadWorkflowRun(ctx, owner, name, build.RunID)
				if e != nil {
					return e
				}
				runs = append(runs, run)
			}
		default:
			return fmt.Errorf("unknown reconciliation kind %q", job.Kind)
		}
		if err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	q := s.queries.WithTx(tx)
	// A transaction-bound facade reuses lifecycle operations without copying
	// Server's mutexes or starting asynchronous work against a finished tx.
	domain := &Server{cfg: s.cfg, queries: q, log: s.log, forges: s.forges, repoConfigLoader: s.repoConfigLoader, bus: events.New(s.log)}
	changed := false
	inventoryChanged := !previous.Initialized || !reflect.DeepEqual(previous.Installations, next.Installations)
	switch job.Kind {
	case "inventory":
		if inventoryChanged {
			if err := q.ApplyForgeInventory(ctx, job.Provider, next.Installations); err != nil {
				return err
			}
			changed = true
		} else if err := q.TouchForgeInventory(ctx, job.Provider); err != nil {
			return err
		}
		if err := q.EnsureEnrolledForgeReconciliation(ctx, job.Provider); err != nil {
			return err
		}
	case "refs":
		changed, err = domain.applyObservedRefs(ctx, repo, next.Refs, previous.Refs, previous.Initialized && previous.AnalysisRevision == next.AnalysisRevision)
	case "pull_requests":
		for i := range next.PRs {
			pr := next.PRs[i]
			pr.Repo = forge.Repository{ProviderID: repo.ProviderID, FullName: repo.ProviderID}
			if !isWebhookCommitSHA(pr.HeadSHA) || !isWebhookCommitSHA(pr.BaseSHA) {
				return errors.New("PR observation omitted valid head/base commits")
			}
			if pr.Number <= 0 || pr.TargetBranch == "" || pr.Action == "closed" && pr.ClosedAt == nil || pr.Merged && pr.MergedAt == nil {
				return errors.New("PR observation omitted authoritative identity, target or lifecycle timestamps")
			}
			old := findObservedPR(previous.PRs, pr.Number)
			// A previously closed PR is only revisited when it reappears
			// in the open list. Terminal observations remain checkpointed.
			if old != nil && reflect.DeepEqual(*old, next.PRs[i]) {
				continue
			}
			request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
			if err = domain.handlePullRequestWebhookEvent(request, job.Provider, provider.ID(), pr); err != nil {
				return err
			}
			changed = true
		}
	case "releases":
		err = domain.applyObservedReleases(ctx, repo, previous.Releases, next.Releases)
		if len(previous.Releases) > 0 || len(next.Releases) > 0 {
			changed = !reflect.DeepEqual(previous.Releases, next.Releases)
		}
	case "builds":
		for _, run := range runs {
			if run.Status != "completed" || run.Conclusion == "success" || run.Conclusion == "" {
				continue
			}
			for _, build := range pending {
				if run.ID == build.RunID && run.Attempt == build.Attempt && run.SHA == build.SHA {
					var affected int64
					if affected, err = q.FailObservedBuild(ctx, repo.ID, run.ID, run.Attempt, run.SHA); err != nil {
						return err
					}
					changed = changed || affected > 0
				} else if run.ID == build.RunID {
					next.Note = "Some workflow observations do not match the pending snapshot's attempt/commit; timeout policy applies"
				}
			}
		}
	}
	if err != nil {
		return err
	}
	if changed && repo != nil {
		if err := q.RecordForgeReconciliationChange(ctx, job.Provider, repo.ID.String(), "forge."+job.Kind+".reconciled"); err != nil {
			return err
		}
	}
	forge.PruneResponseCache(ctx)
	if len(next.Cache) == 0 {
		next.Cache = nil
	}
	if len(next.Refs) == 0 {
		next.Refs = nil
	}
	if len(next.PRs) == 0 {
		next.PRs = nil
	}
	if len(next.Releases) == 0 {
		next.Releases = nil
	}
	if len(next.Installations) == 0 {
		next.Installations = nil
	}
	next.GatePending = previous.GatePending || changed && (job.Kind == "refs" || job.Kind == "pull_requests")
	job.RecordRun = changed
	job.StateUnchanged = reflect.DeepEqual(previous, next)
	encoded, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(encoded) > 16<<20 {
		return errors.New("reconciliation checkpoint exceeds 16 MiB; scope needs partitioning")
	}
	interval := s.forgeEventConfig(job.Provider).InventoryInterval
	if job.Kind == "pull_requests" && len(next.PRs) > 0 || job.Kind == "builds" && len(pending) > 0 || next.GatePending {
		interval = s.forgeEventConfig(job.Provider).PollInterval
	}
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	due := time.Now().Add(interval + forgePollJitter(interval/10))
	if err := q.FinishForgeReconciliation(ctx, job, encoded, due, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if job.Kind == "inventory" && inventoryChanged {
		if invalidator, ok := provider.(forge.CredentialInvalidator); ok {
			invalidator.InvalidateInstallationCredentials()
		}
	}
	if (next.GatePending || job.Kind == "pull_requests") && repo != nil && s.gatePublisher != nil {
		reporting, err := s.gatePublisher.RepositoryReportingEnabled(ctx, repo.ID)
		if err != nil {
			return &forgePostCommitError{err}
		}
		if !reporting {
			if err := s.gatePublisher.RetireUnintegratedChecks(ctx, repo.ID); err != nil {
				return &forgePostCommitError{err}
			}
			if next.GatePending {
				return s.clearForgeGatePending(ctx, job.ID)
			}
			return nil
		}
		if !next.GatePending {
			return nil
		}
		started := time.Now().UTC()
		refs, err := s.allReconciliationRefs(ctx, repo.ID)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if ref.RefType == store.RefTypePullRequest && (ref.PrState == nil || *ref.PrState == "open") {
				s.gatePublisher.PublishGateForRef(ctx, ref.ID)
			}
		}
		// Clear the durable intent only after the publisher's persisted
		// acknowledgement. A crash or denied check write retries next cycle.
		fresh, err := s.queries.ForgeGatePublicationFresh(ctx, repo.ID, started)
		if err != nil {
			return err
		}
		if fresh {
			return s.clearForgeGatePending(ctx, job.ID)
		}
	}
	return nil
}

func findObservedPR(prs []forge.PullRequestEvent, number int) *forge.PullRequestEvent {
	for i := range prs {
		if prs[i].Number == number {
			return &prs[i]
		}
	}
	return nil
}

func forgePollJitter(limit time.Duration) time.Duration {
	return time.Duration(rand.Int64N(max(int64(limit), 1))) //nolint:gosec // Scheduling jitter is not security-sensitive.
}

func (s *Server) allReconciliationRefs(ctx context.Context, repoID uuid.UUID) ([]store.Ref, error) {
	result := []store.Ref{}
	for offset := 0; ; {
		rows, total, err := s.queries.ListRefsByRepo(ctx, repoID, 200, offset)
		if err != nil {
			return nil, err
		}
		result = append(result, rows...)
		offset += len(rows)
		if offset >= total {
			return result, nil
		}
		if len(rows) == 0 {
			return nil, errors.New("ref pagination ended before total")
		}
		if offset >= 10000 {
			return nil, errors.New("tracked ref scope exceeds 10000 rows")
		}
	}
}

func (s *Server) applyObservedRefs(ctx context.Context, repo *store.Repository, observed, previous []forge.RefObservation, sameRevision bool) (bool, error) {
	refs, err := s.allReconciliationRefs(ctx, repo.ID)
	if err != nil {
		return false, err
	}
	seen := map[string]bool{}
	priorByKey := map[string]*store.Ref{}
	for i := range refs {
		priorByKey[string(refs[i].RefType)+":"+refs[i].Name] = &refs[i]
	}
	previousHeads := map[string]string{}
	if sameRevision {
		for _, ref := range previous {
			kind := store.RefTypeBranch
			if ref.Tag {
				kind = store.RefTypeTag
			}
			previousHeads[string(kind)+":"+ref.Name] = ref.SHA
		}
	}
	changed := false
	for _, ref := range observed {
		if ref.Name == "" || !isWebhookCommitSHA(ref.SHA) || isDeletedRefSHA(ref.SHA) {
			return false, errors.New("ref listing omitted a valid name or commit")
		}
		kind := store.RefTypeBranch
		prefix := "refs/heads/"
		if ref.Tag {
			kind = store.RefTypeTag
			prefix = "refs/tags/"
		}
		key := string(kind) + ":" + ref.Name
		seen[key] = true
		prior := priorByKey[key]
		if prior != nil && prior.LatestCommitSHA != nil && *prior.LatestCommitSHA == ref.SHA {
			if previousHeads[key] == ref.SHA {
				continue
			}
			event := forge.PushEvent{After: ref.SHA}
			if err := s.maybeEnqueueSecretScan(ctx, repo, kind, ref.Name, event); err != nil {
				return false, err
			}
			if err := s.maybeEnqueueDepExtraction(ctx, repo, kind, ref.Name, event); err != nil {
				return false, err
			}
			continue
		}
		event := forge.PushEvent{Ref: prefix + ref.Name, After: ref.SHA, Repo: forge.Repository{ProviderID: repo.ProviderID, FullName: repo.ProviderID}}
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
		if err := s.handlePushWebhookEvent(request, repo.Provider, event); err != nil {
			return false, err
		}
		changed = true
	}
	for _, ref := range refs {
		if ref.RefType != store.RefTypeBranch && ref.RefType != store.RefTypeTag || ref.LatestCommitSHA == nil {
			continue
		}
		if seen[string(ref.RefType)+":"+ref.Name] {
			continue
		}
		if ref.RefType == store.RefTypeTag {
			release, err := s.queries.GetReleaseByRepoVersion(ctx, repo.ID, ref.Name)
			if err != nil {
				return false, err
			}
			if release != nil {
				if err := s.removeDerivedRelease(ctx, repo, release, "poll_tag_absent"); err != nil {
					return false, err
				}
			}
		}
		if err := s.queries.RetireObservedRef(ctx, ref.ID); err != nil {
			return false, err
		}
		changed = true
	}
	for _, observedRef := range observed {
		if !observedRef.Tag {
			continue
		}
		ref, err := s.queries.GetRefByRepoAndName(ctx, repo.ID, observedRef.Name, store.RefTypeTag)
		if err != nil {
			return false, err
		}
		if ref == nil {
			continue
		}
		snapshot, err := s.queries.GetSnapshotByRefCommit(ctx, ref.ID, observedRef.SHA)
		if err != nil {
			return false, err
		}
		if snapshot != nil && (snapshot.Status == store.SnapshotStatusComplete || snapshot.Status == store.SnapshotStatusActive) {
			if err := s.reconcileReleaseSnapshot(ctx, snapshot.ID); err != nil {
				return false, err
			}
		}
	}
	return changed, nil
}

func (s *Server) applyObservedReleases(ctx context.Context, repo *store.Repository, previous, current []forge.ReleaseObservation) error {
	seen := map[string]bool{}
	for _, release := range current {
		if release.ID == "" || strings.TrimSpace(release.Event.TagName) == "" {
			return errors.New("release observation omitted identity or tag")
		}
		seen[release.Event.TagName] = true
		same := false
		for _, old := range previous {
			if reflect.DeepEqual(old, release) {
				same = true
				break
			}
		}
		if same {
			continue
		}
		event := release.Event
		event.Repo = forge.Repository{ProviderID: repo.ProviderID, FullName: repo.ProviderID}
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
		if err := s.handleReleaseWebhookEvent(request, repo.Provider, event); err != nil {
			return err
		}
	}
	all := []store.Release{}
	for offset := 0; ; {
		releases, total, err := s.queries.ListReleasesByRepo(ctx, repo.ID, 200, offset)
		if err != nil {
			return err
		}
		all = append(all, releases...)
		offset += len(releases)
		if offset >= total {
			break
		}
		if len(releases) == 0 || offset >= 10000 {
			return errors.New("release listing incomplete or exceeds 10000 rows")
		}
	}
	for i := range all {
		if all[i].Source == store.ReleaseSourceForge && !seen[all[i].Version] {
			if err := s.removeDerivedRelease(ctx, repo, &all[i], "poll_release_absent"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) clearForgeGatePending(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `UPDATE forge_reconciliation SET state=jsonb_set(state,'{gate_pending}','false') WHERE id=$1`, id)
	return err
}

// @Summary      Forge event delivery status
// @Description  Delivery mode and durable reconciliation freshness/errors per scope. Instance administrators only.
// @Tags         instance
// @Produce      json
// @Success      200 {object} api.Response{data=[]forgeDeliveryStatus}
// @Failure      401 {object} api.Response
// @Failure      403 {object} api.Response
// @Failure      500 {object} api.Response
// @Security     BearerAuth
// @Router       /instance/forges/events [get]
func (s *Server) handleForgeDeliveryStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireInstanceAdmin(w, r) {
		return
	}
	jobs, err := s.queries.ListForgeReconciliation(r.Context())
	if err != nil {
		s.log.Error().Err(err).Msg("read forge reconciliation status")
		api.JSONError(w, 500, "failed to read forge reconciliation status")
		return
	}
	result := []forgeDeliveryStatus{}
	for _, fc := range s.cfg.Forges {
		row := forgeDeliveryStatus{Provider: fc.ID, Mode: fc.DeliveryMode(), Scopes: []forgeDeliveryScope{}}
		for _, job := range jobs {
			if job.Provider == fc.ID {
				var checkpoint forgeCheckpoint
				if err := json.Unmarshal(job.State, &checkpoint); err != nil {
					s.log.Error().Err(err).Msg("decode forge status checkpoint")
					api.JSONError(w, 500, "invalid forge reconciliation checkpoint")
					return
				}
				row.Scopes = append(row.Scopes, forgeDeliveryScope{ForgeReconciliation: job, Note: checkpoint.Note, GatePending: checkpoint.GatePending})
			}
		}
		result = append(result, row)
	}
	api.JSON(w, 200, result)
}

type forgeDeliveryScope struct {
	store.ForgeReconciliation
	Note        string `json:"note,omitempty"`
	GatePending bool   `json:"gate_pending"`
}
type forgeDeliveryStatus struct {
	Provider string               `json:"provider"`
	Mode     string               `json:"mode"`
	Scopes   []forgeDeliveryScope `json:"scopes"`
}

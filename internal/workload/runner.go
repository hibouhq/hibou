package workload

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Identity struct{ Attempt, JobUID, PodUID string }
type Request struct {
	ID, Fence, Class string
	Input            []byte
	Handler          http.Handler
	// OnIdentity persists resource UIDs with the durable fenced attempt before
	// input/output or delegated operations are accepted. It must reject lost
	// claims. It is called for the Job, every authenticated live-Pod request and
	// final result acceptance; persistence must therefore be idempotent.
	OnIdentity func(context.Context, Identity) error
}
type Result struct {
	Output                  []byte
	Attempt, JobUID, PodUID string
}
type Runner struct {
	config Config
	client *Client
	broker *Broker
	mu     sync.Mutex
	active map[string]bool
}

func NewRunner(config Config, c *Client, b *Broker) (*Runner, error) {
	cfg, err := config.normalized()
	if err != nil {
		return nil, err
	}
	if c == nil || b == nil {
		return nil, errors.New("workload requires Kubernetes client and broker")
	}
	return &Runner{config: cfg, client: c, broker: b, active: make(map[string]bool)}, nil
}

// Ready checks the explicit supported version matrix and asks admission to
// validate the exact Job template (without creating a resource). Runtime/node
// user namespace support remains a required operator qualification.
func (r *Runner) Ready(ctx context.Context) error {
	if err := r.client.version(ctx); err != nil {
		return err
	}
	var response Job
	if err := r.client.request(ctx, "POST", r.client.jobs(r.config.Namespace)+"?dryRun=All&fieldValidation=Strict", r.config.job(randomID(), randomToken(), "preflight"), &response); err != nil {
		return err
	}
	p := response.Spec.Template.Spec
	if !p.hostUsersPresent || p.HostUsers || p.RuntimeClassName != r.config.RuntimeClass || p.ServiceAccountName != r.config.ServiceAccount || p.ActiveDeadlineSeconds != int64(r.config.Deadline.Seconds()) || !r.config.approvedPullSecrets(p) {
		return errors.New("admission did not preserve required user namespace/runtime/identity fields")
	}
	return nil
}
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func (r *Runner) Run(ctx context.Context, req Request) (result Result, err error) {
	if req.Class != ClassRemediation || !boundedString(req.ID, 256) || !boundedString(req.Fence, 256) || req.OnIdentity == nil {
		return result, errors.New("remediation class, bounded ID/fence and durable identity callback required")
	}
	if int64(len(req.Input)) > r.config.MaxInputBytes {
		return result, errors.New("workload input exceeds limit")
	}
	// A new fence revokes the old capability; same-process concurrent attempts
	// for one durable intent must be reconciled by its caller rather than raced.
	r.mu.Lock()
	if r.active[req.ID] {
		r.mu.Unlock()
		return result, errors.New("workload intent already active")
	}
	if len(r.active) >= 1 {
		r.mu.Unlock()
		return result, errors.New("controller attempt capacity reached")
	}
	r.active[req.ID] = true
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.active, req.ID); r.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(ctx, r.config.Deadline)
	defer cancel()
	result.Attempt = randomID()
	a := &attempt{token: randomToken(), fence: req.Fence, input: append([]byte(nil), req.Input...), handler: req.Handler, maxInput: r.config.MaxInputBytes, maxOutput: r.config.MaxOutputBytes, sem: make(chan struct{}, 2)}
	a.ctx, a.cancel = context.WithCancel(ctx)
	job := r.config.job(result.Attempt, a.token, req.Fence)
	var created Job
	err = r.client.request(ctx, "POST", r.client.jobs(r.config.Namespace)+"?fieldValidation=Strict", job, &created)
	if err == nil && (created.Metadata.UID == "" || created.Metadata.Name != job.Metadata.Name) {
		err = errors.New("invalid Job identity returned by Kubernetes")
	}
	if err != nil {
		// A lost CREATE response may still have created the Job. Reconcile only
		// the unguessable name plus this attempt's owner/fence before deleting.
		reconcile, stop := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer stop()
		var orphan Job
		if getErr := r.client.request(reconcile, "GET", r.client.jobs(r.config.Namespace)+"/"+job.Metadata.Name, nil, &orphan); getErr == nil && orphan.Metadata.UID != "" && r.owned(orphan, orphan.Metadata.UID, result.Attempt, req.Fence) {
			result.JobUID = orphan.Metadata.UID
			err = errors.Join(err, r.client.delete(reconcile, r.config.Namespace, job.Metadata.Name, orphan.Metadata.UID))
		}
		return result, err
	}
	result.JobUID = created.Metadata.UID
	a.jobUID = result.JobUID
	defer func() {
		a.mu.Lock()
		result.PodUID = a.podUID
		a.mu.Unlock()
		r.broker.revoke(result.Attempt)
		// Cleanup is independent of cancellation but strictly bounded.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		err = errors.Join(err, r.client.delete(cleanup, r.config.Namespace, job.Metadata.Name, result.JobUID))
	}()
	if err = req.OnIdentity(ctx, Identity{Attempt: result.Attempt, JobUID: result.JobUID}); err != nil {
		return result, err
	}
	var identityMu sync.Mutex
	a.validate = func(callCtx context.Context, podUID string) error {
		identityMu.Lock()
		defer identityMu.Unlock()
		if !boundedString(podUID, 128) || ctx.Err() != nil {
			return errors.New("expired workload")
		}
		pod, err := r.livePod(callCtx, job.Metadata.Name, result.JobUID, podUID, result.Attempt, req.Fence)
		if err != nil {
			return err
		}
		if a.podUID != "" && a.podUID != pod.Metadata.UID {
			return errors.New("workload Pod replaced")
		}
		if err := req.OnIdentity(callCtx, Identity{result.Attempt, result.JobUID, pod.Metadata.UID}); err != nil {
			a.cancel()
			return err
		}
		if a.podUID == "" {
			a.mu.Lock()
			a.podUID = pod.Metadata.UID
			a.mu.Unlock()
		}
		return nil
	}
	r.broker.add(result.Attempt, a)
	ticker := time.NewTicker(r.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return result, errors.Join(errors.New("workload deadline exceeded, including Pending/runtime/user-namespace failures; no fallback"), ctx.Err())
			}
			return result, ctx.Err()
		case <-a.ctx.Done():
			return result, errors.New("workload capability revoked")
		case <-ticker.C:
		}
		var current Job
		if err = r.client.request(ctx, "GET", r.client.jobs(r.config.Namespace)+"/"+job.Metadata.Name, nil, &current); err != nil {
			return result, err
		}
		if !r.owned(current, result.JobUID, result.Attempt, req.Fence) {
			return result, errors.New("Job identity or fence changed")
		}
		if current.Status.Failed > 0 {
			return result, errors.New("workload Job failed")
		}
		for _, condition := range current.Status.Conditions {
			if condition.Type == "Failed" && condition.Status == "True" {
				return result, errors.New("workload deadline or execution failure")
			}
		}
		if current.Status.Succeeded > 0 {
			a.mu.Lock()
			podUID := a.podUID
			submitted := a.submitted
			data := append([]byte(nil), a.output...)
			a.mu.Unlock()
			if !submitted || podUID == "" {
				return result, errors.New("successful Job did not submit authenticated output")
			}
			if err = a.validate(ctx, podUID); err != nil {
				return result, err
			}
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			result.PodUID = podUID
			result.Output = data
			return result, nil
		}
	}
}
func (r *Runner) owned(j Job, uid, attempt, fence string) bool {
	return j.Metadata.UID == uid && j.Metadata.DeletionTimestamp == nil &&
		j.Metadata.Labels[ownerLabel] == r.config.owner() && j.Metadata.Labels[attemptLabel] == attempt &&
		j.Metadata.Labels[fenceLabel] == hash(fence) && j.Metadata.Labels[classLabel] == ClassRemediation &&
		j.Spec.Template.Spec.ServiceAccountName == r.config.ServiceAccount &&
		j.Spec.Template.Spec.RuntimeClassName == r.config.RuntimeClass
}
func (r *Runner) livePod(ctx context.Context, name, jobUID, podUID, attempt, fence string) (Pod, error) {
	var j Job
	if err := r.client.request(ctx, "GET", r.client.jobs(r.config.Namespace)+"/"+name, nil, &j); err != nil {
		return Pod{}, err
	}
	if !r.owned(j, jobUID, attempt, fence) {
		return Pod{}, errors.New("Job no longer owns attempt")
	}
	if j.Status.Failed > 0 {
		return Pod{}, errors.New("Job has failed")
	}
	for _, condition := range j.Status.Conditions {
		if condition.Type == "Failed" && condition.Status == "True" {
			return Pod{}, errors.New("Job has failed")
		}
	}
	var list struct {
		Items    []Pod `json:"items"`
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
	}
	query := "?limit=3&labelSelector=" + url.QueryEscape("batch.kubernetes.io/job-name="+name)
	if err := r.client.request(ctx, "GET", r.client.pods(r.config.Namespace)+query, nil, &list); err != nil {
		return Pod{}, err
	}
	if len(list.Items) != 1 || list.Metadata.Continue != "" {
		return Pod{}, errors.New("expected exactly one workload Pod")
	}
	p := list.Items[0]
	if p.Metadata.UID != podUID || p.Metadata.Name == "" {
		return Pod{}, errors.New("Pod UID mismatch")
	}
	// Read the Pod by immutable owner and check the returned UID again, so a
	// forged label or a name replacement cannot authorize broker operations.
	if err := r.client.request(ctx, "GET", r.client.pods(r.config.Namespace)+"/"+url.PathEscape(p.Metadata.Name), nil, &p); err != nil {
		return Pod{}, err
	}
	if p.Metadata.UID != podUID || p.Metadata.DeletionTimestamp != nil || p.Spec.ServiceAccountName != r.config.ServiceAccount || p.Spec.RuntimeClassName != r.config.RuntimeClass || !p.Spec.hostUsersPresent || p.Spec.HostUsers ||
		len(p.Spec.Containers) != 1 || p.Spec.Containers[0].Image != r.config.Image || p.Spec.ActiveDeadlineSeconds != int64(r.config.Deadline.Seconds()) || !r.config.approvedPullSecrets(p.Spec) {
		return Pod{}, errors.New("invalid live Pod identity")
	}
	if p.Status.Phase != "Running" && p.Status.Phase != "Succeeded" {
		return Pod{}, errors.New("Pod is not active")
	}
	if len(p.Metadata.OwnerReferences) != 1 {
		return Pod{}, errors.New("invalid Pod owner")
	}
	o := p.Metadata.OwnerReferences[0]
	if o.APIVersion != "batch/v1" || o.Kind != "Job" || o.UID != jobUID || o.Name != name || !o.Controller {
		return Pod{}, errors.New("Pod is not owned by Job")
	}
	return p, nil
}

// Cleanup reconciles only this release's owned Jobs whose server creation time
// plus enforced active deadline and a clock-skew grace have expired. Fresh Jobs
// may belong to another live controller and must survive startup reconciliation.
// Pagination/size errors fail closed, never expand deletion scope.
func (r *Runner) Cleanup(ctx context.Context) error {
	var list struct {
		Items    []Job `json:"items"`
		Metadata struct {
			Continue string `json:"continue"`
		} `json:"metadata"`
	}
	path := r.client.jobs(r.config.Namespace) + "?limit=100&labelSelector=" + url.QueryEscape(ownerLabel+"="+r.config.owner())
	if err := r.client.request(ctx, "GET", path, nil, &list); err != nil {
		return err
	}
	if list.Metadata.Continue != "" {
		return errors.New("orphan cleanup exceeds bounded page")
	}
	for _, j := range list.Items {
		if j.Metadata.Labels[ownerLabel] != r.config.owner() || j.Metadata.Labels[classLabel] != ClassRemediation ||
			j.Spec.Template.Spec.ServiceAccountName != r.config.ServiceAccount || j.Spec.Template.Spec.RuntimeClassName != r.config.RuntimeClass ||
			j.Metadata.Name != "hibou-"+j.Metadata.Labels[attemptLabel] || j.Metadata.UID == "" {
			return errors.New("unrecognized owned orphan; operator reconciliation required")
		}
		if j.Metadata.CreationTimestamp == nil || j.Metadata.CreationTimestamp.IsZero() || j.Spec.ActiveDeadlineSeconds < 1 || j.Spec.ActiveDeadlineSeconds > 1800 ||
			time.Now().Before(j.Metadata.CreationTimestamp.Add(time.Duration(j.Spec.ActiveDeadlineSeconds)*time.Second+30*time.Second)) {
			continue
		}
		if err := r.client.delete(ctx, r.config.Namespace, j.Metadata.Name, j.Metadata.UID); err != nil {
			return err
		}
	}
	return nil
}

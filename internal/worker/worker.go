// Package worker provides the lease + heartbeat machinery for durable
// background work, so adding a new job type is cheaper than writing a bare
// goroutine.
//
// This exists because the wrong pattern was previously the easy one: an
// unclaimed `go func(){…}` (see the advisory-scan enqueue path) loses its work
// when the pod is evicted mid-run and offers no cross-replica coordination.
// Anything durable should claim a lease here instead.
//
// The contract mirrors the snapshot artifact processor, which is the reference
// implementation: claim atomically, renew while work is in flight, and abandon
// immediately if ownership is lost so another replica can safely retry.
package worker

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrClaimLost is returned through Run's context cause when a heartbeat
// discovers the lease is no longer held by this worker. Callers must abandon
// their work rather than finalizing it: another replica now owns the job.
var ErrClaimLost = errors.New("worker: claim lost")

// Lease renews a claim and reports whether this worker still owns it.
// Implementations are one UPDATE guarded by the owner id.
type Lease interface {
	// Renew extends the claim to expiresAt. It returns false when the claim is
	// no longer owned by this worker.
	Renew(ctx context.Context, expiresAt time.Time) (bool, error)
}

// LeaseFunc adapts a plain function to Lease.
type LeaseFunc func(ctx context.Context, expiresAt time.Time) (bool, error)

func (f LeaseFunc) Renew(ctx context.Context, expiresAt time.Time) (bool, error) {
	return f(ctx, expiresAt)
}

// Config bounds a claim's lifetime. HeartbeatInterval must be comfortably
// shorter than LeaseDuration so a single slow renewal doesn't drop the claim.
type Config struct {
	LeaseDuration     time.Duration
	HeartbeatInterval time.Duration
}

// Run executes fn with a heartbeat renewing the lease underneath it.
//
// The context passed to fn is cancelled as soon as the lease is lost, with
// ErrClaimLost as its cause, so long-running work (a clone, a scan) stops
// promptly instead of racing the new owner. Run returns fn's error, or a
// wrapped ErrClaimLost when ownership was lost before fn finished.
func Run(ctx context.Context, lease Lease, cfg Config, fn func(ctx context.Context) error) error {
	if lease == nil || cfg.HeartbeatInterval <= 0 || cfg.LeaseDuration <= 0 {
		// No renewal configured: run directly rather than silently pretending
		// the claim is being held.
		return fn(ctx)
	}

	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		heartbeat(runCtx, cancel, lease, cfg)
	}()

	err := fn(runCtx)

	cancel(nil)
	<-done

	// A lost claim outranks fn's own error: the work must not be finalized.
	if cause := context.Cause(runCtx); cause != nil && errors.Is(cause, ErrClaimLost) {
		return fmt.Errorf("%w", ErrClaimLost)
	}
	return err
}

func heartbeat(ctx context.Context, cancel context.CancelCauseFunc, lease Lease, cfg Config) {
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			owned, err := lease.Renew(ctx, time.Now().Add(cfg.LeaseDuration))
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				cancel(fmt.Errorf("renew claim: %w", err))
				return
			}
			if !owned {
				cancel(ErrClaimLost)
				return
			}
		}
	}
}

// IsClaimLost reports whether an error means another worker took the job. Used
// by callers to decide "abandon quietly" versus "record a failure".
func IsClaimLost(err error) bool {
	return errors.Is(err, ErrClaimLost)
}

package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func fastConfig() Config {
	return Config{LeaseDuration: 200 * time.Millisecond, HeartbeatInterval: 5 * time.Millisecond}
}

func TestRunRenewsWhileWorking(t *testing.T) {
	var renewals atomic.Int32
	lease := LeaseFunc(func(context.Context, time.Time) (bool, error) {
		renewals.Add(1)
		return true, nil
	})

	err := Run(context.Background(), lease, fastConfig(), func(ctx context.Context) error {
		time.Sleep(40 * time.Millisecond)
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if renewals.Load() < 2 {
		t.Fatalf("expected repeated renewals, got %d", renewals.Load())
	}
}

// The point of the helper: losing the lease must cancel in-flight work so the
// new owner isn't racing us, and must surface as ErrClaimLost so the caller
// abandons instead of finalizing.
func TestRunAbortsWhenClaimLost(t *testing.T) {
	lease := LeaseFunc(func(context.Context, time.Time) (bool, error) {
		return false, nil
	})

	observed := make(chan error, 1)
	err := Run(context.Background(), lease, fastConfig(), func(ctx context.Context) error {
		<-ctx.Done()
		observed <- context.Cause(ctx)
		return ctx.Err()
	})

	if !IsClaimLost(err) {
		t.Fatalf("Run err = %v, want ErrClaimLost", err)
	}
	if cause := <-observed; !errors.Is(cause, ErrClaimLost) {
		t.Fatalf("work saw cause %v, want ErrClaimLost", cause)
	}
}

func TestRunClaimLostOutranksWorkError(t *testing.T) {
	lease := LeaseFunc(func(context.Context, time.Time) (bool, error) { return false, nil })
	boom := errors.New("work failed")

	err := Run(context.Background(), lease, fastConfig(), func(ctx context.Context) error {
		<-ctx.Done()
		return boom
	})
	// Recording a failure against a job we no longer own would clobber the new
	// owner's run, so the lost claim has to win.
	if !IsClaimLost(err) {
		t.Fatalf("err = %v, want ErrClaimLost to outrank the work error", err)
	}
}

func TestRunSurfacesRenewError(t *testing.T) {
	lease := LeaseFunc(func(context.Context, time.Time) (bool, error) {
		return false, errors.New("db down")
	})
	err := Run(context.Background(), lease, fastConfig(), func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	// A renewal error is not a lost claim — it must not be mistaken for one.
	if IsClaimLost(err) {
		t.Fatalf("renew error reported as claim lost: %v", err)
	}
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestRunWithoutHeartbeatRunsDirectly(t *testing.T) {
	called := false
	err := Run(context.Background(), LeaseFunc(func(context.Context, time.Time) (bool, error) {
		t.Fatal("lease must not be renewed when no interval is configured")
		return false, nil
	}), Config{}, func(context.Context) error {
		called = true
		return nil
	})
	if err != nil || !called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestRunPropagatesParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	lease := LeaseFunc(func(context.Context, time.Time) (bool, error) { return true, nil })

	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	err := Run(ctx, lease, fastConfig(), func(runCtx context.Context) error {
		<-runCtx.Done()
		return runCtx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

package server

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// cooldownGate admits one run per key at a time and refuses a new run until
// the cooldown after the previous one has passed. The zero value is ready.
type cooldownGate struct {
	mu       sync.Mutex
	running  map[uuid.UUID]struct{}
	finished map[uuid.UUID]time.Time
}

// tryStart reports whether a run for key may start now; when it may not, the
// duration says how long to wait (zero while one is still running).
func (g *cooldownGate) tryStart(key uuid.UUID, cooldown time.Duration, now time.Time) (bool, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.running == nil {
		g.running = make(map[uuid.UUID]struct{})
		g.finished = make(map[uuid.UUID]time.Time)
	}
	if _, busy := g.running[key]; busy {
		return false, 0
	}
	if last, ok := g.finished[key]; ok {
		if wait := last.Add(cooldown).Sub(now); wait > 0 {
			return false, wait
		}
		delete(g.finished, key)
	}
	g.running[key] = struct{}{}
	return true, 0
}

// finish ends the run for key; a zero ranAt records no cooldown (the run
// did no work worth spacing out).
func (g *cooldownGate) finish(key uuid.UUID, ranAt time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.running, key)
	if g.finished != nil && !ranAt.IsZero() {
		g.finished[key] = ranAt
	}
}

// coalescingRunner runs at most one job per key; a request arriving while one
// runs marks the key dirty and the running job goes round once more, so the
// last request is always reflected without stacking goroutines. The zero
// value is ready.
type coalescingRunner struct {
	mu    sync.Mutex
	state map[uuid.UUID]bool // key → rerun requested
}

// run starts fn in a goroutine unless one is already running for key.
func (c *coalescingRunner) run(key uuid.UUID, fn func()) {
	c.mu.Lock()
	if c.state == nil {
		c.state = make(map[uuid.UUID]bool)
	}
	if _, running := c.state[key]; running {
		c.state[key] = true
		c.mu.Unlock()
		return
	}
	c.state[key] = false
	c.mu.Unlock()

	go func() {
		for {
			fn()
			c.mu.Lock()
			if !c.state[key] {
				delete(c.state, key)
				c.mu.Unlock()
				return
			}
			c.state[key] = false
			c.mu.Unlock()
		}
	}()
}

// acquireUploadWorker reserves one of upload.processing_concurrency slots for
// a background coverage/test parse, waiting while ctx allows. The caller
// hands releaseUploadWorker to the goroutine. Without a pool (a Server built
// without New) it always succeeds.
func (s *Server) acquireUploadWorker(ctx context.Context) bool {
	if s.uploadWorkSlots == nil {
		return true
	}
	select {
	case s.uploadWorkSlots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Server) releaseUploadWorker() {
	if s.uploadWorkSlots == nil {
		return
	}
	<-s.uploadWorkSlots
}

// inFlightKey is one counter an operation holds while it runs, with the most
// it may hold at once.
type inFlightKey struct {
	key   string
	limit int
}

// keyedInFlight counts operations in flight per key (principal, org). An
// operation takes all its keys or none. The zero value is ready.
type keyedInFlight struct {
	mu      sync.Mutex
	counts  map[string]int
	changed chan struct{} // closed and replaced on every release
}

// acquire waits until every key is under its limit and takes them, or gives
// up when expired fires (acquired=false) or ctx ends (cancelled=true).
func (k *keyedInFlight) acquire(ctx context.Context, expired <-chan time.Time, keys []inFlightKey) (acquired, cancelled bool) {
	for {
		k.mu.Lock()
		if k.counts == nil {
			k.counts = make(map[string]int)
		}
		if k.changed == nil {
			k.changed = make(chan struct{})
		}
		free := true
		for _, entry := range keys {
			if entry.limit > 0 && k.counts[entry.key] >= entry.limit {
				free = false
				break
			}
		}
		if free {
			for _, entry := range keys {
				k.counts[entry.key]++
			}
			k.mu.Unlock()
			return true, false
		}
		changed := k.changed
		k.mu.Unlock()
		select {
		case <-changed:
		case <-expired:
			return false, false
		case <-ctx.Done():
			return false, true
		}
	}
}

func (k *keyedInFlight) release(keys []inFlightKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, entry := range keys {
		if k.counts[entry.key] <= 1 {
			delete(k.counts, entry.key)
		} else {
			k.counts[entry.key]--
		}
	}
	if k.changed != nil {
		close(k.changed)
	}
	k.changed = make(chan struct{})
}

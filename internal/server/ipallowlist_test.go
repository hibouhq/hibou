package server

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

type scriptedIPSource struct {
	mu    sync.Mutex
	cidrs []string
}

func (s *scriptedIPSource) Name() string { return "scripted" }

func (s *scriptedIPSource) FetchCIDRs(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cidrs...), nil
}

func (s *scriptedIPSource) set(cidrs ...string) {
	s.mu.Lock()
	s.cidrs = cidrs
	s.mu.Unlock()
}

// Q8: a refresh that changes the forge's webhook-source ranges is reported to
// the change hook (and so to the audit log); the initial load and no-op
// refreshes are not.
func TestForgeIPAllowlistReportsRangeChanges(t *testing.T) {
	source := &scriptedIPSource{cidrs: []string{"192.0.2.0/24", "198.51.100.0/24"}}
	allowlist := newForgeIPAllowlist(context.Background(), zerolog.New(io.Discard), source, nil)
	defer allowlist.cancel()

	var calls [][2][]string
	allowlist.SetChangeHook(func(added, removed []string) {
		calls = append(calls, [2][]string{added, removed})
	})

	allowlist.refresh() // unchanged
	if len(calls) != 0 {
		t.Fatalf("no-op refresh reported %v", calls)
	}

	source.set("198.51.100.0/24", "203.0.113.0/24")
	allowlist.refresh()
	if len(calls) != 1 {
		t.Fatalf("hook calls = %d, want 1", len(calls))
	}
	if got := strings.Join(calls[0][0], ","); got != "203.0.113.0/24" {
		t.Fatalf("added = %s", got)
	}
	if got := strings.Join(calls[0][1], ","); got != "192.0.2.0/24" {
		t.Fatalf("removed = %s", got)
	}
}

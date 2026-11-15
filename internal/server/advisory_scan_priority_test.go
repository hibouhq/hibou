package server

import (
	"testing"

	"github.com/hibouhq/hibou/internal/store"
)

func TestAdvisoryScanPriority(t *testing.T) {
	open, closed, merged := "open", "closed", "merged"
	for _, tc := range []struct {
		name     string
		ref      store.Ref
		priority int
		scan     bool
	}{
		{"default branch", store.Ref{Name: "main", RefType: store.RefTypeBranch}, advisoryPriorityDefaultBranch, true},
		{"qualified default", store.Ref{Name: "refs/heads/main", RefType: store.RefTypeBranch}, advisoryPriorityDefaultBranch, true},
		{"open PR", store.Ref{Name: "refs/pull/7", RefType: store.RefTypePullRequest, PrState: &open}, advisoryPriorityOpenPR, true},
		{"unknown PR", store.Ref{Name: "refs/pull/9", RefType: store.RefTypePullRequest}, advisoryPriorityOpenPR, true},
		{"closed PR", store.Ref{RefType: store.RefTypePullRequest, PrState: &closed}, 0, false},
		{"merged PR", store.Ref{RefType: store.RefTypePullRequest, PrState: &merged}, 0, false},
		{"other branch", store.Ref{Name: "feature", RefType: store.RefTypeBranch}, advisoryPriorityOtherRef, true},
		{"tag named main", store.Ref{Name: "main", RefType: store.RefTypeTag}, advisoryPriorityOtherRef, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priority, scan := advisoryScanPriority(&tc.ref, "main")
			if scan != tc.scan || priority != tc.priority {
				t.Fatalf("got (%d, %v), want (%d, %v)", priority, scan, tc.priority, tc.scan)
			}
		})
	}
	if advisoryPriorityDefaultBranch >= advisoryPriorityOpenPR || advisoryPriorityOpenPR >= advisoryPriorityReleasePinned || advisoryPriorityReleasePinned >= advisoryPriorityOtherRef {
		t.Fatal("unexpected advisory scan priority ordering")
	}
}

func TestActiveJobCountIncludesAllScanSlots(t *testing.T) {
	srv := &Server{
		activeArtifacts:    2,
		secretScanSlots:    make(chan struct{}, 2),
		advisoryScanSlots:  make(chan struct{}, 3),
		depExtractionSlots: make(chan struct{}, 2),
	}
	for _, slots := range []chan struct{}{srv.secretScanSlots, srv.advisoryScanSlots, srv.depExtractionSlots} {
		slots <- struct{}{}
	}
	if got := srv.activeJobCount(); got != 5 {
		t.Fatalf("active jobs=%d, want 5", got)
	}
	<-srv.advisoryScanSlots
	if got := srv.activeJobCount(); got != 4 {
		t.Fatalf("active jobs after scan=%d, want 4", got)
	}
	if got := (&Server{}).activeJobCount(); got != 0 {
		t.Fatalf("nil slots active jobs=%d", got)
	}
}

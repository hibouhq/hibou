package presence

import (
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
)

func sp(s string) *string { return &s }

func row(typ, scanner, fingerprint, file string) store.Vulnerability {
	return store.Vulnerability{Type: typ, ScannerName: scanner, Fingerprint: fingerprint, FilePath: sp(file), Status: "detected", Origin: "scanner", Presence: store.PresenceReported}
}

func completed(producer string) store.ProducerRun {
	return store.ProducerRun{Producer: producer, Outcome: store.ProducerOutcomeCompleted, Scope: store.ProducerScopeFull}
}

func carriedReasons(carries []Carry) map[string]string {
	out := map[string]string{}
	for _, carry := range carries {
		out[carry.Source.Fingerprint] = carry.Reason
	}
	return out
}

func TestPlanCarriesWhatWasNotRechecked(t *testing.T) {
	prevID := uuid.New()
	previous := Snapshot{ID: prevID, CommitSHA: "a1b2c3d", Rows: []store.Vulnerability{
		row("sast", "gosec", "still-there", "a.go"),
		row("sast", "gosec", "fixed", "b.go"),
		row("sast", "gosec", "timed-out", "big.go"),
		row("sast", "Opengrep OSS", "tool-missing", "c.go"),
		row("secret", "gitleaks", "secret", "config.yml"),
		row("dependency", "trivy", "dep", ""),
		row("sast", "gosec", "already-resolved", "d.go"),
		{Type: "manual", Fingerprint: "assertion", Status: "detected", Origin: "human"},
	}}
	previous.Rows[6].Status = "resolved"
	current := Snapshot{ID: uuid.New(), CommitSHA: "e4f5a6b",
		Rows: []store.Vulnerability{row("sast", "gosec", "still-there", "a.go")},
		Runs: []store.ProducerRun{
			{Producer: "gosec", Outcome: store.ProducerOutcomePartial, Scope: store.ProducerScopeFull,
				SkippedFiles: []store.SkippedFile{{Path: "./big.go", Reason: "timeout"}}},
			// Incremental secret scan: partial, no paths.
			{Producer: ProducerSecretScanning, Outcome: store.ProducerOutcomePartial, Scope: store.ProducerScopePartial, Detail: sp("incremental scan")},
			// Advisory scan still running.
			{Producer: ProducerSBOMMatching, Outcome: ""},
		},
	}

	carries, _ := Plan(previous, current, Options{})
	got := carriedReasons(carries)
	want := map[string]string{
		"timed-out":    "file_skipped:timeout",
		"tool-missing": ReasonProducerMissing,
		"secret":       ReasonPartialScope,
		"dep":          ReasonProducerPending,
		"assertion":    ReasonAssertion, // ADR-034 §4: carried until decided
	}
	if len(got) != len(want) {
		t.Fatalf("carried = %v, want %v", got, want)
	}
	for fingerprint, reason := range want {
		if got[fingerprint] != reason {
			t.Errorf("%s: reason %q, want %q", fingerprint, got[fingerprint], reason)
		}
	}
	for _, carry := range carries {
		if carry.LastSeenSnapshotID != prevID || carry.LastSeenCommit != "a1b2c3d" || carry.Presence != store.PresenceNotRechecked {
			t.Fatalf("carry = %+v", carry)
		}
	}
}

// A row carried again keeps pointing at where it was last really reported.
func TestPlanKeepsLastSeenAcrossCarries(t *testing.T) {
	origin := uuid.New()
	carried := row("sast", "gosec", "fp", "a.go")
	carried.Presence = store.PresenceNotRechecked
	carried.LastSeenSnapshotID = &origin
	carried.LastSeenCommit = sp("0ldc0mm")
	carries, _ := Plan(Snapshot{ID: uuid.New(), CommitSHA: "middle", Rows: []store.Vulnerability{carried}}, Snapshot{ID: uuid.New()}, Options{})
	if len(carries) != 1 || carries[0].LastSeenSnapshotID != origin || carries[0].LastSeenCommit != "0ldc0mm" {
		t.Fatalf("carries = %+v", carries)
	}
}

func TestCovered(t *testing.T) {
	partial := store.ProducerRun{Producer: "p", Outcome: store.ProducerOutcomePartial, Scope: store.ProducerScopePartial, ScopePaths: []string{"src/", "./pkg/x.go"}}
	cases := []struct {
		name   string
		runs   []store.ProducerRun
		file   string
		ok     bool
		reason string
	}{
		{"no run", nil, "a.go", false, ReasonProducerMissing},
		{"failed", []store.ProducerRun{{Outcome: store.ProducerOutcomeFailed}}, "a.go", false, ReasonProducerFailed},
		{"full completed", []store.ProducerRun{completed("p")}, "a.go", true, ""},
		{"partial in dir scope", []store.ProducerRun{partial}, "src/main.go", true, ""},
		{"partial in file scope", []store.ProducerRun{partial}, "pkg/x.go", true, ""},
		{"partial outside scope", []store.ProducerRun{partial}, "srcx/main.go", false, ReasonOutsideScope},
		{"pathless diagnostic", []store.ProducerRun{{Outcome: store.ProducerOutcomePartial, Scope: store.ProducerScopeFull, Detail: sp("rule failed to load")}}, "a.go", false, ReasonPartialRun},
		{"one of two artifacts covers", []store.ProducerRun{{Outcome: store.ProducerOutcomeFailed}, completed("p")}, "a.go", true, ""},
	}
	for _, tc := range cases {
		ok, reason := Covered(tc.runs, tc.file)
		if ok != tc.ok || reason != tc.reason {
			t.Errorf("%s: got (%v, %q), want (%v, %q)", tc.name, ok, reason, tc.ok, tc.reason)
		}
	}
}

func changes(byPath map[string]Change) ChangeChecker {
	return func(_, path string) Change {
		if change, ok := byPath[path]; ok {
			return change
		}
		return Change{Known: true}
	}
}

func resolutionReasons(resolutions []Resolution) map[string]string {
	out := map[string]string{}
	for _, resolution := range resolutions {
		out[resolution.Source.Fingerprint] = resolution.Reason
	}
	return out
}

// Covered and absent: resolved on evidence, otherwise unconfirmed (ADR-034 §3).
func TestPlanResolutionRules(t *testing.T) {
	taint := row("sast", "opengrep oss", "taint-other-change", "Executor.java")
	taint.Metadata = []byte(`{"trace_files":["Controller.java","Executor.java"]}`)
	taintFixed := row("sast", "opengrep oss", "taint-source-change", "Executor2.java")
	taintFixed.Metadata = []byte(`{"trace_files":["Controller2.java","Executor2.java"]}`)
	aged := row("sast", "gosec", "aged", "same.go")
	aged.Presence = store.PresenceUnconfirmed
	aged.ConsecutiveAbsences = 2
	agedCommit := "c0ffee"
	aged.LastSeenCommit = &agedCommit
	previous := Snapshot{ID: uuid.New(), CommitSHA: "base", Rows: []store.Vulnerability{
		row("sast", "gosec", "edited", "edited.go"),
		row("sast", "gosec", "untouched", "same.go"),
		row("sast", "gosec", "deleted-file", "gone.go"),
		aged,
		taint,
		taintFixed,
		row("sast", "agent:7", "agent-finding", "x.go"),
		row("sast", "noisy", "noisy", "n.go"),
	}, Runs: []store.ProducerRun{
		{Producer: "gosec", Outcome: store.ProducerOutcomeCompleted, Scope: store.ProducerScopeFull, Version: sp("2.21.0")},
	}}
	current := Snapshot{ID: uuid.New(), CommitSHA: "head", Runs: []store.ProducerRun{
		{Producer: "gosec", Outcome: store.ProducerOutcomeCompleted, Scope: store.ProducerScopeFull, Version: sp("2.21.0")},
		{Producer: "opengrep oss", Outcome: store.ProducerOutcomeCompleted, Scope: store.ProducerScopeFull},
		{Producer: "agent:7", Outcome: store.ProducerOutcomeCompleted, Scope: store.ProducerScopeFull},
		{Producer: "noisy", Outcome: store.ProducerOutcomeCompleted, Scope: store.ProducerScopeFull},
	}}
	opts := Options{
		Changed: changes(map[string]Change{
			"edited.go":        {Known: true, Changed: true},
			"gone.go":          {Known: true, Removed: true},
			"Controller2.java": {Known: true, Changed: true},
			"Main.java":        {Known: true, Changed: true},
		}),
		Policy: func(producer string) Policy {
			if producer == "noisy" {
				return Policy{Kind: PolicyConsecutiveAbsence, Threshold: 2}
			}
			return Policy{}
		},
	}
	carries, resolutions := Plan(previous, current, opts)

	wantResolved := map[string]string{
		"edited":              ResolvedFixed,
		"deleted-file":        ResolvedFileRemoved,
		"aged":                ResolvedNoLongerReported, // third unchanged covered scan
		"taint-source-change": ResolvedFixed,            // a trace file changed, not the sink
	}
	gotResolved := resolutionReasons(resolutions)
	if len(gotResolved) != len(wantResolved) {
		t.Fatalf("resolved = %v, want %v", gotResolved, wantResolved)
	}
	for fingerprint, reason := range wantResolved {
		if gotResolved[fingerprint] != reason {
			t.Errorf("%s resolved as %q, want %q", fingerprint, gotResolved[fingerprint], reason)
		}
	}
	wantCarried := map[string]string{
		"untouched":          ReasonUnchanged,
		"taint-other-change": ReasonUnchangedTrace,
		"agent-finding":      ReasonExplicitPolicy,
		"noisy":              ReasonAbsentCount,
	}
	got := carriedReasons(carries)
	if len(got) != len(wantCarried) {
		t.Fatalf("carried = %v, want %v", got, wantCarried)
	}
	for _, carry := range carries {
		if got[carry.Source.Fingerprint] != wantCarried[carry.Source.Fingerprint] || carry.Presence != store.PresenceUnconfirmed || carry.ConsecutiveAbsences != 1 {
			t.Errorf("carry %s = %+v", carry.Source.Fingerprint, carry)
		}
	}
}

func TestPlanProducerChangedAndPartialTaint(t *testing.T) {
	taint := row("sast", "opengrep oss", "taint", "Sink.java")
	taint.Metadata = []byte(`{"trace_files":["Source.java","Sink.java"]}`)
	previous := Snapshot{ID: uuid.New(), CommitSHA: "base",
		Rows: []store.Vulnerability{row("sast", "gosec", "renamed-rule", "a.go"), taint},
		Runs: []store.ProducerRun{{Producer: "gosec", Outcome: store.ProducerOutcomeCompleted, Scope: store.ProducerScopeFull, Version: sp("2.21.0")}},
	}
	current := Snapshot{ID: uuid.New(), CommitSHA: "head", Runs: []store.ProducerRun{
		{Producer: "gosec", Outcome: store.ProducerOutcomeCompleted, Scope: store.ProducerScopeFull, Version: sp("2.22.0")},
		// Partial run that saw the sink: not enough for a taint finding.
		{Producer: "opengrep oss", Outcome: store.ProducerOutcomePartial, Scope: store.ProducerScopePartial, ScopePaths: []string{"Sink.java"}},
	}}
	carries, resolutions := Plan(previous, current, Options{Changed: changes(map[string]Change{"a.go": {Known: true, Changed: true}})})
	if got := resolutionReasons(resolutions); got["renamed-rule"] != ResolvedProducerChanged || len(got) != 1 {
		t.Fatalf("resolutions = %v", got)
	}
	if got := carriedReasons(carries); got["taint"] != ReasonPartialScope || len(got) != 1 {
		t.Fatalf("carried = %v", got)
	}
}

func TestPlanAssertions(t *testing.T) {
	gone := store.Vulnerability{Type: "manual", Fingerprint: "file-deleted", FilePath: sp("old.go"), Status: "detected", Origin: "agent"}
	previous := Snapshot{ID: uuid.New(), CommitSHA: "base", Rows: []store.Vulnerability{
		{Type: "manual", Fingerprint: "open", Status: "detected", Origin: "human"},
		{Type: "manual", Fingerprint: "retracted", Status: "detected", Origin: "agent"},
		gone,
	}}
	carries, resolutions := Plan(previous, Snapshot{ID: uuid.New(), CommitSHA: "head"}, Options{
		ClosedAssertions: map[string]bool{"retracted": true},
		Changed:          changes(map[string]Change{"old.go": {Known: true, Removed: true}}),
	})
	if len(resolutions) != 0 {
		t.Fatalf("assertions are never resolved by absence: %+v", resolutions)
	}
	got := carriedReasons(carries)
	if len(got) != 2 || got["open"] != ReasonAssertion || got["file-deleted"] != ReasonLocationGone {
		t.Fatalf("carried = %v", got)
	}
}

// An unanswered change question (budget, forge error, truncated list) never
// resolves a finding; a forge that cannot compare at all lets coverage decide.
func TestPlanDeferredChangeStaysUnconfirmed(t *testing.T) {
	previous := Snapshot{ID: uuid.New(), CommitSHA: "base", Rows: []store.Vulnerability{
		row("sast", "gosec", "deferred", "a.go"),
	}}
	current := Snapshot{ID: uuid.New(), CommitSHA: "head", Runs: []store.ProducerRun{completed("gosec")}}
	carries, resolutions := Plan(previous, current, Options{Changed: func(string, string) Change { return Change{Deferred: true} }})
	if len(resolutions) != 0 || len(carries) != 1 || carries[0].Reason != ReasonChangeUnchecked {
		t.Fatalf("deferred = carries %+v resolutions %+v", carries, resolutions)
	}
	_, resolutions = Plan(previous, current, Options{Changed: func(string, string) Change { return Change{} }})
	if len(resolutions) != 1 || resolutions[0].Reason != ResolvedFixed {
		t.Fatalf("no compare support: coverage alone decides: %+v", resolutions)
	}
}

// A retired producer that does not run resolves its findings as retired; if
// it runs again, the usual rules apply.
func TestPlanRetiredProducer(t *testing.T) {
	previous := Snapshot{ID: uuid.New(), CommitSHA: "base", Rows: []store.Vulnerability{row("sast", "oldtool", "f", "a.go")}}
	retired := Options{Policy: func(string) Policy { return Policy{Kind: PolicyRetired} }}
	carries, resolutions := Plan(previous, Snapshot{ID: uuid.New(), CommitSHA: "head"}, retired)
	if len(carries) != 0 || len(resolutions) != 1 || resolutions[0].Reason != ResolvedProducerRetired {
		t.Fatalf("retired and absent: carries %+v resolutions %+v", carries, resolutions)
	}
	running := Snapshot{ID: uuid.New(), CommitSHA: "head", Runs: []store.ProducerRun{completed("oldtool")}}
	retired.Changed = func(string, string) Change { return Change{Known: true} }
	carries, resolutions = Plan(previous, running, retired)
	if len(resolutions) != 0 || len(carries) != 1 || carries[0].Reason != ReasonUnchanged {
		t.Fatalf("retired but running again: carries %+v resolutions %+v", carries, resolutions)
	}
}

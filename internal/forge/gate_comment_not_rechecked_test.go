package forge

import (
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestGateCommentListsNotRechecked(t *testing.T) {
	missing, skipped := "producer_missing", "file_skipped:timeout"
	result := &delta.DeltaResult{
		New:      []store.Vulnerability{},
		Resolved: []store.Vulnerability{{Type: "sast", ScannerName: "gosec"}},
		NotRechecked: []store.Vulnerability{
			{Type: "sast", ScannerName: "gosec", PresenceReason: &missing},
			{Type: "sast", ScannerName: "gosec", PresenceReason: &missing},
			{Type: "sast", ScannerName: "opengrep oss", PresenceReason: &skipped},
		},
		Unchanged: 4,
	}
	annotation := &gateContext{snapshot: dbgen.Snapshot{CommitSha: "abc"}}
	body := (&GatePublisher{}).buildGateCommentBody(annotation, &delta.GateResult{Passed: true}, result, gateStatus{state: "success"})

	for _, want := range []string{
		"| 0 | 1 | 3 | 4 |",
		"3 not re-checked — still counted, not fixed",
		"`gosec` — did not run on this build (2)",
		"`opengrep oss` — skipped the file (timeout) (1)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("comment missing %q:\n%s", want, body)
		}
	}
	if strings.Index(body, "`gosec`") > strings.Index(body, "`opengrep oss`") {
		t.Error("most frequent reason must come first")
	}
}

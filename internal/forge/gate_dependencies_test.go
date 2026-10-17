package forge

import (
	"strings"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/delta"
)

func TestDependenciesMarkdown(t *testing.T) {
	until := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	result := &delta.GateResult{Dependencies: &delta.DependencyDelta{
		Evaluated: true, Added: 2, Updated: 1, Removed: 1, Holds: 1, Denies: 1,
		Changes: []delta.DependencyChange{
			{Change: delta.DependencyAdded, Name: "fresh-thing", Version: "1.0.0", Decision: "hold", Until: &until, Reason: "in cooldown until 2026-10-24"},
			{Change: delta.DependencyAdded, Name: "evil-thing", Version: "0.0.1", Decision: "deny", Reason: "flagged as malicious"},
			{Change: delta.DependencyUpdated, Name: "express", PreviousVersion: "4.18.2", Version: "4.21.2", Decision: "allow", Exempt: "allowed: fixes CVE-2026-1234", Warnings: []string{"deprecated: use v5"}},
			{Change: delta.DependencyRemoved, Name: "left-pad", Version: "1.3.0"},
		},
	}}
	body := dependenciesMarkdown(result)
	for _, want := range []string{
		"**Dependencies:** 2 added, 1 updated, 1 removed · 1 in cooldown, 1 refused",
		"⏳ `fresh-thing` 1.0.0 (added) — in cooldown until 2026-10-24",
		"🚫 `evil-thing` 0.0.1 (added) — flagged as malicious",
		"✓ `express` 4.18.2 → 4.21.2 (updated) — allowed: fixes CVE-2026-1234 · ⚠ deprecated: use v5",
		"A cooldown ends on its own",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "left-pad") {
		t.Error("removed components are counted, not listed")
	}
	if got := dependenciesMarkdown(&delta.GateResult{Dependencies: &delta.DependencyDelta{Note: "no base inventory"}}); !strings.Contains(got, "no base inventory") {
		t.Errorf("unevaluated delta must show its note, got %q", got)
	}
	if got := dependenciesMarkdown(&delta.GateResult{}); got != "" {
		t.Errorf("no delta, no section, got %q", got)
	}
}

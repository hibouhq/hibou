package scanplan

import (
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/applicability"
	"github.com/hibouhq/hibou/internal/scancatalog"
)

func load(t *testing.T) *scancatalog.Catalog {
	t.Helper()
	catalog, err := scancatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func mixedInput(catalog *scancatalog.Catalog) Input {
	result := applicability.Detect([]string{"java/pom.xml", "java/src/main/java/App.java", "web/package.json", "web/src/index.js", "web/node_modules/x/y.js"}, false, catalog)
	return Input{
		CommitSHA: "abc", Runner: Runner{OS: "linux", Arch: "amd64"}, Applicability: result,
		DetectionRevision: applicability.Revision, CatalogRevision: catalog.Revision,
	}
}

func jobFor(plan Plan, scanner string) (Job, bool) {
	for _, job := range plan.Jobs {
		if job.ScannerID == scanner {
			return job, true
		}
	}
	return Job{}, false
}

func TestBuildPlan(t *testing.T) {
	catalog := load(t)
	plan := Build(mixedInput(catalog), catalog, scancatalog.DistributionConfig{})

	if plan.Mode != ModeBaseline || plan.Digest == "" {
		t.Fatalf("plan = %+v", plan)
	}
	if _, ok := jobFor(plan, "opengrep-interfile"); ok {
		t.Fatal("pre-releases are opt-in, not default")
	}
	opengrep, ok := jobFor(plan, "opengrep")
	if !ok || opengrep.Status != JobBlocked || !strings.Contains(opengrep.BlockedReason, "no approved ruleset") {
		t.Fatalf("opengrep must be blocked on its unreviewed ruleset: %+v", opengrep)
	}
	if opengrep.Artifact == nil || opengrep.Artifact.Source != "upstream" {
		t.Fatalf("the artifact still resolves: %+v", opengrep.Artifact)
	}
	spotbugs, ok := jobFor(plan, "spotbugs-findsecbugs")
	if !ok || spotbugs.Status != JobReady || spotbugs.Scope != "partial" || spotbugs.Targets[0] != "java" {
		t.Fatalf("spotbugs job = %+v", spotbugs)
	}
	if !contains(spotbugs.Prerequisites, "compiled-classes") || !contains(spotbugs.Exclusions, "web/node_modules") {
		t.Fatalf("spotbugs prerequisites/exclusions = %+v", spotbugs)
	}

	// Same inputs, same digest; the next plan is a full (not incremental) run.
	again := Build(mixedInput(catalog), catalog, scancatalog.DistributionConfig{})
	if again.Digest != plan.Digest {
		t.Fatal("plan digest must be reproducible")
	}
	next := mixedInput(catalog)
	next.Previous = &plan
	if p := Build(next, catalog, scancatalog.DistributionConfig{}); p.Mode != ModeFull || !strings.Contains(p.ModeReason, "incremental") {
		t.Fatalf("next plan mode = %s (%s)", p.Mode, p.ModeReason)
	}
}

func TestBuildPlanBlockers(t *testing.T) {
	catalog := load(t)
	input := mixedInput(catalog)
	input.Enabled = []string{"opengrep-interfile"}
	input.Runner = Runner{OS: "linux", Arch: "riscv64"}
	plan := Build(input, catalog, scancatalog.DistributionConfig{})
	if len(plan.Jobs) != 1 || plan.Jobs[0].Status != JobBlocked || !strings.Contains(plan.Jobs[0].BlockedReason, "linux/riscv64") {
		t.Fatalf("unsupported runner must be a named blocker: %+v", plan.Jobs)
	}
	mirror := Build(mixedInput(catalog), catalog, scancatalog.DistributionConfig{Mode: scancatalog.ModeMirror, MirrorBaseURL: "https://m.example.test"})
	spotbugs, _ := jobFor(mirror, "spotbugs-findsecbugs")
	if spotbugs.Status != JobBlocked || !strings.Contains(spotbugs.BlockedReason, "unavailable") {
		t.Fatalf("mirror mode without a Maven mirror blocks the Maven job: %+v", spotbugs)
	}
}

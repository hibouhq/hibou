package scanpolicy

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/applicability"
	"github.com/hibouhq/hibou/internal/scancatalog"
)

func input(t *testing.T) Input {
	t.Helper()
	catalog, err := scancatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		Catalog:       catalog,
		Applicability: applicability.Detect([]string{"pom.xml", "src/main/java/App.java"}, false, catalog),
		Settings:      map[string]string{},
		Now:           time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC),
	}
}

func byID(decisions []Decision) map[string]Decision {
	out := map[string]Decision{}
	for _, d := range decisions {
		out[d.ScannerID] = d
	}
	return out
}

func TestResolveDefaultsAndRepoChoices(t *testing.T) {
	in := input(t)
	got := byID(Resolve(in))
	if got["opengrep"].State != StateRecommended || got["spotbugs-findsecbugs"].State != StateRecommended {
		t.Fatalf("defaults = %+v", got)
	}
	if got["opengrep-interfile"].State != StateOff {
		t.Fatalf("pre-release must be off by default: %+v", got["opengrep-interfile"])
	}

	in.Settings = map[string]string{"opengrep": ModeDisabled, "opengrep-interfile": ModeEnabled}
	got = byID(Resolve(in))
	if got["opengrep"].State != StateDisabled || got["opengrep-interfile"].State != StateEnabled {
		t.Fatalf("repo choices = %+v", got)
	}
	if enabled := Enabled(Resolve(in)); len(enabled) != 2 {
		t.Fatalf("enabled = %v", enabled)
	}
}

func TestResolveRequirementCannotBeLoosened(t *testing.T) {
	in := input(t)
	requirement := Requirement{ID: uuid.New(), Language: "java", Capability: "bytecode-security", Enforcement: "blocking"}
	in.Requirements = []Requirement{requirement}
	in.Settings = map[string]string{"spotbugs-findsecbugs": ModeDisabled}

	got := byID(Resolve(in))
	spotbugs := got["spotbugs-findsecbugs"]
	if spotbugs.State != StateRequired || spotbugs.RepoMode != ModeDisabled || len(spotbugs.Requirements) != 1 {
		t.Fatalf("a repo cannot disable a required scanner: %+v", spotbugs)
	}

	// An approved, unexpired exception waives it; an expired one does not.
	in.Exceptions = []Exception{{ID: uuid.New(), RequirementID: requirement.ID, Scope: ".", Status: "approved", ExpiresAt: in.Now.Add(24 * time.Hour)}}
	if got := byID(Resolve(in))["spotbugs-findsecbugs"]; got.State != StateDisabled || len(got.Exempted) != 1 {
		t.Fatalf("exception must waive the requirement: %+v", got)
	}
	in.Exceptions[0].ExpiresAt = in.Now.Add(-time.Hour)
	if got := byID(Resolve(in))["spotbugs-findsecbugs"]; got.State != StateRequired {
		t.Fatalf("an expired exception waives nothing: %+v", got)
	}
	in.Exceptions[0].ExpiresAt, in.Exceptions[0].Status = in.Now.Add(time.Hour), "requested"
	if got := byID(Resolve(in))["spotbugs-findsecbugs"]; got.State != StateRequired {
		t.Fatalf("a requested exception waives nothing: %+v", got)
	}
}

func TestResolveRequirementCandidates(t *testing.T) {
	in := input(t)
	// cross-file taint: only the pre-release provides it, so it must be
	// approved by name to count.
	unapproved := Requirement{ID: uuid.New(), Language: "java", Capability: "cross-file-taint"}
	in.Requirements = []Requirement{unapproved}
	if got := byID(Resolve(in))["opengrep-interfile"]; got.State == StateRequired {
		t.Fatal("a pre-release is never required unless approved by name")
	}
	approved := unapproved
	approved.ScannerIDs = []string{"opengrep-interfile"}
	in.Requirements = []Requirement{approved}
	if got := byID(Resolve(in))["opengrep-interfile"]; got.State != StateRequired {
		t.Fatalf("approved pre-release must be required: %+v", got)
	}
	// No Python in the repo: a Python requirement requires nothing.
	in.Requirements = []Requirement{{ID: uuid.New(), Language: "python", Capability: "source-patterns"}}
	for _, d := range Resolve(in) {
		if d.State == StateRequired {
			t.Fatalf("requirement for an absent language required %s", d.ScannerID)
		}
	}
}

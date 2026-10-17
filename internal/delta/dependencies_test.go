package delta

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/cooldown"
	"github.com/hibouhq/hibou/internal/packagepolicy"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type dependencyTestStore struct {
	DeltaStore
	components map[uuid.UUID][]dbgen.Component
	run        *store.DepExtractionRun
}

func (s *dependencyTestStore) GetDepExtractionRunBySnapshot(_ context.Context, snapshotID uuid.UUID) (*store.DepExtractionRun, error) {
	if s.run != nil && s.run.SnapshotID == snapshotID {
		return s.run, nil
	}
	return nil, nil
}

func (s *dependencyTestStore) ListComponentsBySnapshot(_ context.Context, snapshotID uuid.UUID) ([]dbgen.Component, error) {
	return s.components[snapshotID], nil
}

func component(ecosystem, name, version string) dbgen.Component {
	return dbgen.Component{ID: uuid.New(), Purl: "pkg:" + ecosystem + "/" + name + "@" + version, Name: name, Version: version, Ecosystem: ecosystem}
}

func TestDiffComponents(t *testing.T) {
	base := []dbgen.Component{component("npm", "express", "4.18.2"), component("npm", "lodash", "4.17.21"), component("golang", "golang.org/x/net", "0.16.0")}
	head := []dbgen.Component{component("npm", "express", "4.21.2"), component("npm", "lodash", "4.17.21"), component("npm", "left-pad", "1.3.0")}
	delta := diffComponents(base, head)
	if delta.Added != 1 || delta.Updated != 1 || delta.Removed != 1 {
		t.Fatalf("counts added=%d updated=%d removed=%d", delta.Added, delta.Updated, delta.Removed)
	}
	kinds := make([]string, 0, len(delta.Changes))
	for _, change := range delta.Changes {
		kinds = append(kinds, change.Change+":"+change.Name)
		if change.Name == "express" && (change.Change != DependencyUpdated || change.PreviousVersion != "4.18.2" || change.Version != "4.21.2") {
			t.Errorf("express update not paired: %+v", change)
		}
	}
	if strings.Join(kinds, ",") != "added:left-pad,updated:express,removed:golang.org/x/net" {
		t.Errorf("order and kinds %v", kinds)
	}
}

func TestEvaluateDependencyDeltaHoldsAndExemptions(t *testing.T) {
	headID, baseID := uuid.New(), uuid.New()
	st := &dependencyTestStore{components: map[uuid.UUID][]dbgen.Component{
		baseID: {component("npm", "express", "4.18.2"), component("npm", "lodash", "4.17.21")},
		headID: {component("npm", "express", "4.21.2"), component("npm", "lodash", "4.17.21"), component("npm", "fresh-thing", "1.0.0"), component("npm", "evil-thing", "0.0.1")},
	}}
	until := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	svc := &Service{store: st, log: zerolog.Nop()}
	var seenPolicy packagepolicy.Policy
	svc.SetPackagePolicy(func(_ context.Context, req packagepolicy.Request) ([]packagepolicy.Decision, error) {
		seenPolicy = req.Policy
		out := make([]packagepolicy.Decision, 0, len(req.Purls))
		for _, purl := range req.Purls {
			switch {
			case strings.Contains(purl, "express"), strings.Contains(purl, "fresh-thing"):
				out = append(out, packagepolicy.Decision{Purl: purl, Decision: packagepolicy.DecisionHold, Until: &until, Reason: "in cooldown until 2026-10-24", Evaluated: true})
			case strings.Contains(purl, "evil-thing"):
				out = append(out, packagepolicy.Decision{Purl: purl, Decision: packagepolicy.DecisionDeny, Reason: "flagged as malicious", Evaluated: true})
			default:
				out = append(out, packagepolicy.Decision{Purl: purl, Decision: packagepolicy.DecisionAllow, Evaluated: true})
			}
		}
		return out, nil
	}, packagepolicy.Policy{WindowMode: "auto"})

	name := "express"
	ecosystem := "npm"
	resolved := []store.Vulnerability{{ComponentName: &name, Ecosystem: &ecosystem, PrimaryIdentifierValue: "CVE-2026-1234"}}
	cfg := &GateConfig{HeadSnapshotID: headID, BaseSnapshotID: baseID, Cooldown: &CooldownGate{WindowMode: "duration", WindowDuration: 7 * 24 * time.Hour, Enforcement: "blocking"}, PrivateNamespaces: []string{"pkg:npm/@acme/*"}}
	delta, reasons, notes := svc.evaluateDependencyDelta(context.Background(), uuid.New(), uuid.New(), cfg, &DeltaResult{Resolved: resolved})
	if delta == nil || !delta.Evaluated {
		t.Fatalf("delta not evaluated: %+v", delta)
	}
	if seenPolicy.WindowMode != "duration" || seenPolicy.WindowDuration != 7*24*time.Hour || len(seenPolicy.PrivateNamespaces) != 1 {
		t.Errorf("repository policy not applied: %+v", seenPolicy)
	}
	if delta.Holds != 1 || delta.Denies != 1 {
		t.Errorf("holds=%d denies=%d, want 1 and 1 (express is exempt)", delta.Holds, delta.Denies)
	}
	byName := map[string]DependencyChange{}
	for _, change := range delta.Changes {
		byName[change.Name] = change
	}
	if express := byName["express"]; express.Decision != packagepolicy.DecisionAllow || !strings.Contains(express.Exempt, "CVE-2026-1234") {
		t.Errorf("a version fixing a resolved finding must be exempt from cooldown: %+v", express)
	}
	if fresh := byName["fresh-thing"]; fresh.Decision != packagepolicy.DecisionHold || fresh.Until == nil {
		t.Errorf("fresh-thing must be held: %+v", fresh)
	}
	joined := strings.Join(reasons, "\n")
	if len(reasons) != 2 || !strings.Contains(joined, "fresh-thing") || !strings.Contains(joined, "evil-thing") {
		t.Errorf("blocking enforcement: reasons %v", reasons)
	}
	if len(notes) != 0 {
		t.Errorf("no notes expected under blocking, got %v", notes)
	}

	// Advisory enforcement: the hold becomes a note, the deny stays a reason.
	cfg.Cooldown.Enforcement = "advisory"
	_, reasons, notes = svc.evaluateDependencyDelta(context.Background(), uuid.New(), uuid.New(), cfg, &DeltaResult{Resolved: resolved})
	if len(reasons) != 1 || !strings.Contains(reasons[0], "evil-thing") {
		t.Errorf("advisory: only the deny is a reason, got %v", reasons)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "fresh-thing") {
		t.Errorf("advisory: the hold is a note, got %v", notes)
	}

	// No base inventory: nothing is judged, and it says so.
	empty, reasons, _ := svc.evaluateDependencyDelta(context.Background(), uuid.New(), uuid.New(), &GateConfig{HeadSnapshotID: headID, BaseSnapshotID: uuid.New()}, &DeltaResult{})
	if empty == nil || empty.Evaluated || empty.Note == "" || len(reasons) != 0 {
		t.Errorf("no base must mean not evaluated with a note, got %+v %v", empty, reasons)
	}
}

func TestEvaluateInstallConfig(t *testing.T) {
	headID := uuid.New()
	run := &store.DepExtractionRun{SnapshotID: headID, Modules: []store.DepExtractionModule{
		{Path: ".", InstallConfig: []store.DepInstallConfig{{Tool: "npm", Path: ".npmrc", Setting: "min-release-age", Present: true, WindowSeconds: 3 * 86400, Value: "3"}}},
		{Path: "web", InstallConfig: []store.DepInstallConfig{{Tool: "pnpm", Path: "web/pnpm-workspace.yaml", Setting: "minimumReleaseAge"}}},
		{Path: "svc"},
	}, Updaters: []store.DepUpdaterConfig{{Tool: "renovate", Path: "renovate.json", Present: true, WindowSeconds: 86400}}}
	st := &dependencyTestStore{run: run}
	svc := &Service{store: st, log: zerolog.Nop()}

	// warn (the default): every gap is a note; the short npm window counts
	// only against a duration policy.
	gaps, reasons, notes := svc.evaluateInstallConfig(context.Background(), &GateConfig{HeadSnapshotID: headID})
	if len(reasons) != 0 || len(notes) != 2 || len(gaps) != 2 {
		t.Fatalf("warn: gaps=%v reasons=%v notes=%v", gaps, reasons, notes)
	}
	if !strings.Contains(notes[0], "`web/` has no install-time cooldown for pnpm") {
		t.Errorf("missing pnpm gap: %v", notes)
	}
	if !strings.Contains(notes[1], "renovate waits 1d") {
		t.Errorf("updater mismatch not noted: %v", notes)
	}

	// require with a 7d policy: the missing setting and the short window
	// are reasons; the updater mismatch stays a note.
	cfg := &GateConfig{HeadSnapshotID: headID, Cooldown: &CooldownGate{InstallConfig: "require", WindowMode: cooldown.WindowDuration, WindowDuration: 7 * 24 * time.Hour}}
	gaps, reasons, notes = svc.evaluateInstallConfig(context.Background(), cfg)
	if len(reasons) != 2 || len(notes) != 1 || len(gaps) != 3 {
		t.Fatalf("require: gaps=%v reasons=%v notes=%v", gaps, reasons, notes)
	}
	if !strings.Contains(reasons[0], "npm waits 3d before installing a new version, the policy window is 7d") {
		t.Errorf("short window: %v", reasons)
	}

	// off: nothing.
	if gaps, reasons, notes := svc.evaluateInstallConfig(context.Background(), &GateConfig{HeadSnapshotID: headID, Cooldown: &CooldownGate{InstallConfig: "off"}}); len(gaps)+len(reasons)+len(notes) != 0 {
		t.Errorf("off: %v %v %v", gaps, reasons, notes)
	}
}

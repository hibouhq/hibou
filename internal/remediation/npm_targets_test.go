package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func targetBackend(t *testing.T, style, actualVersion string) NPMBackend {
	t.Helper()
	b := fixtureNPMBackend(t)
	_, lock := npmFixture(t, actualVersion, style+"1.0.1")
	b.Tool = testTool(t, "if [ \"$1\" = ci ]; then exit 0; fi\n"+
		"if [ \"$1\" = install ]; then\ncat > package-lock.json <<'LOCK'\n"+lock+"LOCK\nexit 0\nfi\nexit 29")
	b.Match = func(ctx context.Context, purls []string) ([]AdvisoryMatch, error) {
		out, err := npmMatchFixture(ctx, purls)
		for i := range out {
			if strings.HasSuffix(out[i].Purl, "@1.0.0") {
				out[i].Signals = &MatchSignals{RecommendedVersion: "1.0.1", FetchedAt: time.Now()}
			}
		}
		return out, err
	}
	return b
}

func TestExactAndGossipTargetsPreserveDeclarationStyle(t *testing.T) {
	for _, style := range []string{"", "^", "~"} {
		for _, mode := range []string{"exact", "gossip"} {
			t.Run(mode+style, func(t *testing.T) {
				manifest, lock := npmFixture(t, "1.0.0", style+"1.0.0")
				root, sha := repository(t, map[string]string{"package.json": manifest, "package-lock.json": lock})
				b := targetBackend(t, style, "1.0.1")
				unit, err := b.Prepare(t.Context(), root, sha, "package.json", nil, "patch")
				if err != nil {
					t.Fatal(err)
				}
				if len(unit.DirectPackages) != 1 || unit.DirectPackages[0].RecommendedVersion != "1.0.1" {
					t.Fatalf("missing version controls: %+v", unit.DirectPackages)
				}
				unit.VersionTargets = []VersionTarget{{Name: "fixture-dependency", Mode: mode, Version: "1.0.1"}}
				a, err := (Engine{Backend: b}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{unit}})
				if err != nil {
					t.Fatal(err)
				}
				if len(a.Units[0].RequestedTargets) != 1 || a.Units[0].Updates[0].To != "1.0.1" {
					t.Fatalf("exact target not reported: %+v", a.Units)
				}
				if !strings.Contains(string(a.Patch), `"fixture-dependency":"`+style+`1.0.1"`) {
					t.Fatalf("declaration style lost: %s", a.Patch)
				}
			})
		}
	}
}

func TestRequestedVersionIsNeverSilentlySubstituted(t *testing.T) {
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	root, sha := repository(t, map[string]string{"package.json": manifest, "package-lock.json": lock})
	b := targetBackend(t, "", "1.0.2")
	u, err := b.Prepare(t.Context(), root, sha, "package.json", nil, "patch")
	if err != nil {
		t.Fatal(err)
	}
	u.VersionTargets = []VersionTarget{{Name: "fixture-dependency", Mode: "exact", Version: "1.0.1"}}
	a, err := (Engine{Backend: b}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{u}})
	if err == nil || a != nil || !strings.Contains(err.Error(), "does not equal") {
		t.Fatalf("target substituted: %v %v", a, err)
	}
}

func TestInvalidVersionChoicesFailBeforeNativeInstall(t *testing.T) {
	for _, target := range []VersionTarget{
		{Name: "fixture-dependency", Mode: "exact", Version: "latest"},
		{Name: "fixture-dependency", Mode: "exact", Version: "^1.0.1"},
		{Name: "fixture-dependency", Mode: "exact", Version: "0.9.0"},
		{Name: "fixture-dependency", Mode: "exact", Version: "1.1.0"},
		{Name: "fixture-dependency", Mode: "exact", Version: "1.0.1-beta.1"},
		{Name: "fixture-dependency", Mode: "gossip", Version: "1.0.2"},
		{Name: "other", Mode: "exact", Version: "1.0.1"},
	} {
		t.Run(target.Name+target.Version, func(t *testing.T) {
			manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
			root, sha := repository(t, map[string]string{"package.json": manifest, "package-lock.json": lock})
			b := targetBackend(t, "", "1.0.1")
			u, err := b.Prepare(t.Context(), root, sha, "package.json", nil, "patch")
			if err != nil {
				t.Fatal(err)
			}
			u.VersionTargets = []VersionTarget{target}
			a, err := (Engine{Backend: b}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{u}})
			if err == nil || a != nil {
				t.Fatalf("invalid choice accepted: %v %v", a, err)
			}
		})
	}
}

func TestGossipFreshnessAndPolicyRemainMandatory(t *testing.T) {
	if freshRecommendation(&MatchSignals{FetchedAt: time.Now().Add(24 * time.Hour)}) ||
		freshRecommendation(&MatchSignals{FetchedAt: time.Now().Add(-25 * time.Hour)}) {
		t.Fatal("untrustworthy timestamp accepted")
	}
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	root, sha := repository(t, map[string]string{"package.json": manifest, "package-lock.json": lock})
	b := targetBackend(t, "", "1.0.1")
	u, err := b.Prepare(t.Context(), root, sha, "package.json", nil, "patch")
	if err != nil {
		t.Fatal(err)
	}
	original := b.Match
	b.Match = func(ctx context.Context, purls []string) ([]AdvisoryMatch, error) {
		out, err := original(ctx, purls)
		for i := range out {
			if strings.HasSuffix(out[i].Purl, "@1.0.1") {
				out[i].Decision = "hold"
				out[i].Reason = "cooldown"
			}
		}
		return out, err
	}
	u.VersionTargets = []VersionTarget{{Name: "fixture-dependency", Mode: "gossip", Version: "1.0.1"}}
	a, err := (Engine{Backend: b}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{u}})
	if err == nil || a != nil || !strings.Contains(err.Error(), "policy") || errors.Is(err, ErrNoChanges) {
		t.Fatalf("policy bypassed by recommendation: %v %v", a, err)
	}
}

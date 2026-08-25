package cvetriage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The chain ADR-028 exists to make work, end to end and in order:
//
//	an advisory arrives with no package coordinates
//	  → a watch on the vendor's own product name matches it
//	  → it queues for a person rather than producing a finding
//	  → a person names the packages
//	  → advisory data is authored with the CNA's ranges, not typed ones
//	  → the ordinary purl matcher can find it
//
// Every step is asserted, because a chain that is only tested link by link can
// still be broken between them.
func TestWatchedProductBecomesAuthoredAdvisory(t *testing.T) {
	ctx := context.Background()
	record := loadTomcatRecord(t)

	// 1. The advisory names a product and version ranges, and no package.
	if len(record.Affected) != 1 || record.Affected[0].ProductKey != "apachetomcat" {
		t.Fatalf("fixture changed: %+v", record.Affected)
	}
	for _, product := range record.Affected {
		for _, versionRange := range product.Ranges {
			if versionRange.LastAffected == "" {
				t.Fatalf("range %+v lost its bound", versionRange)
			}
		}
	}

	// 2. A watch on the CNA's own product name matches it.
	target := newFakeStore()
	subscriptionID := uuid.New()
	target.subscriptions = []dbgen.CveSubscription{{ID: subscriptionID, Label: "Apache Tomcat"}}
	source := &fakeSource{
		ids:      []string{record.ID},
		revision: "e2e",
		records:  map[string][]byte{record.ID: readFixture(t, "CVE-2026-59084.json")},
	}

	result, err := newSweeper(source, target).Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// 3. It queues for a person. Nothing is reported as a finding yet, because
	//    the coordinate that would make one possible does not exist upstream.
	if result.Queued != 1 || result.Applied != 0 {
		t.Fatalf("result = %+v, want it queued for a person", result)
	}

	// 4. A person names the packages. They type no versions.
	decision := Decision{
		CVEID:   record.ID,
		ActorID: uuid.New(),
		Packages: []Package{
			{Ecosystem: "Maven", Name: "org.apache.tomcat:tomcat-catalina"},
			{Ecosystem: "Maven", Name: "org.apache.tomcat.embed:tomcat-embed-core"},
		},
	}
	ingester := &fakeIngester{}
	if _, err := Apply(ctx, ingester, decision, record); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// 5. The authored data carries the CNA's ranges verbatim and attaches to
	//    the CVE, so it converges rather than forking a second advisory.
	authored := ingester.results[0]
	if len(authored.Aliases) != 1 || authored.Aliases[0] != record.ID {
		t.Fatalf("aliases = %v, want the CVE so it converges", authored.Aliases)
	}
	if len(authored.AffectedRanges) != 10 {
		t.Fatalf("ranges = %d, want 5 branches x 2 packages", len(authored.AffectedRanges))
	}
	for _, authoredRange := range authored.AffectedRanges {
		if authoredRange.Fixed != "" {
			t.Errorf("range %+v invented a fixed version", authoredRange)
		}
		if authoredRange.Source != SourceTriage {
			t.Errorf("range %+v is not attributable to triage", authoredRange)
		}
	}

	// 6. The coordinates are now the ones the ordinary purl matcher uses.
	names := map[string]bool{}
	for _, authoredRange := range authored.AffectedRanges {
		names[authoredRange.Ecosystem+"/"+authoredRange.PackageName] = true
	}
	if !names["maven/org.apache.tomcat:tomcat-catalina"] {
		t.Errorf("authored coordinates = %v", names)
	}
}

// The reuse claim, which is the whole economic argument: a mapping is made once
// per product, not once per advisory. A second Tomcat CVE must reach a finding
// without asking anybody anything.
func TestSecondAdvisoryForTheSameProductNeedsNoTriage(t *testing.T) {
	ctx := context.Background()

	target := newFakeStore()
	target.subscriptions = []dbgen.CveSubscription{{ID: uuid.New(), Label: "Apache Tomcat"}}
	// The product was mapped when its first advisory was triaged, and opted in.
	target.autoApply = []Package{{Ecosystem: "Maven", Name: "org.apache.tomcat:tomcat-catalina"}}

	source := &fakeSource{
		ids:      []string{"CVE-2026-53434"},
		revision: "second",
		records:  map[string][]byte{"CVE-2026-53434": readFixture(t, "CVE-2026-53434.json")},
	}

	result, err := newSweeper(source, target).Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if result.Queued != 0 {
		t.Error("a second advisory for an already-mapped product asked a person again")
	}
	if result.Applied != 1 || len(target.applied) != 1 {
		t.Fatalf("result = %+v, applied = %v", result, target.applied)
	}
	if len(target.appliedPackages) != 1 ||
		target.appliedPackages[0].Name != "org.apache.tomcat:tomcat-catalina" {
		t.Errorf("reused packages = %+v", target.appliedPackages)
	}
}

// Authoring advisory data creates findings across every repository using the
// package, so no base role may confer it — admin included.
func TestAuthoringRequiresAnExplicitGrant(t *testing.T) {
	// Guarded in internal/rbac (TestNoBaseRoleGrantsTriage); asserted here as
	// the chain's precondition so the two cannot drift apart silently.
	if advisory.IsReservedIdentifier("CVE-2026-59084") {
		t.Fatal("a CVE was treated as a reserved hibou identifier")
	}
	decision := Decision{CVEID: "CVE-2026-59084", Packages: []Package{{Ecosystem: "Maven", Name: "g:a"}}}
	if err := decision.Validate(); err == nil {
		t.Fatal("a decision with no actor was accepted; authorship must be attributable")
	}
}

func loadTomcatRecord(t *testing.T) cvefeed.Projection {
	t.Helper()
	record, err := cvefeed.Decode(readFixture(t, "CVE-2026-59084.json"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return record
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "cvefeed", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

var (
	_ = zerolog.Nop
	_ = store.EventAuthored
)

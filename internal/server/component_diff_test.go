package server

import (
	"slices"
	"testing"

	"github.com/hibouhq/hibou/internal/store"
)

func componentRow(purl, name, version string, licenses ...string) store.ListComponentsBySnapshotWithVulnsRow {
	return store.ListComponentsBySnapshotWithVulnsRow{
		Purl:      purl,
		Name:      name,
		Version:   version,
		Ecosystem: "npm",
		Licenses:  licenses,
	}
}

// A license already carried by an untouched dependency is not introduced by the
// change, so the base set must cover the components the diff never lists.
func TestBuildComponentDiffBaseLicensesCoverUnchangedComponents(t *testing.T) {
	unchanged := componentRow("pkg:npm/keep@1.0.0", "keep", "1.0.0", "GPL-3.0-only")
	base := []store.ListComponentsBySnapshotWithVulnsRow{unchanged}
	head := []store.ListComponentsBySnapshotWithVulnsRow{
		unchanged,
		componentRow("pkg:npm/new@2.0.0", "new", "2.0.0", "GPL-3.0-only"),
	}

	diff := buildComponentDiff(base, head)

	if diff.Unchanged != 1 {
		t.Fatalf("Unchanged = %d, want 1", diff.Unchanged)
	}
	if len(diff.Removed) != 0 {
		t.Fatalf("Removed = %+v, want empty", diff.Removed)
	}
	if !slices.Contains(diff.BaseLicenses, "GPL-3.0-only") {
		t.Fatalf("BaseLicenses = %v, want it to contain GPL-3.0-only", diff.BaseLicenses)
	}
	// The added component's only license is already in the base set, so nothing
	// is newly introduced.
	for _, entry := range diff.Added {
		for _, id := range entry.Licenses {
			if !slices.Contains(diff.BaseLicenses, id) {
				t.Fatalf("license %q on added %s reported as new", id, entry.Purl)
			}
		}
	}
}

func TestBuildComponentDiffNormalizesLicenses(t *testing.T) {
	base := []store.ListComponentsBySnapshotWithVulnsRow{
		componentRow("pkg:npm/a@1.0.0", "a", "1.0.0", "(MIT)"),
		componentRow("pkg:npm/b@1.0.0", "b", "1.0.0", "  MIT  ", "MIT"),
	}
	head := []store.ListComponentsBySnapshotWithVulnsRow{
		componentRow("pkg:npm/c@1.0.0", "c", "1.0.0", "(MIT)", ""),
	}

	diff := buildComponentDiff(base, head)

	if want := []string{"MIT"}; !slices.Equal(diff.BaseLicenses, want) {
		t.Fatalf("BaseLicenses = %v, want %v", diff.BaseLicenses, want)
	}
	if len(diff.Added) != 1 {
		t.Fatalf("Added = %+v, want one entry", diff.Added)
	}
	if want := []string{"MIT"}; !slices.Equal(diff.Added[0].Licenses, want) {
		t.Fatalf("Added[0].Licenses = %v, want %v", diff.Added[0].Licenses, want)
	}
}

// Nothing declared anywhere in the base must still marshal as [], not null.
func TestBuildComponentDiffBaseLicensesEmptyNotNil(t *testing.T) {
	diff := buildComponentDiff(nil, nil)
	if diff.BaseLicenses == nil {
		t.Fatal("BaseLicenses is nil, want empty slice")
	}
}

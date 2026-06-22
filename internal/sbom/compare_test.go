package sbom

import (
	"reflect"
	"testing"
)

func TestCompare(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base []ParsedComponent
		head []ParsedComponent
		want *SBOMDiff
	}{
		{
			name: "identical sboms",
			base: []ParsedComponent{
				{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Ecosystem: "npm"},
				{Name: "local-lib", Version: "2.0.0", Ecosystem: "custom"},
			},
			head: []ParsedComponent{
				{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Ecosystem: "npm"},
				{Name: "local-lib", Version: "2.0.0", Ecosystem: "custom"},
			},
			want: &SBOMDiff{
				Added:          []ComponentDelta{},
				Removed:        []ComponentDelta{},
				VersionChanged: []ComponentDelta{},
				Unchanged: []ComponentDelta{
					{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Ecosystem: "npm"},
					{Name: "local-lib", Version: "2.0.0", Ecosystem: "custom"},
				},
				Summary: SBOMDiffSummary{TotalBase: 2, TotalHead: 2, Unchanged: 2},
			},
		},
		{
			name: "added and removed components",
			base: []ParsedComponent{
				{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Ecosystem: "npm"},
				{PURL: "pkg:npm/b@1.0.0", Name: "b", Version: "1.0.0", Ecosystem: "npm"},
			},
			head: []ParsedComponent{
				{PURL: "pkg:npm/b@1.0.0", Name: "b", Version: "1.0.0", Ecosystem: "npm"},
				{PURL: "pkg:npm/c@1.0.0", Name: "c", Version: "1.0.0", Ecosystem: "npm"},
			},
			want: &SBOMDiff{
				Added:          []ComponentDelta{{PURL: "pkg:npm/c@1.0.0", Name: "c", Version: "1.0.0", Ecosystem: "npm"}},
				Removed:        []ComponentDelta{{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Ecosystem: "npm"}},
				VersionChanged: []ComponentDelta{},
				Unchanged:      []ComponentDelta{{PURL: "pkg:npm/b@1.0.0", Name: "b", Version: "1.0.0", Ecosystem: "npm"}},
				Summary:        SBOMDiffSummary{TotalBase: 2, TotalHead: 2, Added: 1, Removed: 1, Unchanged: 1},
			},
		},
		{
			name: "version changes compare by fallback key when purl missing",
			base: []ParsedComponent{{Name: "local-lib", Version: "1.0.0", Ecosystem: "custom"}},
			head: []ParsedComponent{{Name: "local-lib", Version: "1.1.0", Ecosystem: "custom"}},
			want: &SBOMDiff{
				Added:          []ComponentDelta{},
				Removed:        []ComponentDelta{},
				VersionChanged: []ComponentDelta{{Name: "local-lib", BaseVersion: "1.0.0", HeadVersion: "1.1.0", Ecosystem: "custom"}},
				Unchanged:      []ComponentDelta{},
				Summary:        SBOMDiffSummary{TotalBase: 1, TotalHead: 1, VersionChanged: 1},
			},
		},
		{
			name: "version changes compare by normalized purl key",
			base: []ParsedComponent{{PURL: "pkg:npm/alpha@1.0.0", Name: "alpha", Version: "1.0.0", Ecosystem: "npm"}},
			head: []ParsedComponent{{PURL: "pkg:npm/alpha@1.1.0", Name: "alpha", Version: "1.1.0", Ecosystem: "npm"}},
			want: &SBOMDiff{
				Added:          []ComponentDelta{},
				Removed:        []ComponentDelta{},
				VersionChanged: []ComponentDelta{{PURL: "pkg:npm/alpha@1.1.0", Name: "alpha", BaseVersion: "1.0.0", HeadVersion: "1.1.0", Ecosystem: "npm"}},
				Unchanged:      []ComponentDelta{},
				Summary:        SBOMDiffSummary{TotalBase: 1, TotalHead: 1, VersionChanged: 1},
			},
		},
		{
			name: "multi-version package sets keep distinct versions per document",
			base: []ParsedComponent{
				{PURL: "pkg:npm/foo@1.0.0", Name: "foo", Version: "1.0.0", Ecosystem: "npm"},
				{PURL: "pkg:npm/foo@2.0.0", Name: "foo", Version: "2.0.0", Ecosystem: "npm"},
				{PURL: "pkg:npm/bar@1.0.0", Name: "bar", Version: "1.0.0", Ecosystem: "npm"},
			},
			head: []ParsedComponent{
				{PURL: "pkg:npm/foo@2.0.0", Name: "foo", Version: "2.0.0", Ecosystem: "npm"},
				{PURL: "pkg:npm/foo@3.0.0", Name: "foo", Version: "3.0.0", Ecosystem: "npm"},
				{PURL: "pkg:npm/bar@2.0.0", Name: "bar", Version: "2.0.0", Ecosystem: "npm"},
			},
			want: &SBOMDiff{
				Added:          []ComponentDelta{{PURL: "pkg:npm/foo@3.0.0", Name: "foo", Version: "3.0.0", Ecosystem: "npm"}},
				Removed:        []ComponentDelta{{PURL: "pkg:npm/foo@1.0.0", Name: "foo", Version: "1.0.0", Ecosystem: "npm"}},
				VersionChanged: []ComponentDelta{{PURL: "pkg:npm/bar@2.0.0", Name: "bar", BaseVersion: "1.0.0", HeadVersion: "2.0.0", Ecosystem: "npm"}},
				Unchanged:      []ComponentDelta{{PURL: "pkg:npm/foo@2.0.0", Name: "foo", Version: "2.0.0", Ecosystem: "npm"}},
				Summary:        SBOMDiffSummary{TotalBase: 3, TotalHead: 3, Added: 1, Removed: 1, VersionChanged: 1, Unchanged: 1},
			},
		},
		{
			name: "mixed changes sorted by name",
			base: []ParsedComponent{
				{PURL: "pkg:npm/z@1.0.0", Name: "zeta", Version: "1.0.0", Ecosystem: "npm"},
				{PURL: "pkg:npm/a@1.0.0", Name: "alpha", Version: "1.0.0", Ecosystem: "npm"},
				{Name: "local-lib", Version: "1.0.0", Ecosystem: "custom"},
			},
			head: []ParsedComponent{
				{PURL: "pkg:npm/a@1.0.0", Name: "alpha", Version: "1.0.0", Ecosystem: "npm"},
				{PURL: "pkg:npm/m@1.0.0", Name: "mu", Version: "1.0.0", Ecosystem: "npm"},
				{Name: "local-lib", Version: "2.0.0", Ecosystem: "custom"},
			},
			want: &SBOMDiff{
				Added:          []ComponentDelta{{PURL: "pkg:npm/m@1.0.0", Name: "mu", Version: "1.0.0", Ecosystem: "npm"}},
				Removed:        []ComponentDelta{{PURL: "pkg:npm/z@1.0.0", Name: "zeta", Version: "1.0.0", Ecosystem: "npm"}},
				VersionChanged: []ComponentDelta{{Name: "local-lib", BaseVersion: "1.0.0", HeadVersion: "2.0.0", Ecosystem: "custom"}},
				Unchanged:      []ComponentDelta{{PURL: "pkg:npm/a@1.0.0", Name: "alpha", Version: "1.0.0", Ecosystem: "npm"}},
				Summary:        SBOMDiffSummary{TotalBase: 3, TotalHead: 3, Added: 1, Removed: 1, VersionChanged: 1, Unchanged: 1},
			},
		},
		{
			name: "empty inputs",
			base: nil,
			head: nil,
			want: &SBOMDiff{
				Added:          []ComponentDelta{},
				Removed:        []ComponentDelta{},
				VersionChanged: []ComponentDelta{},
				Unchanged:      []ComponentDelta{},
				Summary:        SBOMDiffSummary{},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Compare(tt.base, tt.head)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Compare() diff = %#v, want %#v", got, tt.want)
			}
		})
	}
}

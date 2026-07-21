package forge

import (
	"reflect"
	"testing"
)

func TestParseUnifiedPatch(t *testing.T) {
	tests := []struct {
		name  string
		patch string
		want  []int
	}{
		{
			name: "additions and context advance new-line counter",
			// New file lines: 10 (ctx), 11 (+), 12 (+), 13 (ctx)
			patch: "@@ -10,2 +10,4 @@ func foo() {\n ctx\n+added one\n+added two\n ctx2",
			want:  []int{11, 12},
		},
		{
			name: "removed lines do not advance new-line counter",
			// -old at new-line 5 removed; +new replaces it at new-line 5
			patch: "@@ -5,2 +5,2 @@\n context\n-removed\n+replacement",
			want:  []int{6},
		},
		{
			name:  "multiple hunks",
			patch: "@@ -1,1 +1,2 @@\n a\n+b\n@@ -20,0 +21,1 @@\n+far",
			want:  []int{2, 21},
		},
		{
			name:  "no newline marker ignored",
			patch: "@@ -1,1 +1,1 @@\n-old\n+new\n\\ No newline at end of file",
			want:  []int{1},
		},
		{
			name:  "empty patch",
			patch: "",
			want:  nil,
		},
		{
			name:  "hunk without explicit count",
			patch: "@@ -0,0 +1 @@\n+only line",
			want:  []int{1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseUnifiedPatch(tc.patch)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseUnifiedPatch(%q) = %v, want %v", tc.patch, got, tc.want)
			}
		})
	}
}

func TestSortedUniqueLines(t *testing.T) {
	got := sortedUniqueLines([]int{5, 1, 5, 0, -3, 2, 1})
	want := []int{1, 2, 5}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sortedUniqueLines = %v, want %v", got, want)
	}
	if sortedUniqueLines(nil) != nil {
		t.Fatal("expected nil for empty input")
	}
}

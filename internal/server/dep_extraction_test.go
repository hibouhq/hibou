package server

import "testing"

func TestBranchIsEager(t *testing.T) {
	patterns := []string{"develop", "release/*", "  ", "hotfix/*"}
	cases := []struct {
		ref, defaultBranch string
		want               bool
	}{
		{"main", "main", true},
		{"main", "refs/heads/main", true},
		{"develop", "main", true},
		{"release/1.2", "main", true},
		{"release/1.2/fix", "main", false}, // path.Match: * does not cross /
		{"hotfix/urgent", "main", true},
		{"feature/x", "main", false},
		{"", "main", false},
	}
	for _, tc := range cases {
		if got := branchIsEager(tc.ref, tc.defaultBranch, patterns); got != tc.want {
			t.Errorf("branchIsEager(%q, %q) = %v, want %v", tc.ref, tc.defaultBranch, got, tc.want)
		}
	}
	if branchIsEager("feature/x", "main", nil) {
		t.Error("no patterns: only the default branch is eager")
	}
}

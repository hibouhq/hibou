package lsp

import (
	"fmt"
	"strings"
	"testing"
)

func TestLineMapFollowsInsertionsAndDeletions(t *testing.T) {
	t.Parallel()

	old := splitLines("a\nb\nc\nd\ne\n")
	cur := splitLines("new1\na\nb\nX\nd\ne\nnew2\n")
	m := newLineMap(old, cur)

	cases := []struct {
		start, end         int
		wantStart, wantEnd int
		wantEdited         bool
	}{
		{0, 0, 1, 1, false}, // "a" moved down by the inserted first line
		{1, 1, 2, 2, false}, // "b"
		{2, 2, 3, 3, true},  // "c" was replaced: anchored on its replacement "X", marked edited
		{3, 4, 4, 5, false}, // "d".."e" moved
		{1, 3, 2, 4, true},  // range spanning the rewritten line
	}
	for _, tc := range cases {
		s, e, edited := m.mapRange(tc.start, tc.end)
		if s != tc.wantStart || e != tc.wantEnd || edited != tc.wantEdited {
			t.Errorf("mapRange(%d,%d) = (%d,%d,%v), want (%d,%d,%v)", tc.start, tc.end, s, e, edited, tc.wantStart, tc.wantEnd, tc.wantEdited)
		}
	}
}

func TestLineMapInsertionInsideRangeMarksEdited(t *testing.T) {
	t.Parallel()

	m := newLineMap(splitLines("a\nb\nc"), splitLines("a\nb\ninserted\nc"))
	if s, e, edited := m.mapRange(1, 2); s != 1 || e != 3 || !edited {
		t.Fatalf("mapRange = (%d,%d,%v), want (1,3,true)", s, e, edited)
	}
	if s, e, edited := m.mapRange(0, 1); s != 0 || e != 1 || edited {
		t.Fatalf("untouched range = (%d,%d,%v), want (0,1,false)", s, e, edited)
	}
}

func TestLineMapIdentical(t *testing.T) {
	t.Parallel()

	lines := splitLines("x\r\ny\r\nz\r\n")
	m := newLineMap(lines, splitLines("x\ny\nz"))
	if s, e, edited := m.mapRange(0, 2); s != 0 || e != 2 || edited {
		t.Fatalf("mapRange = (%d,%d,%v), want (0,2,false)", s, e, edited)
	}
}

func TestLineMapGivesUpOnHugeRewriteWithoutLosingAnchors(t *testing.T) {
	t.Parallel()

	var old, cur []string
	old = append(old, "head")
	cur = append(cur, "head")
	for i := range 4 * maxDiffEdits {
		old = append(old, fmt.Sprintf("old %d", i))
		cur = append(cur, fmt.Sprintf("new %d", i))
	}
	old = append(old, "tail")
	cur = append(cur, "tail")

	m := newLineMap(old, cur)
	if s, _, edited := m.mapRange(len(old)-1, len(old)-1); s != len(cur)-1 || edited {
		t.Fatalf("tail = (%d,%v), want (%d,false)", s, edited, len(cur)-1)
	}
	if _, _, edited := m.mapRange(10, 10); !edited {
		t.Fatal("rewritten middle must be reported as edited")
	}
}

func TestMyersMatchesIsALongestCommonSubsequence(t *testing.T) {
	t.Parallel()

	a := strings.Split("ABCABBA", "")
	b := strings.Split("CBABAC", "")
	pairs, ok := myersMatches(a, b)
	if !ok {
		t.Fatal("diff gave up")
	}
	if len(pairs) != 4 { // LCS length of the classic Myers example
		t.Fatalf("matched %d lines, want 4", len(pairs))
	}
	for _, p := range pairs {
		if a[p[0]] != b[p[1]] {
			t.Fatalf("pair %v matches %q with %q", p, a[p[0]], b[p[1]])
		}
	}
}

func TestParseRemote(t *testing.T) {
	t.Parallel()

	cases := map[string]remote{
		"https://github.com/hibouhq/hibou.git":                {Host: "github.com", Owner: "hibouhq", Repo: "hibou"},
		"git@github.com:hibouhq/hibou.git":                    {Host: "github.com", Owner: "hibouhq", Repo: "hibou"},
		"ssh://git@gitlab.example.com:2222/group/sub/project": {Host: "gitlab.example.com", Owner: "group/sub", Repo: "project"},
		"https://user:pw@Forgejo.Example.com/devtools/api/":   {Host: "forgejo.example.com", Owner: "devtools", Repo: "api"},
		"forgejo.local:devtools/api.git":                      {Host: "forgejo.local", Owner: "devtools", Repo: "api"},
	}
	for raw, want := range cases {
		got, err := parseRemote(raw)
		if err != nil || got != want {
			t.Errorf("parseRemote(%q) = %+v, %v; want %+v", raw, got, err, want)
		}
	}
	for _, bad := range []string{"/srv/git/repo", "https://github.com/onlyrepo", ""} {
		if _, err := parseRemote(bad); err == nil {
			t.Errorf("parseRemote(%q) succeeded, want error", bad)
		}
	}
}

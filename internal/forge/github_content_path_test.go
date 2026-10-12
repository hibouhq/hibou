package forge

import (
	"context"
	"errors"
	"testing"
)

func TestEscapeContentPathRejectsDotSegments(t *testing.T) {
	for _, path := range []string{"", "/", "..", "../secrets", "a/../b", "a/./b", ".", "a//b", "a/..", "a\\..\\b", "a\x00b"} {
		if got, err := checkedContentPath(path); !errors.Is(err, errUnsafeContentPath) {
			t.Errorf("checkedContentPath(%q) = %q, %v; want errUnsafeContentPath", path, got, err)
		}
		if got := escapeContentPath(path); got != "" {
			t.Errorf("escapeContentPath(%q) = %q, want empty", path, got)
		}
	}
}

func TestEscapeContentPathEscapesSegments(t *testing.T) {
	cases := map[string]string{
		".hibou.yaml":         ".hibou.yaml",
		"/.github/hibou.yml/": ".github/hibou.yml",
		"dir with space/a?b":  "dir%20with%20space/a%3Fb",
		"..hidden/x..y":       "..hidden/x..y",
	}
	for in, want := range cases {
		got, err := checkedContentPath(in)
		if err != nil || got != want {
			t.Errorf("checkedContentPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestGitHubContentCallsRejectTraversal(t *testing.T) {
	g := &GitHub{}
	if _, err := g.GetFileContent(context.Background(), "o", "r", "../../orgs/x", "main"); !errors.Is(err, errUnsafeContentPath) {
		t.Fatalf("GetFileContent: expected errUnsafeContentPath, got %v", err)
	}
	if err := g.CreateOrUpdateFile(context.Background(), "o", "r", "a/../../b", "main", "msg", nil); !errors.Is(err, errUnsafeContentPath) {
		t.Fatalf("CreateOrUpdateFile: expected errUnsafeContentPath, got %v", err)
	}
}

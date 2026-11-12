package lsp

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/remediation"
)

func TestRemediationApplySessionAndBufferGuards(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "package.json")
	if err := os.WriteFile(file, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{workspaces: map[string]*workspace{}, docs: map[string]*document{}}
	s.workspaces[root] = newWorkspace(s, root)
	for _, invalid := range []remediationApplyParams{{}, {Root: t.TempDir()}} {
		if _, err := s.remediationApply(t.Context(), invalid); err == nil {
			t.Fatal("missing or unregistered root accepted")
		}
	}
	s.docs[pathToURI(file)] = &document{path: file, text: "unsaved change"}
	p := remediationApplyParams{Root: root, Artifact: remediation.Artifact{Changes: []remediation.Change{{Path: "package.json"}}}}
	if _, err := s.remediationApply(t.Context(), p); err == nil || !strings.Contains(err.Error(), "unsaved") {
		t.Fatalf("unsaved buffer not rejected: %v", err)
	}
}

func TestRemediationApplyWholeBatchWithoutServer(t *testing.T) {
	root := t.TempDir()
	gitCmd(t, root, "init", "-q")
	before, after := "{}\n", "{\"fixed\":true}\n"
	for _, name := range []string{"package.json", "package-lock.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(before), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitCmd(t, root, "add", ".")
	gitCmd(t, root, "commit", "-q", "-m", "baseline")
	sha := gitCmd(t, root, "rev-parse", "HEAD")
	for _, name := range []string{"package.json", "package-lock.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(after), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	patch := []byte(gitCmd(t, root, "diff", "--no-ext-diff", "--no-textconv") + "\n")
	var changes []remediation.Change
	for _, name := range []string{"package.json", "package-lock.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(before), 0o644); err != nil {
			t.Fatal(err)
		}
		changes = append(changes, remediation.Change{Path: name,
			Before: fmt.Sprintf("%x", sha256.Sum256([]byte(before))), After: fmt.Sprintf("%x", sha256.Sum256([]byte(after)))})
	}
	a := remediation.Artifact{BaseSHA: sha, Patch: patch, SHA256: fmt.Sprintf("%x", sha256.Sum256(patch)), Changes: changes,
		Units: []remediation.UnitResult{{ID: "root"}}, Verification: []remediation.Verification{{DependencyFilesConsistent: true, SelectedVulnsAddressed: true, NoIntroducedVulns: true}}}
	s := &Server{workspaces: map[string]*workspace{}, docs: map[string]*document{}}
	s.workspaces[root] = newWorkspace(s, root)
	p := remediationApplyParams{Root: root, Artifact: a}
	result, err := s.remediationApply(t.Context(), p)
	if err != nil || result.AlreadyApplied {
		t.Fatalf("batch apply: %v %v", result, err)
	}
	for _, change := range changes {
		data, err := os.ReadFile(filepath.Join(root, change.Path))
		if err != nil || string(data) != after {
			t.Fatalf("batch output %s: %s %v", change.Path, data, err)
		}
	}
	result, err = s.remediationApply(t.Context(), p)
	if err != nil || !result.AlreadyApplied {
		t.Fatalf("batch retry: %v %v", result, err)
	}
}

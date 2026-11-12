package remediation

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedSnapshotTransfersDependencyDataWithoutGitOrOtherSource(t *testing.T) {
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	root, sha := repository(t, map[string]string{
		"package.json": manifest, "package-lock.json": lock, "private-source.txt": "not transferred",
	})
	snapshot, err := CaptureManagedSnapshot(t.Context(), root, sha)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SourceSHA != sha || len(snapshot.Files) != 2 {
		t.Fatalf("unexpected source transport: %+v", snapshot)
	}
	copyRoot, synthetic, cleanup, err := MaterializeManagedSnapshot(t.Context(), snapshot, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for name, data := range snapshot.Files {
		copied, err := gitOutput(t.Context(), copyRoot, copyRoot, "cat-file", "blob", synthetic+":"+name)
		if err != nil || !bytes.Equal(data, copied) {
			t.Fatalf("transport changed %s: %v", name, err)
		}
	}
	snapshot.Files["../package.json"] = []byte(`{}`)
	if _, _, cleanup, err := MaterializeManagedSnapshot(t.Context(), snapshot, t.TempDir()); err == nil {
		cleanup()
		t.Fatal("unsafe snapshot path accepted")
	}
}

func TestManagedPreparationDoesNotNeedNativeTools(t *testing.T) {
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	root, sha := repository(t, map[string]string{"package.json": manifest, "package-lock.json": lock})
	snapshot, err := CaptureManagedSnapshot(t.Context(), root, sha)
	if err != nil {
		t.Fatal(err)
	}
	input := ManagedInput{BaseSHA: sha, Operation: "prepare", Tool: Tool{Path: filepath.Join(t.TempDir(), "does-not-exist")}}
	result, err := PrepareManagedModules(t.Context(), root, input, snapshot, npmMatchFixture)
	if err != nil || len(result.Modules) != 1 || result.Modules[0].Unit == nil {
		t.Fatalf("data-only discovery tried to execute a tool: %+v %v", result, err)
	}
}

func TestManagedSnapshotExcludesUnselectedConfiguration(t *testing.T) {
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	files := map[string][]byte{
		"selected/package.json": []byte(manifest), "selected/package-lock.json": []byte(lock),
		"other/.npmrc": []byte("registry credentials must not cross this job boundary"),
	}
	unit := Unit{RequiredFiles: []string{"selected/package.json", "selected/package-lock.json"}, InputSHA256: map[string]string{
		"selected/package.json": digest([]byte(manifest)), "selected/package-lock.json": digest([]byte(lock)),
	}}
	selected, err := SelectManagedSnapshot(ManagedSnapshot{SourceSHA: strings.Repeat("a", 40), Files: files}, []Unit{unit})
	if err != nil || len(selected.Files) != 2 || selected.Files["other/.npmrc"] != nil {
		t.Fatalf("unselected source entered workload: %+v %v", selected, err)
	}
	unit.InputSHA256["selected/package-lock.json"] = strings.Repeat("0", 64)
	if _, err := SelectManagedSnapshot(ManagedSnapshot{SourceSHA: strings.Repeat("a", 40), Files: files}, []Unit{unit}); err == nil {
		t.Fatal("snapshot with stale discovery hashes accepted")
	}
}

func TestManagedCandidateIsIndependentlyBoundToPatchGraphAndPolicy(t *testing.T) {
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	root, sha := repository(t, map[string]string{"package.json": manifest, "package-lock.json": lock})
	backend := fixtureNPMBackend(t)
	unit, err := backend.Prepare(t.Context(), root, sha, "package.json", nil, "patch")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := (Engine{Backend: backend}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{unit}})
	if err != nil {
		t.Fatal(err)
	}
	files, err := managedArtifactFiles(t.Context(), root, t.TempDir(), *artifact)
	if err != nil {
		t.Fatal(err)
	}
	input := ManagedInput{BaseSHA: sha, Units: []Unit{unit}}
	result := &ManagedResult{Artifact: artifact, Files: files}
	if err := VerifyManagedCandidate(t.Context(), root, input, result, backend, false); err != nil {
		t.Fatal(err)
	}
	originalPatch, originalDigest := artifact.Patch, artifact.SHA256
	artifact.Patch = append(append([]byte(nil), originalPatch...), []byte("diff --git a/unexpected.txt b/unexpected.txt\nnew file mode 100644\n--- /dev/null\n+++ b/unexpected.txt\n@@ -0,0 +1 @@\n+unexpected\n")...)
	artifact.SHA256 = digest(artifact.Patch)
	if err := VerifyManagedCandidate(t.Context(), root, input, result, backend, false); err == nil {
		t.Fatal("patch containing an undeclared file bypassed trusted reconstruction")
	}
	artifact.Patch, artifact.SHA256 = originalPatch, originalDigest
	denied := backend
	denied.Match = func(ctx context.Context, purls []string) ([]AdvisoryMatch, error) {
		matches, err := npmMatchFixture(ctx, purls)
		for i := range matches {
			if strings.HasSuffix(matches[i].Purl, "@1.0.1") {
				matches[i].Decision = "hold"
			}
		}
		return matches, err
	}
	if err := VerifyManagedCandidate(t.Context(), root, input, result, denied, false); err == nil {
		t.Fatal("candidate's claimed verification bypassed controller policy")
	}
	artifact.Changes[0].Before = strings.Repeat("0", 64)
	if err := VerifyManagedCandidate(t.Context(), root, input, result, backend, false); err == nil {
		t.Fatal("candidate with forged baseline hashes accepted")
	}
}

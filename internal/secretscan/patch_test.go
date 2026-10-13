package secretscan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleDiff = `diff --git a/config/prod.env b/config/prod.env
index 1111111..2222222 100644
--- a/config/prod.env
+++ b/config/prod.env
@@ -1,3 +1,5 @@
 DB_HOST=localhost
+AWS_KEY=AKIAIOSFODNN7EXAMPLE
 DB_PORT=5432
+DEBUG=true
@@ -10,2 +12,3 @@
 TAIL=1
+LAST=value
diff --git a/deleted.txt b/deleted.txt
--- a/deleted.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-gone
-lines
`

func TestAddedLinesByFile(t *testing.T) {
	files, err := addedLinesByFile([]byte(sampleDiff))
	if err != nil {
		t.Fatalf("addedLinesByFile: %v", err)
	}
	lines, ok := files["config/prod.env"]
	if !ok || len(lines) != 3 {
		t.Fatalf("added lines = %#v, want 3 for config/prod.env", files)
	}
	// Line numbers must be new-file positions: context consumes a line, removals don't.
	if lines[0].number != 2 || lines[0].text != "AWS_KEY=AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("first added = %+v, want line 2", lines[0])
	}
	if lines[1].number != 4 || lines[1].text != "DEBUG=true" {
		t.Fatalf("second added = %+v, want line 4", lines[1])
	}
	if lines[2].number != 13 {
		t.Fatalf("third added = %+v, want line 13 from the second hunk", lines[2])
	}
	if _, ok := files["deleted.txt"]; ok {
		t.Fatal("a deleted file (+++ /dev/null) must not be materialized")
	}
}

func TestAddedLinesByFileRejectsTraversalPaths(t *testing.T) {
	hostile := "--- a/x\n+++ b/../../etc/cron.d/evil\n@@ -0,0 +1 @@\n+boom\n"
	files, err := addedLinesByFile([]byte(hostile))
	if err != nil {
		t.Fatalf("addedLinesByFile: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("files = %#v, want traversal path dropped", files)
	}
}

func TestMaterializePatchFilesMapsLinesToRealNumbers(t *testing.T) {
	files, err := addedLinesByFile([]byte(sampleDiff))
	if err != nil {
		t.Fatalf("addedLinesByFile: %v", err)
	}
	dir, lineMaps, cleanup, err := materializePatchFiles(t.TempDir(), files)
	if err != nil {
		t.Fatalf("materializePatchFiles: %v", err)
	}
	defer cleanup()

	content, err := os.ReadFile(filepath.Join(dir, "config", "prod.env"))
	if err != nil {
		t.Fatalf("read materialized file: %v", err)
	}
	// Only added lines are written; non-adjacent runs get one blank separator.
	want := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n\nDEBUG=true\n\nLAST=value\n"
	if string(content) != want {
		t.Fatalf("materialized = %q, want %q", content, want)
	}
	lineMap := lineMaps["config/prod.env"]
	// The scanner reports materialized lines; the map must give back the line
	// the pushed file actually has.
	for materialized, real := range map[int32]int32{1: 2, 3: 4, 5: 13} {
		if got := lineMap.real(materialized); got != real {
			t.Fatalf("real(%d) = %d, want %d", materialized, got, real)
		}
	}
}

func TestMaterializePatchFilesHugeHunkStartDoesNotPad(t *testing.T) {
	hostile := "--- a/x\n+++ b/x\n@@ -1 +2000000000 @@\n+AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	files, err := addedLinesByFile([]byte(hostile))
	if err != nil {
		t.Fatalf("addedLinesByFile: %v", err)
	}
	dir, lineMaps, cleanup, err := materializePatchFiles(t.TempDir(), files)
	if err != nil {
		t.Fatalf("materializePatchFiles: %v", err)
	}
	defer cleanup()
	info, err := os.Stat(filepath.Join(dir, "x"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() > 64 {
		t.Fatalf("materialized %d bytes, want only the added line", info.Size())
	}
	if got := lineMaps["x"].real(1); got != 2000000000 {
		t.Fatalf("real(1) = %d, want 2000000000", got)
	}
}

func TestParseHunkNewStartRejectsOutOfRange(t *testing.T) {
	if _, err := parseHunkNewStart("@@ -1 +99999999999 @@"); err == nil {
		t.Fatal("want an error for a start line beyond int32")
	}
}

func TestMaterializePatchFilesCapsFileCount(t *testing.T) {
	files := make(map[string][]addedLine, maxPatchFiles+1)
	for i := 0; i <= maxPatchFiles; i++ {
		files[fmt.Sprintf("f%d", i)] = []addedLine{{number: 1, text: "x"}}
	}
	if _, _, _, err := materializePatchFiles(t.TempDir(), files); !errors.Is(err, ErrPatchTooLarge) {
		t.Fatalf("err = %v, want ErrPatchTooLarge", err)
	}
}

func TestMaterializePatchFilesCapsBytes(t *testing.T) {
	line := strings.Repeat("a", 1<<20)
	files := map[string][]addedLine{}
	for i := 0; i < 5; i++ {
		files[fmt.Sprintf("f%d", i)] = []addedLine{{number: 1, text: line}}
	}
	if _, _, _, err := materializePatchFiles(t.TempDir(), files); !errors.Is(err, ErrPatchTooLarge) {
		t.Fatalf("err = %v, want ErrPatchTooLarge", err)
	}
}

// An added line whose content is "++ b/decoy" shows in the diff as
// "+++ b/decoy". Inside a hunk it is an added line: it must not switch the
// current file, and the secret after it must stay attributed and scanned.
func TestAddedLinesByFileDecoyHeaderInsideHunk(t *testing.T) {
	patch := "diff --git a/app.env b/app.env\n" +
		"--- a/app.env\n" +
		"+++ b/app.env\n" +
		"@@ -0,0 +1,3 @@\n" +
		"+++ b/decoy\n" +
		"+@@ -0,0 +1 @@\n" +
		"+AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
	files, err := addedLinesByFile([]byte(patch))
	if err != nil {
		t.Fatalf("addedLinesByFile: %v", err)
	}
	if _, ok := files["decoy"]; ok {
		t.Fatalf("decoy header inside a hunk switched files: %#v", files)
	}
	lines := files["app.env"]
	if len(lines) != 3 || lines[0].text != "++ b/decoy" || lines[2].text != "AWS_KEY=AKIAIOSFODNN7EXAMPLE" || lines[2].number != 3 {
		t.Fatalf("app.env added lines = %#v, want all three with the secret on line 3", lines)
	}
}

// Outside a hunk, "+++ " is a file header only right after "--- ".
func TestAddedLinesByFilePlusHeaderNeedsMinusHeader(t *testing.T) {
	patch := "--- a/real\n+++ b/real\n@@ -1 +1 @@\n-old\n+new\n+++ b/decoy\n@@ -5 +5,2 @@\n x\n+SECRET=1\n"
	files, err := addedLinesByFile([]byte(patch))
	if err != nil {
		t.Fatalf("addedLinesByFile: %v", err)
	}
	if _, ok := files["decoy"]; ok {
		t.Fatalf("lone +++ line switched files: %#v", files)
	}
	if lines := files["real"]; len(lines) != 2 || lines[1].text != "SECRET=1" || lines[1].number != 6 {
		t.Fatalf("real added lines = %#v", lines)
	}
}

// git quotes the whole path, b/ prefix included.
func TestParseDiffPathQuotedPrefix(t *testing.T) {
	for raw, want := range map[string]string{
		`"b/dir/na\"me"`: `dir/na"me`,
		`"b/tab\there"`:  "tab\there",
		"b/plain":        "plain",
		`"b/../escape"`:  "",
		"/dev/null":      "",
		`"b/"`:           "",
	} {
		if got := parseDiffPath(raw); got != want {
			t.Errorf("parseDiffPath(%q) = %q, want %q", raw, got, want)
		}
	}
}

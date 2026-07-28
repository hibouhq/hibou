package secretscan

import (
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

func TestMaterializePatchFilesPlacesLinesAtRealNumbers(t *testing.T) {
	files, err := addedLinesByFile([]byte(sampleDiff))
	if err != nil {
		t.Fatalf("addedLinesByFile: %v", err)
	}
	dir, cleanup, err := materializePatchFiles(t.TempDir(), files)
	if err != nil {
		t.Fatalf("materializePatchFiles: %v", err)
	}
	defer cleanup()

	content, err := os.ReadFile(filepath.Join(dir, "config", "prod.env"))
	if err != nil {
		t.Fatalf("read materialized file: %v", err)
	}
	lines := strings.Split(string(content), "\n")
	// 1-indexed line 2 is index 1: the scanner must report the same line the
	// pushed file actually has.
	if lines[1] != "AWS_KEY=AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("line 2 = %q, want the added secret line", lines[1])
	}
	if lines[3] != "DEBUG=true" || lines[12] != "LAST=value" {
		t.Fatalf("padding wrong: line4=%q line13=%q", lines[3], lines[12])
	}
	if lines[0] != "" || lines[2] != "" {
		t.Fatal("unpatched lines must be blank padding, never invented content")
	}
}

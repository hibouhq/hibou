package forge

import (
	"bufio"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// PatchDiff is the changed-file line map between two refs (typically a pull
// request's target `base` and source `head`). It powers line-level patch
// (diff) coverage: the fraction of the lines a change added or modified that
// the test suite actually executes.
type PatchDiff struct {
	// Files are the changed files, keyed by their head-side path.
	Files []PatchFile
	// Truncated is true when the forge capped the file list (e.g. GitHub's
	// compare API returns at most 300 files); callers should surface this so
	// a partial patch coverage number is never mistaken for a complete one.
	Truncated bool
}

// PatchFile is one changed file and the new-side line numbers a change touched.
type PatchFile struct {
	Path string // head-side (new) path
	// OldPath is the pre-rename path when Status == "renamed", else empty.
	OldPath string
	// Status mirrors the forge's classification: added, modified, removed,
	// renamed, copied, changed.
	Status string
	// AddedLines are the new-side line numbers that were added or modified,
	// sorted ascending. These are the lines patch coverage evaluates.
	AddedLines []int
	// Hunks is the raw unified-diff patch text for this file, exactly as the
	// forge returned it. It is carried through to the client so the annotated
	// diff can be rendered without a second forge round-trip or storing source.
	Hunks string
}

// hunkHeaderPattern matches a unified-diff hunk header, capturing the new-side
// start line and optional line count: "@@ -12,3 +14,6 @@ optional context".
var hunkHeaderPattern = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

// ParseUnifiedPatch extracts the new-side line numbers that a single file's
// unified-diff patch text added or modified. In unified-diff terms these are
// the `+` lines; context and removed (`-`) lines are skipped, and the new-file
// line counter advances only over context and added lines. This is what the
// forge compare API returns per file in its `patch` field.
func ParseUnifiedPatch(patch string) []int {
	if strings.TrimSpace(patch) == "" {
		return nil
	}

	var added []int
	newLine := 0
	inHunk := false

	scanner := bufio.NewScanner(strings.NewReader(patch))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if start, ok := parseHunkStart(line); ok {
			newLine = start
			inHunk = true
			continue
		}
		if !inHunk {
			continue
		}
		switch {
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
			// File headers occasionally appear inside combined patches; ignore.
			continue
		case strings.HasPrefix(line, "+"):
			added = append(added, newLine)
			newLine++
		case strings.HasPrefix(line, "-"):
			// Removed line: consumes an old-side line only.
		case strings.HasPrefix(line, "\\"):
			// "\ No newline at end of file": no line movement.
		default:
			// Context line (leading space) or empty context line.
			newLine++
		}
	}
	return added
}

// parseHunkStart returns the new-side starting line number of a hunk header.
func parseHunkStart(line string) (int, bool) {
	match := hunkHeaderPattern.FindStringSubmatch(line)
	if match == nil {
		return 0, false
	}
	start, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}
	return start, true
}

// sortedUniqueLines returns the ascending, deduplicated line numbers.
func sortedUniqueLines(lines []int) []int {
	if len(lines) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(lines))
	out := make([]int, 0, len(lines))
	for _, line := range lines {
		if line <= 0 {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	sort.Ints(out)
	return out
}

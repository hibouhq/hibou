package secretscan

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FilesystemScanner is implemented by providers that can scan a plain
// directory (no git history). Used for the synchronous push-check path, where
// the commits exist nowhere Hibou can clone.
type FilesystemScanner interface {
	ScanFilesystem(ctx context.Context, dir string) ([]SecretFinding, error)
}

// CheckPatch scans the added lines of a unified diff and persists nothing
// (ADR-010). Findings report the path and new-file line number of the leak.
func (s *Scanner) CheckPatch(ctx context.Context, patch []byte) ([]SecretFinding, error) {
	if s == nil {
		return nil, errors.New("secret scanner is not configured")
	}
	files, err := addedLinesByFile(patch)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return []SecretFinding{}, nil
	}

	dir, lineMaps, cleanup, err := materializePatchFiles(s.tempDir, files)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	findings := make([]SecretFinding, 0)
	seen := make(map[string]struct{})
	ran := false
	for _, provider := range s.providers {
		scanner, ok := provider.(FilesystemScanner)
		if !ok {
			continue
		}
		ran = true
		providerFindings, err := scanner.ScanFilesystem(ctx, dir)
		if err != nil {
			return nil, fmt.Errorf("provider %s patch scan: %w", provider.Name(), err)
		}
		appendUniqueSecretFindings(&findings, seen, providerFindings)
	}
	if !ran {
		return nil, errors.New("no configured provider can scan a patch")
	}
	for index := range findings {
		findings[index].FilePath = filepath.ToSlash(strings.TrimPrefix(findings[index].FilePath, dir+string(os.PathSeparator)))
		lineMap := lineMaps[findings[index].FilePath]
		findings[index].StartLine = lineMap.real(findings[index].StartLine)
		findings[index].EndLine = lineMap.real(findings[index].EndLine)
	}
	return findings, nil
}

// Limits on what a patch may materialize. The request body is already capped,
// but a diff can name many tiny files; each one costs a file create.
const (
	maxPatchFiles             = 1000
	maxPatchMaterializedBytes = 4 << 20
)

// ErrPatchTooLarge reports a patch over the materialization limits.
var ErrPatchTooLarge = errors.New("patch exceeds the secret check limits")

// patchLineMap maps a materialized file's 1-based line to the pushed file's
// new-file line number; 0 marks a separator between non-adjacent runs.
type patchLineMap []int

func (m patchLineMap) real(line int32) int32 {
	if line < 1 || int(line) > len(m) {
		return line
	}
	if real := m[line-1]; real > 0 {
		if real > math.MaxInt32 {
			return math.MaxInt32
		}
		return int32(real) // #nosec G115 -- bounded just above.
	}
	return line
}

type addedLine struct {
	number int
	text   string
}

// addedLinesByFile extracts the + lines of a unified diff, keyed by new-file
// path, with their new-file line numbers.
func addedLinesByFile(patch []byte) (map[string][]addedLine, error) {
	files := make(map[string][]addedLine)
	currentPath := ""
	newLine := 0
	inHunk := false

	for _, rawLine := range strings.Split(string(patch), "\n") {
		switch {
		case strings.HasPrefix(rawLine, "+++ "):
			currentPath = parseDiffPath(strings.TrimPrefix(rawLine, "+++ "))
			inHunk = false
		case strings.HasPrefix(rawLine, "@@"):
			start, err := parseHunkNewStart(rawLine)
			if err != nil {
				return nil, err
			}
			newLine = start
			inHunk = true
		case !inHunk || currentPath == "":
			// File headers, mode lines, binary notices.
		case strings.HasPrefix(rawLine, "+"):
			files[currentPath] = append(files[currentPath], addedLine{number: newLine, text: rawLine[1:]})
			newLine++
		case strings.HasPrefix(rawLine, "-"):
			// Removed line: no new-file line consumed.
		case strings.HasPrefix(rawLine, `\`):
			// "\ No newline at end of file"
		default:
			newLine++
		}
	}
	return files, nil
}

func parseDiffPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "/dev/null" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "b/")
	// git quotes paths with special characters.
	if unquoted, err := strconv.Unquote(raw); err == nil {
		raw = unquoted
	}
	if strings.Contains(raw, "..") || strings.HasPrefix(raw, "/") {
		// A hostile patch must not escape the scratch dir.
		return ""
	}
	return raw
}

func parseHunkNewStart(header string) (int, error) {
	// @@ -a,b +c,d @@ — c is the new-file start line.
	plus := strings.Index(header, "+")
	if plus < 0 {
		return 0, fmt.Errorf("malformed hunk header %q", header)
	}
	rest := header[plus+1:]
	end := strings.IndexAny(rest, ", @")
	if end < 0 {
		end = len(rest)
	}
	start, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0, fmt.Errorf("malformed hunk header %q: %w", header, err)
	}
	if start < 0 || start > math.MaxInt32 {
		return 0, fmt.Errorf("hunk start out of range in %q", header)
	}
	return start, nil
}

// materializePatchFiles writes only each file's added lines, compactly, and
// returns the line map that translates scanner-reported positions back to
// the pushed file's line numbers. Padding to the real line numbers would let
// a hunk header like "@@ -1 +2000000000 @@" allocate gigabytes. Non-adjacent
// runs are separated by one blank line so a multi-line rule cannot join lines
// that are not neighbours in the pushed file.
func materializePatchFiles(tempDir string, files map[string][]addedLine) (string, map[string]patchLineMap, func(), error) {
	if len(files) > maxPatchFiles {
		return "", nil, nil, fmt.Errorf("%w: %d files (max %d)", ErrPatchTooLarge, len(files), maxPatchFiles)
	}
	root := tempDir
	if root == "" {
		root = os.TempDir()
	}
	dir, err := os.MkdirTemp(root, "hibou-secret-check-*")
	if err != nil {
		return "", nil, nil, fmt.Errorf("create patch scan dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	lineMaps := make(map[string]patchLineMap, len(files))
	total := 0
	for path, lines := range files {
		if path == "" || len(lines) == 0 {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			cleanup()
			return "", nil, nil, fmt.Errorf("create patch scan subdir: %w", err)
		}
		var builder strings.Builder
		lineMap := make(patchLineMap, 0, len(lines))
		previous := 0
		for _, line := range lines {
			if previous > 0 && line.number != previous+1 {
				builder.WriteByte('\n')
				lineMap = append(lineMap, 0)
			}
			builder.WriteString(line.text)
			builder.WriteByte('\n')
			lineMap = append(lineMap, line.number)
			previous = line.number
		}
		total += builder.Len()
		if total > maxPatchMaterializedBytes {
			cleanup()
			return "", nil, nil, fmt.Errorf("%w: more than %d bytes of added lines", ErrPatchTooLarge, maxPatchMaterializedBytes)
		}
		if err := os.WriteFile(target, []byte(builder.String()), 0o600); err != nil {
			cleanup()
			return "", nil, nil, fmt.Errorf("write patch scan file: %w", err)
		}
		lineMaps[path] = lineMap
	}
	return dir, lineMaps, cleanup, nil
}

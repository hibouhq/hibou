package secretscan

import (
	"context"
	"errors"
	"fmt"
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

	dir, cleanup, err := materializePatchFiles(s.tempDir, files)
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
	}
	return findings, nil
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
	return start, nil
}

// materializePatchFiles writes each file's added lines at their real new-file
// line numbers (blank-padded), so scanner-reported locations match the pushed
// content exactly.
func materializePatchFiles(tempDir string, files map[string][]addedLine) (string, func(), error) {
	root := tempDir
	if root == "" {
		root = os.TempDir()
	}
	dir, err := os.MkdirTemp(root, "hibou-secret-check-*")
	if err != nil {
		return "", nil, fmt.Errorf("create patch scan dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	for path, lines := range files {
		if path == "" || len(lines) == 0 {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("create patch scan subdir: %w", err)
		}
		var builder strings.Builder
		current := 1
		for _, line := range lines {
			for current < line.number {
				builder.WriteByte('\n')
				current++
			}
			builder.WriteString(line.text)
			builder.WriteByte('\n')
			current++
		}
		if err := os.WriteFile(target, []byte(builder.String()), 0o600); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("write patch scan file: %w", err)
		}
	}
	return dir, cleanup, nil
}

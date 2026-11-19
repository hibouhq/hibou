package notices

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/package-url/packageurl-go"

	"github.com/hibouhq/hibou/internal/license"
)

// Package contents are untrusted input (ADR-051 §7): only licence and notice
// files are read, by name, with size and count limits. Nothing is executed.
const (
	maxLicenseFileBytes = 1 << 20 // 1 MiB per file
	maxFilesPerPackage  = 24
)

var licenseNamePrefixes = []string{"license", "licence", "copying", "unlicense", "copyright"}

// isLicenseFile reports whether a base name looks like a licence file:
// LICENSE, LICENSE.md, LICENSE-MIT, COPYING.LESSER, MIT-LICENSE.txt.
func isLicenseFile(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".md", ".txt", ".rst", ".markdown"} {
		lower = strings.TrimSuffix(lower, ext)
	}
	for _, prefix := range licenseNamePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return !strings.HasSuffix(lower, ".go") && !strings.HasSuffix(lower, ".js") && !strings.HasSuffix(lower, ".py")
		}
	}
	return strings.HasSuffix(lower, "-license") || strings.HasSuffix(lower, "-licence") || strings.HasSuffix(lower, ".license")
}

// isNoticeFile reports whether a base name is a NOTICE file.
func isNoticeFile(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".md", ".txt"} {
		lower = strings.TrimSuffix(lower, ext)
	}
	return lower == "notice" || lower == "notices"
}

// readDirEvidence reads the licence and notice files at the top of a
// directory (and of the extra sub-directories given, relative to it).
func readDirEvidence(dir string, subdirs ...string) (files []File, notice string, issues []string) {
	count := 0
	for _, sub := range append([]string{""}, subdirs...) {
		if sub != "" {
			info, err := os.Lstat(filepath.Join(dir, sub))
			if err == nil && info.Mode()&os.ModeSymlink != 0 {
				issues = append(issues, "symlinked evidence directory "+sub)
				continue
			}
		}
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				issues = append(issues, "cannot list evidence directory "+filepath.ToSlash(sub))
			}
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !isLicenseFile(name) && !isNoticeFile(name) {
				continue
			}
			count++
			if count > maxFilesPerPackage {
				issues = append(issues, "evidence file count exceeds 24 files")
				break
			}
			data, err := readEvidenceFile(filepath.Join(dir, sub, name))
			if err != nil {
				issues = append(issues, "cannot read evidence "+path.Join(filepath.ToSlash(sub), name)+": "+evidenceError(err))
				continue
			}
			if strings.TrimSpace(string(data)) == "" {
				issues = append(issues, "empty evidence file "+name)
				continue
			}
			rel := path.Join(filepath.ToSlash(sub), name)
			if isNoticeFile(name) {
				notice = joinNotices(notice, string(data))
				continue
			}
			files = append(files, File{Path: rel, Text: string(data)})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, notice, uniqueSorted(issues)
}

// Do not follow evidence-file symlinks or read unbounded package contents.
func readEvidenceFile(filename string) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > maxLicenseFileBytes {
		return nil, errors.New("file exceeds 1 MiB")
	}
	root, err := os.OpenRoot(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	handle, err := root.Open(filepath.Base(filename))
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(handle, maxLicenseFileBytes+1))
	closeErr := handle.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if len(data) > maxLicenseFileBytes {
		return nil, errors.New("file exceeds 1 MiB")
	}
	if !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
		return nil, errors.New("evidence is not UTF-8 text")
	}
	return data, nil
}

// Keep machine-specific cache paths out of generated documents.
func evidenceError(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}

// readZipEvidence reads the licence and notice files of an archive that sit
// at its root or directly under META-INF/ (jars, wheels).
func readZipEvidence(archive string, dirs ...string) (files []File, notice string, err error) {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return nil, "", err
	}
	defer reader.Close()
	var issues []error
	count := 0
	allowed := map[string]bool{".": true}
	for _, dir := range dirs {
		allowed[strings.TrimSuffix(dir, "/")] = true
	}
	entries := append([]*zip.File{}, reader.File...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, entry := range entries {
		if entry.FileInfo().IsDir() {
			continue
		}
		name := path.Base(entry.Name)
		if !allowed[path.Dir(entry.Name)] || (!isLicenseFile(name) && !isNoticeFile(name)) {
			continue
		}
		count++
		if count > maxFilesPerPackage {
			issues = append(issues, errors.New("evidence file count exceeds 24 files"))
			break
		}
		if !entry.Mode().IsRegular() {
			issues = append(issues, fmt.Errorf("%s: not a regular file", name))
			continue
		}
		if entry.UncompressedSize64 > maxLicenseFileBytes {
			issues = append(issues, fmt.Errorf("%s: file exceeds 1 MiB", name))
			continue
		}
		handle, err := entry.Open()
		if err != nil {
			issues = append(issues, fmt.Errorf("%s: cannot open evidence", name))
			continue
		}
		data, err := io.ReadAll(io.LimitReader(handle, maxLicenseFileBytes+1))
		closeErr := handle.Close()
		if err != nil || closeErr != nil || len(data) > maxLicenseFileBytes || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
			issues = append(issues, fmt.Errorf("%s: unreadable, oversized or non-text evidence", name))
			continue
		}
		if isNoticeFile(name) {
			notice = joinNotices(notice, string(data))
			continue
		}
		files = append(files, File{Path: entry.Name, Text: string(data)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, notice, errors.Join(issues...)
}

func joinNotices(existing, added string) string {
	added = strings.TrimSpace(added)
	if existing == "" {
		return added
	}
	if added == "" || strings.Contains(existing, added) {
		return existing
	}
	return existing + "\n\n" + added
}

// parsePurl returns the parts collectors need; ok is false for a purl
// without a name or a version.
func parsePurl(raw string) (purl packageurl.PackageURL, ok bool) {
	parsed, err := packageurl.FromString(raw)
	if err != nil || parsed.Name == "" || parsed.Version == "" {
		return packageurl.PackageURL{}, false
	}
	for _, field := range []string{parsed.Namespace, parsed.Name, parsed.Version} {
		if strings.ContainsAny(field, "\\\x00") || strings.HasPrefix(field, "/") {
			return packageurl.PackageURL{}, false
		}
		for _, segment := range strings.Split(field, "/") {
			if segment == "." || segment == ".." {
				return packageurl.PackageURL{}, false
			}
		}
	}
	for _, key := range []string{"classifier", "type"} {
		value := parsed.Qualifiers.Map()[key]
		if strings.ContainsAny(value, "/\\\x00") || value == "." || value == ".." {
			return packageurl.PackageURL{}, false
		}
	}
	return parsed, true
}

// spdxLike reports whether declared metadata is an identifier or expression
// rather than free text ("Apache License, Version 2.0", "see LICENSE").
func spdxLike(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 120 || strings.ContainsAny(value, ",;:\n") {
		return false
	}
	if _, err := license.Alternatives(value); err != nil {
		return false
	}
	lower := strings.ToLower(value)
	return !strings.HasPrefix(lower, "see ") && lower != "unlicensed" && lower != "proprietary" && lower != "custom"
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func firstExisting(paths ...string) string {
	for _, candidate := range paths {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return ""
}

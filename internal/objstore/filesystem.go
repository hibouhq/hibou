package objstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errInvalidKey = errors.New("invalid object store key")

// FilesystemStore stores blobs on the local filesystem.
type FilesystemStore struct {
	basePath     string
	baseResolved string
}

func NewFilesystemStore(basePath string) (*FilesystemStore, error) {
	trimmed := strings.TrimSpace(basePath)
	if trimmed == "" {
		return nil, fmt.Errorf("base path is required")
	}
	if err := os.MkdirAll(trimmed, 0o755); err != nil {
		return nil, fmt.Errorf("create base path: %w", err)
	}
	baseResolved, err := filepath.EvalSymlinks(trimmed)
	if err != nil {
		return nil, fmt.Errorf("resolve base path: %w", err)
	}
	return &FilesystemStore{basePath: trimmed, baseResolved: baseResolved}, nil
}

func (f *FilesystemStore) Put(ctx context.Context, key string, r io.Reader, contentType string) error {
	_ = contentType

	resolved, err := f.resolvePath(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return fmt.Errorf("create object directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(resolved), ".objstore-*")
	if err != nil {
		return fmt.Errorf("create temp object: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := io.Copy(tmpFile, r); err != nil {
		return fmt.Errorf("write object: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp object: %w", err)
	}
	if err := os.Rename(tmpName, resolved); err != nil {
		return fmt.Errorf("commit object: %w", err)
	}

	return nil
}

func (f *FilesystemStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolved, err := f.resolvePath(key)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (f *FilesystemStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := f.resolvePath(key)
	if err != nil {
		return err
	}
	return os.Remove(resolved)
}

func (f *FilesystemStore) Exists(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	resolved, err := f.resolvePath(key)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(resolved)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (f *FilesystemStore) resolvePath(key string) (string, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "", errInvalidKey
	}
	if filepath.IsAbs(trimmed) {
		return "", errInvalidKey
	}
	cleaned := filepath.Clean(trimmed)
	if cleaned == "." || cleaned == "" {
		return "", errInvalidKey
	}
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if part == ".." || part == "." || part == "" {
			return "", errInvalidKey
		}
	}
	resolved := filepath.Join(f.baseResolved, cleaned)
	current := f.baseResolved
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				current = next
				continue
			}
			return "", fmt.Errorf("resolve object path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolvedLink, err := filepath.EvalSymlinks(next)
			if err != nil {
				return "", fmt.Errorf("resolve object path: %w", err)
			}
			if !pathWithinBase(f.baseResolved, resolvedLink) {
				return "", errInvalidKey
			}
			next = resolvedLink
		}
		current = next
	}
	if !pathWithinBase(f.baseResolved, resolved) {
		return "", errInvalidKey
	}
	return resolved, nil
}

func pathWithinBase(basePath, candidate string) bool {
	rel, err := filepath.Rel(basePath, candidate)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

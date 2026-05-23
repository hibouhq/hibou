package objstore

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemStorePutGetRoundTrip(t *testing.T) {
	store, err := NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemStore() error = %v", err)
	}

	ctx := context.Background()
	key := "acme/service/snapshot-1/sbom.json"
	body := "{\"bomFormat\":\"CycloneDX\"}"
	if err := store.Put(ctx, key, strings.NewReader(body), "application/json"); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	r, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer r.Close()

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(data) != body {
		t.Fatalf("Get() body = %q, want %q", string(data), body)
	}
}

func TestFilesystemStoreDelete(t *testing.T) {
	store, err := NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemStore() error = %v", err)
	}

	ctx := context.Background()
	key := "acme/service/snapshot-1/sarif.json"
	if err := store.Put(ctx, key, strings.NewReader("{}"), "application/json"); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Get(ctx, key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Get() after delete error = %v, want not-exist", err)
	}
	if exists, err := store.Exists(ctx, key); err != nil || exists {
		t.Fatalf("Exists() after delete = (%v, %v), want (false, nil)", exists, err)
	}
}

func TestFilesystemStoreExists(t *testing.T) {
	store, err := NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemStore() error = %v", err)
	}

	ctx := context.Background()
	key := "acme/service/snapshot-1/sbom.json"
	exists, err := store.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if exists {
		t.Fatalf("Exists() before put = true, want false")
	}
	if err := store.Put(ctx, key, strings.NewReader("{}"), "application/json"); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	exists, err = store.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists() error = %v", err)
	}
	if !exists {
		t.Fatalf("Exists() after put = false, want true")
	}
}

func TestFilesystemStoreRejectsPathTraversal(t *testing.T) {
	store, err := NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFilesystemStore() error = %v", err)
	}

	ctx := context.Background()
	for _, key := range []string{"../escape.json", "acme/../../escape.json", "/tmp/escape.json"} {
		if err := store.Put(ctx, key, strings.NewReader("{}"), "application/json"); !errors.Is(err, errInvalidKey) {
			t.Fatalf("Put(%q) error = %v, want errInvalidKey", key, err)
		}
	}
}

func TestFilesystemStoreRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	store, err := NewFilesystemStore(root)
	if err != nil {
		t.Fatalf("NewFilesystemStore() error = %v", err)
	}

	outsideDir := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(root, "escape")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	outsideFile := filepath.Join(outsideDir, "stolen.json")
	if err := os.WriteFile(outsideFile, []byte("{}"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	ctx := context.Background()
	if err := store.Put(ctx, "escape/payload.json", strings.NewReader("{}"), "application/json"); !errors.Is(err, errInvalidKey) {
		t.Fatalf("Put() error = %v, want errInvalidKey", err)
	}
	if _, err := store.Get(ctx, "escape/stolen.json"); !errors.Is(err, errInvalidKey) {
		t.Fatalf("Get() error = %v, want errInvalidKey", err)
	}
	if _, err := store.Exists(ctx, "escape/stolen.json"); !errors.Is(err, errInvalidKey) {
		t.Fatalf("Exists() error = %v, want errInvalidKey", err)
	}
	if err := store.Delete(ctx, "escape/stolen.json"); !errors.Is(err, errInvalidKey) {
		t.Fatalf("Delete() error = %v, want errInvalidKey", err)
	}
}

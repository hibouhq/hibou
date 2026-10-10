package objstore

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFilesystemInventory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for key, body := range map[string]string{"a/one.json": "1234", "a/b/two.json": "123456", "three": "1"} {
		if err := store.Put(ctx, key, strings.NewReader(body), ""); err != nil {
			t.Fatal(err)
		}
	}
	// A symlink out of the store is neither followed nor counted.
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte(strings.Repeat("x", 1000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store.baseResolved, "link")); err != nil {
		t.Fatal(err)
	}

	inv, err := store.Inventory(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Objects != 3 || inv.Bytes != 11 || inv.Truncated {
		t.Fatalf("inventory = %+v, want 3 objects / 11 bytes", inv)
	}
	if runtime.GOOS == "linux" && (inv.Volume == nil || inv.Volume.CapacityBytes <= 0 || inv.Volume.FreeBytes < 0) {
		t.Fatalf("volume = %+v, want capacity on linux", inv.Volume)
	}

	capped, err := store.Inventory(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if capped.Objects != 2 || !capped.Truncated {
		t.Fatalf("capped inventory = %+v, want 2 objects, truncated", capped)
	}
}

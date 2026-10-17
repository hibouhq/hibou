package depinventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestProbeCorpus prints what the engine returns per case; it is the tool
// used to write expected.json files, kept so a SCALIBR upgrade can be
// re-checked by eye. Run with DEPINVENTORY_PROBE=1.
func TestProbeCorpus(t *testing.T) {
	if os.Getenv("DEPINVENTORY_PROBE") == "" {
		t.Skip("probe")
	}
	if root := os.Getenv("DEPINVENTORY_PROBE_ROOT"); root != "" {
		inv, err := Extract(context.Background(), root, Options{})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("== %s: %d components, %d modules, %s\n", root, len(inv.Components), len(inv.Modules), inv.Duration)
		for _, m := range inv.Modules {
			fmt.Printf("   module %s complete=%v files=%v\n", m.Path, m.Complete, m.Files)
		}
		for _, e := range inv.FileErrors {
			fmt.Printf("   file error: %s\n", e)
		}
		return
	}
	entries, err := os.ReadDir("testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		inv, err := Extract(context.Background(), filepath.Join("testdata/corpus", entry.Name()), Options{})
		if err != nil {
			t.Errorf("%s: %v", entry.Name(), err)
			continue
		}
		fmt.Printf("== %s (%d components, %d modules, %s)\n", entry.Name(), len(inv.Components), len(inv.Modules), inv.Duration)
		for _, m := range inv.Modules {
			fmt.Printf("   module %s complete=%v %s files=%v\n", m.Path, m.Complete, m.Reason, m.Files)
		}
		sort.Slice(inv.Components, func(i, j int) bool { return inv.Components[i].Purl < inv.Components[j].Purl })
		for _, c := range inv.Components {
			fmt.Printf("   %-60s %-9s %-9s scopes=%v %s:%d [%s]\n", c.Purl, c.Relationship, c.Resolution, c.Scopes, c.Path, c.Line, c.Extractor)
		}
		for _, e := range inv.FileErrors {
			fmt.Printf("   file error: %s\n", e)
		}
	}
}

package depinventory

import (
	"context"
	"crypto/sha1" // #nosec G505 -- the index key under test
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMavenCentralLookupIdentifiesJars(t *testing.T) {
	root := t.TempDir()
	writeJar(t, filepath.Join(root, "lib", "mystery.jar"), map[string]string{"com/x/Y.class": "\xca\xfe\xba\xbe"})
	writeJar(t, filepath.Join(root, "lib", "unknown.jar"), map[string]string{"com/z/Z.class": "\xca\xfe\xba\xbe"})
	data, _ := os.ReadFile(filepath.Join(root, "lib", "mystery.jar"))
	sum := sha1.Sum(data) // #nosec G401 -- the index key under test
	known := hex.EncodeToString(sum[:])

	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("q"))
		if r.URL.Path != "/solrsearch/select" {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.URL.Query().Get("q"), known) {
			_, _ = w.Write([]byte(`{"response":{"numFound":1,"docs":[{"g":"org.example","a":"mystery","v":"2.0.1"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"response":{"numFound":0,"docs":[]}}`))
	}))
	defer server.Close()

	jars := []string{filepath.Join(root, "lib", "mystery.jar"), filepath.Join(root, "lib", "unknown.jar")}
	inv, err := ScanTargets(context.Background(), jars, ScanOptions{JarLookup: MavenCentralLookup(server.URL, server.Client())})
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 {
		t.Errorf("queries %v, want one per jar", queries)
	}
	var found *Component
	for i := range inv.Components {
		if inv.Components[i].Extractor == ExtractorMavenCentral {
			found = &inv.Components[i]
		}
	}
	if found == nil {
		t.Fatalf("no component identified by hash: %+v", inv.Components)
	}
	if found.Purl != "pkg:maven/org.example/mystery@2.0.1" || found.Name != "org.example:mystery" || found.Resolution != ResolutionArtifact || !strings.HasSuffix(found.Path, "lib/mystery.jar") {
		t.Errorf("identified %+v", found)
	}
	if inv.UnidentifiedCount != 1 || !strings.HasSuffix(inv.Unidentified[0].Path, "unknown.jar") {
		t.Errorf("unidentified %+v", inv.Unidentified)
	}

	// Without the opt-in nothing is sent and both jars stay unidentified.
	queries = nil
	inv, err = ScanTargets(context.Background(), jars, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 0 || inv.UnidentifiedCount != 2 {
		t.Errorf("without opt-in: queries %v unidentified %d", queries, inv.UnidentifiedCount)
	}
}

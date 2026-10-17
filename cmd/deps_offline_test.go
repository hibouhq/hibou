package cmd

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/advisorydb"
	"github.com/hibouhq/hibou/internal/depinventory"
)

func writeTestJar(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(content))
	}
	_ = w.Close()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --advisory-db matches locally with the exported database and says what
// it cannot know.
func TestMatchRowsOffline(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "advisories.ndjson")
	f, err := os.Create(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	w, err := advisorydb.NewWriter(f, advisorydb.Header{ExportedAt: time.Now().Add(-10 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	score := 7.5
	if err := w.Write(advisorydb.Record{ID: "a1", CanonicalID: "GHSA-test", Title: "Test", KEV: true,
		Ratings: []advisorydb.Rating{{Rater: "nvd", Score: &score, Version: "v3.1"}},
		Ranges:  []advisorydb.Range{{Ecosystem: "maven", Package: "com.fasterxml.jackson.core:jackson-databind", Introduced: "0", Fixed: "2.15.3"}}}); err != nil {
		t.Fatal(err)
	}
	_ = w.Flush()
	_ = f.Close()

	report := &scanReport{Rows: []scanRow{
		{Component: depinventory.Component{Purl: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.2", Name: "com.fasterxml.jackson.core:jackson-databind", Version: "2.15.2", Ecosystem: "maven"}},
		{Component: depinventory.Component{Purl: "pkg:maven/org.example/fine@1.0.0", Name: "org.example:fine", Version: "1.0.0", Ecosystem: "maven"}},
		{Component: depinventory.Component{Purl: "pkg:maven/org.example/range", Name: "org.example:range", Ecosystem: "maven", Resolution: depinventory.ResolutionUnresolved}},
	}}
	var warnings []string
	if err := matchRowsOffline(report, dbPath, func(m string) { warnings = append(warnings, m) }); err != nil {
		t.Fatal(err)
	}
	if !report.Matched || report.AdvisoryDB != dbPath || report.AdvisoryDBAdvisories != 1 {
		t.Errorf("report %+v", report)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "re-export") {
		t.Errorf("a 10-day-old database must warn: %v", warnings)
	}
	jackson := report.Rows[0]
	if !jackson.Supported || len(jackson.Advisories) != 1 || jackson.Advisories[0].CanonicalID != "GHSA-test" || !jackson.Advisories[0].KEV || jackson.Advisories[0].Severity != "high" || len(jackson.Advisories[0].FixedVersions) != 1 {
		t.Errorf("jackson %+v", jackson)
	}
	if fine := report.Rows[1]; !fine.Supported || len(fine.Advisories) != 0 {
		t.Errorf("fine %+v", fine)
	}
	if unresolved := report.Rows[2]; unresolved.Supported || unresolved.Advisories != nil {
		t.Errorf("an unresolved range is never matched: %+v", unresolved)
	}
	summary := summarize(report)
	if summary.Vulnerable != 1 || summary.KEV != 1 || summary.High != 1 {
		t.Errorf("summary %+v", summary)
	}
}

// verify unwraps an attestation, checks its signature with the key and
// its subject against the deliverable.
func TestVerifyDeliverableAttestation(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "app.jar")
	writeTestJar(t, jar, map[string]string{
		"META-INF/MANIFEST.MF":                          "Manifest-Version: 1.0\n",
		"META-INF/maven/org.example/app/pom.properties": "groupId=org.example\nartifactId=app\nversion=1.0.0\n",
	})
	data, _ := os.ReadFile(jar)
	sum := sha256.Sum256(data)
	sbom, _ := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"components": []map[string]any{{"type": "library", "name": "app", "group": "org.example", "version": "1.0.0", "purl": "pkg:maven/org.example/app@1.0.0"}}})
	statement, _ := json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://cyclonedx.org/bom",
		"subject":   []map[string]any{{"name": "app.jar", "digest": map[string]string{"sha256": hex.EncodeToString(sum[:])}}},
		"predicate": json.RawMessage(sbom),
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payloadType := "application/vnd.in-toto+json"
	pae := "DSSEv1 " + itoa(len(payloadType)) + " " + payloadType + " " + itoa(len(statement)) + " " + string(statement)
	digest := sha256.Sum256([]byte(pae))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(map[string]any{"payloadType": payloadType, "payload": base64.StdEncoding.EncodeToString(statement), "signatures": []map[string]string{{"sig": base64.StdEncoding.EncodeToString(sig)}}})
	attPath := filepath.Join(dir, "app.intoto.json")
	if err := os.WriteFile(attPath, envelope, 0o644); err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	keyPath := filepath.Join(dir, "cosign.pub")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := verifyDeliverable(context.Background(), jar, attPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Signature != "verified" || result.Integrity != "ok" || result.PredicateType != "https://cyclonedx.org/bom" || result.Matched != 1 || len(result.Undeclared) != 0 {
		t.Errorf("verified result %+v", result)
	}
	// Without the key the signature is not checked but everything else is.
	result, err = verifyDeliverable(context.Background(), jar, attPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Signature, "not checked") || result.Integrity != "ok" {
		t.Errorf("no key: %+v", result)
	}
	// Another key: invalid; a different deliverable: integrity mismatch.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	otherPath := filepath.Join(dir, "other.pub")
	_ = os.WriteFile(otherPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}), 0o644)
	result, err = verifyDeliverable(context.Background(), jar, attPath, otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Signature, "invalid") {
		t.Errorf("other key: %+v", result)
	}
	tampered := filepath.Join(dir, "tampered.jar")
	writeTestJar(t, tampered, map[string]string{"META-INF/maven/org.example/app/pom.properties": "groupId=org.example\nartifactId=app\nversion=1.0.0\n", "extra": "x"})
	result, err = verifyDeliverable(context.Background(), tampered, attPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Integrity != "mismatch" || result.Signature != "verified" {
		t.Errorf("tampered deliverable: %+v", result)
	}
	// A plain SBOM reports no signature.
	plain := filepath.Join(dir, "app.cdx.json")
	_ = os.WriteFile(plain, sbom, 0o644)
	result, err = verifyDeliverable(context.Background(), jar, plain, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Signature != "none" {
		t.Errorf("plain SBOM: %+v", result)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

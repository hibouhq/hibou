package delta

import (
	"testing"

	"github.com/hibouhq/hibou/internal/store"
)

func identityStr(s string) *string { return &s }
func identityLine(i int32) *int32  { return &i }

// The same finding whose fingerprint drifted between snapshots (scanner rename,
// fingerprint algorithm change) must cancel out instead of reading as both new
// and resolved.
func TestCancelIdentityPairs(t *testing.T) {
	oldRow := store.Vulnerability{
		Type: "sast", ScannerName: "Trivy", PrimaryIdentifierValue: "CVE-2026-2950",
		FilePath: identityStr("ts/package-lock.json"), StartLine: identityLine(1550), Fingerprint: "old-fp",
	}
	newRow := oldRow
	newRow.ScannerName = "trivy"
	newRow.Fingerprint = "new-fp"

	genuinelyNew := store.Vulnerability{
		Type: "sast", ScannerName: "gosec", PrimaryIdentifierValue: "G402",
		FilePath: identityStr("go/insecure_net.go"), StartLine: identityLine(23), Fingerprint: "g402-fp",
	}
	genuinelyResolved := store.Vulnerability{
		Type: "dependency", ScannerName: "trivy", PrimaryIdentifierValue: "CVE-2019-11253",
		ComponentPurl: identityStr("pkg:golang/gopkg.in/yaml.v2@v2.2.2"), Fingerprint: "yaml-fp",
	}

	keptNew, keptResolved := cancelIdentityPairs(
		[]store.Vulnerability{newRow, genuinelyNew},
		[]store.Vulnerability{oldRow, genuinelyResolved},
	)

	if len(keptNew) != 1 || keptNew[0].PrimaryIdentifierValue != "G402" {
		t.Fatalf("keptNew = %+v", keptNew)
	}
	if len(keptResolved) != 1 || keptResolved[0].PrimaryIdentifierValue != "CVE-2019-11253" {
		t.Fatalf("keptResolved = %+v", keptResolved)
	}
}

func TestCancelIdentityPairsKeepsDistinctLines(t *testing.T) {
	a := store.Vulnerability{Type: "sast", ScannerName: "gosec", PrimaryIdentifierValue: "G101", FilePath: identityStr("a.go"), StartLine: identityLine(10), Fingerprint: "f1"}
	b := a
	b.StartLine = identityLine(20)
	b.Fingerprint = "f2"
	keptNew, keptResolved := cancelIdentityPairs([]store.Vulnerability{a}, []store.Vulnerability{b})
	if len(keptNew) != 1 || len(keptResolved) != 1 {
		t.Fatalf("distinct lines must not cancel: new=%d resolved=%d", len(keptNew), len(keptResolved))
	}
}

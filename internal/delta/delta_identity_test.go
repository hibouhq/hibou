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

func driftSet(rows ...store.Vulnerability) map[string]store.Vulnerability {
	return uniqueVulnerabilities(rows)
}

// A finding without a scanner fingerprint moves when code is added above it:
// the line-based fallback re-keys it, which must not read as new + fixed.
func TestCancelLineDriftPairs(t *testing.T) {
	old := store.Vulnerability{Type: "sast", ScannerName: "gosec", PrimaryIdentifierValue: "G304", Description: "Potential file inclusion via variable", FilePath: identityStr("io.go"), StartLine: identityLine(10), Fingerprint: "at-10"}
	moved := old
	moved.StartLine = identityLine(14)
	moved.Fingerprint = "at-14"

	keptNew, keptResolved := cancelLineDriftPairs([]store.Vulnerability{moved}, []store.Vulnerability{old}, driftSet(moved), driftSet(old))
	if len(keptNew) != 0 || len(keptResolved) != 0 {
		t.Fatalf("moved finding must cancel: new=%d resolved=%d", len(keptNew), len(keptResolved))
	}
}

// Two hits of one rule in one file: which one moved cannot be told, so
// nothing pairs and the delta stays conservative.
func TestCancelLineDriftPairsNeedsOneToOne(t *testing.T) {
	base := store.Vulnerability{Type: "sast", ScannerName: "gosec", PrimaryIdentifierValue: "G101", Description: "Potential hardcoded credentials", FilePath: identityStr("a.go")}
	a10, a20, a30 := base, base, base
	a10.StartLine, a10.Fingerprint = identityLine(10), "f10"
	a20.StartLine, a20.Fingerprint = identityLine(20), "f20"
	a30.StartLine, a30.Fingerprint = identityLine(30), "f30"

	// target {10, 20}, PR {20, 30}: 10 resolved, 30 new, but the key is not unique.
	keptNew, keptResolved := cancelLineDriftPairs([]store.Vulnerability{a30}, []store.Vulnerability{a10}, driftSet(a20, a30), driftSet(a10, a20))
	if len(keptNew) != 1 || len(keptResolved) != 1 {
		t.Fatalf("ambiguous drift must not cancel: new=%d resolved=%d", len(keptNew), len(keptResolved))
	}
}

func TestCancelLineDriftPairsKeepsDifferentMessagesAndUnlocated(t *testing.T) {
	old := store.Vulnerability{Type: "sast", ScannerName: "gosec", PrimaryIdentifierValue: "G104", Description: "Errors unhandled", FilePath: identityStr("x.go"), StartLine: identityLine(5), Fingerprint: "x5"}
	other := old
	other.Description = "Errors unhandled in deferred call"
	other.StartLine, other.Fingerprint = identityLine(9), "x9"
	dep := store.Vulnerability{Type: "dependency", ScannerName: "trivy", PrimaryIdentifierValue: "CVE-1", ComponentPurl: identityStr("pkg:npm/a@1"), Fingerprint: "d1"}
	dep2 := dep
	dep2.Fingerprint = "d2"

	keptNew, keptResolved := cancelLineDriftPairs([]store.Vulnerability{other, dep2}, []store.Vulnerability{old, dep}, driftSet(other, dep2), driftSet(old, dep))
	if len(keptNew) != 2 || len(keptResolved) != 2 {
		t.Fatalf("different message / unlocated rows must not cancel: new=%d resolved=%d", len(keptNew), len(keptResolved))
	}
}

func TestRekeyedPairs(t *testing.T) {
	sameLineOld := store.Vulnerability{Type: "sast", ScannerName: "gosec", PrimaryIdentifierValue: "G101", Description: "creds", FilePath: identityStr("a.go"), StartLine: identityLine(3), Fingerprint: "ref-scoped"}
	sameLineNew := sameLineOld
	sameLineNew.Fingerprint = "content-hash"
	movedOld := store.Vulnerability{Type: "sast", ScannerName: "gosec", PrimaryIdentifierValue: "G304", Description: "inclusion", FilePath: identityStr("b.go"), StartLine: identityLine(10), Fingerprint: "b10"}
	movedNew := movedOld
	movedNew.StartLine, movedNew.Fingerprint = identityLine(15), "b15"
	stable := store.Vulnerability{Type: "sast", ScannerName: "opengrep", PrimaryIdentifierValue: "r", FilePath: identityStr("c.go"), StartLine: identityLine(1), Fingerprint: "stable"}
	fixed := store.Vulnerability{Type: "sast", ScannerName: "gosec", PrimaryIdentifierValue: "G104", Description: "errs", FilePath: identityStr("d.go"), StartLine: identityLine(7), Fingerprint: "d7"}

	pairs := RekeyedPairs(
		[]store.Vulnerability{sameLineOld, movedOld, stable, fixed},
		[]store.Vulnerability{sameLineNew, movedNew, stable},
	)
	got := map[string]string{}
	for _, pair := range pairs {
		got[pair.Old.Fingerprint] = pair.New.Fingerprint
	}
	if len(got) != 2 || got["ref-scoped"] != "content-hash" || got["b10"] != "b15" {
		t.Fatalf("pairs = %v", got)
	}
}

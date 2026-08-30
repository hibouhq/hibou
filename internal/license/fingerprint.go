package license

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Fingerprint identifies one license violation stably enough to hang a waiver
// on. It is deliberately (purl, license) and NOT (purl, version, license):
// including the version would revoke the waiver on every patch bump, so a
// dependency someone reviewed and accepted would re-break the gate on an
// unrelated upgrade. The trade is that a package whose license CHANGES between
// versions keeps its waiver — acceptable because the license atom is part of the
// key, so a change to a different denied license produces a different
// fingerprint and re-fires the gate.
//
// The "license:" prefix namespaces these against SAST and secret fingerprints
// sharing the finding_acceptances table.
func Fingerprint(purl, licenseID string) string {
	sum := sha256.Sum256([]byte("license:" + strings.ToLower(strings.TrimSpace(purl)) + ":" + strings.ToLower(NormalizeID(licenseID))))
	return hex.EncodeToString(sum[:])
}

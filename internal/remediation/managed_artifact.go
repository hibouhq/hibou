package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// ErrManagedExecutionUnavailable is deliberately independent of controller
// heartbeats: a retired executor must not reactivate an unapproved backend.
var ErrManagedExecutionUnavailable = errors.New("managed Kubernetes execution is disabled; configure the approved ADR-056 workload profile and controller")

func ValidateManagedArtifact(request ManagedInput, a *Artifact) error {
	if a == nil || a.BaseSHA != request.BaseSHA || len(a.Patch) == 0 || len(a.Patch) > MaxPatchBytes ||
		len(a.Changes) == 0 || len(a.Verification) != len(request.Units) || len(a.Units) != len(request.Units) {
		return errors.New("isolated executor returned an incomplete artifact")
	}
	sum := sha256.Sum256(a.Patch)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return errors.New("artifact patch digest mismatch")
	}
	for _, v := range a.Verification {
		if !v.DependencyFilesConsistent || !v.SelectedVulnsAddressed || !v.NoIntroducedVulns {
			return errors.New("isolated executor did not verify every selected unit")
		}
	}
	writable := map[string]bool{}
	for _, u := range request.Units {
		for _, file := range u.WritableFiles {
			writable[file] = true
		}
	}
	seen := map[string]bool{}
	for _, change := range a.Changes {
		if !safePath(change.Path) || !writable[change.Path] || seen[change.Path] || len(change.Before) != 64 || len(change.After) != 64 {
			return errors.New("artifact changes escape selected verified dependency files")
		}
		seen[change.Path] = true
	}
	for i, u := range request.Units {
		if a.Units[i].ID != u.ID {
			return errors.New("artifact units differ from selected draft")
		}
	}
	return nil
}

func ValidateManagedFiles(a *Artifact, files map[string][]byte) error {
	if a == nil || len(files) != len(a.Changes) {
		return errors.New("complete publication files are missing")
	}
	var total int
	for _, change := range a.Changes {
		data, exists := files[change.Path]
		if !exists || len(data) > MaxFileBytes {
			return errors.New("publication file missing or oversized")
		}
		total += len(data)
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != change.After {
			return errors.New("publication file digest mismatch")
		}
	}
	if total > MaxInputBytes {
		return errors.New("publication files exceed size limit")
	}
	return nil
}

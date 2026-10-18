package forge

import (
	"errors"
	"fmt"
	"strings"
)

// WriteBranchPrefix is the only branch namespace Hibou writes to (ADR-052
// §1): onboarding uses hibou/configure, remediation hibou/fix/... A write to
// any other branch is refused before the forge is called, so a bug or a
// confused-deputy path cannot touch a default, release or feature branch,
// and the forge's rulesets can confine the App to this one prefix.
const WriteBranchPrefix = "hibou/"

// ErrBranchOutsideNamespace is a write refused because its branch is not
// under WriteBranchPrefix.
var ErrBranchOutsideNamespace = errors.New("forge: Hibou only writes to branches under " + WriteBranchPrefix)

// CheckWriteBranch accepts a branch Hibou may create, commit to, or open a
// pull request from.
func CheckWriteBranch(branch string) error {
	name := strings.TrimSpace(branch)
	rest, ok := strings.CutPrefix(name, WriteBranchPrefix)
	if !ok || name != branch || rest == "" || strings.Contains(name, "..") ||
		strings.HasSuffix(name, "/") || strings.ContainsAny(name, " ~^:?*[\\") {
		return fmt.Errorf("%w: %q", ErrBranchOutsideNamespace, branch)
	}
	return nil
}

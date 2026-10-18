package forge

import "context"

// Confinement checks answer one question per repository Hibou's forge
// identity can reach (ADR-052): could it write anywhere other than its own
// hibou/* branches? Hibou's code never does (CheckWriteBranch); these checks
// look at what the forge itself would allow, which is what bounds a stolen
// key or token.

// ConfinementSeverity orders findings for display.
type ConfinementSeverity string

const (
	// ConfinementOK: the identity cannot write outside hibou/* here.
	ConfinementOK ConfinementSeverity = "ok"
	// ConfinementInfo: nothing wrong, or nothing Hibou can verify.
	ConfinementInfo ConfinementSeverity = "info"
	// ConfinementWarning: Hibou's own branches are blocked, or a weaker
	// bypass applies.
	ConfinementWarning ConfinementSeverity = "warning"
	// ConfinementError: the identity can write outside hibou/*.
	ConfinementError ConfinementSeverity = "error"
)

// Finding codes, stable for the API and the UI.
const (
	ConfinementCodeNoWrite       = "no_write_permission"
	ConfinementCodeUnrestricted  = "other_branches_unrestricted"
	ConfinementCodeBypass        = "identity_can_bypass"
	ConfinementCodeBypassPR      = "identity_can_bypass_via_pull_requests"
	ConfinementCodeDefaultBranch = "default_branch_unprotected"
	// ConfinementCodeAdmin: the identity administers the repository, so it
	// can change or delete the rules that confine it.
	ConfinementCodeAdmin            = "identity_is_admin"
	ConfinementCodeNamespaceBlocked = "hibou_branches_blocked"
	ConfinementCodeClassic          = "classic_protection_unverifiable"
	ConfinementCodeUnverifiable     = "unverifiable"
	ConfinementCodeNoServerToken    = "no_server_token"
)

// ConfinementFinding is one result for one repository (or the whole forge
// when Repository is empty).
type ConfinementFinding struct {
	Repository string              `json:"repository,omitempty"`
	Severity   ConfinementSeverity `json:"severity"`
	Code       string              `json:"code"`
	Message    string              `json:"message"`
	// Ruleset names the forge rule involved, when there is one.
	Ruleset string `json:"ruleset,omitempty"`
}

// ConfinementChecker is implemented by providers that can check their own
// reach.
type ConfinementChecker interface {
	CheckConfinement(ctx context.Context) ([]ConfinementFinding, error)
}

// withAdminFinding adds an admin finding to one repository's findings and
// drops its "confined" result: rules an identity can delete do not confine it.
func withAdminFinding(findings []ConfinementFinding, admin ConfinementFinding) []ConfinementFinding {
	return append([]ConfinementFinding{admin}, withoutConfined(findings)...)
}

func withoutConfined(findings []ConfinementFinding) []ConfinementFinding {
	out := findings[:0:0]
	for _, finding := range findings {
		if finding.Severity == ConfinementOK && finding.Code == ConfinementCodeNoWrite {
			continue
		}
		out = append(out, finding)
	}
	return out
}

// confinementProbeOutside is a branch name outside the namespace, used to
// ask the forge which rules would apply to any other branch. It need not
// exist.
const confinementProbeOutside = "hibou-confinement-probe"

// confinementProbeOutsideNested is the same with a "/": on Forgejo a "*"
// rule stops at "/", so it must be probed separately.
const confinementProbeOutsideNested = "hibou-confinement/probe"

// confinementProbeInside is a branch name inside the namespace.
const confinementProbeInside = WriteBranchPrefix + "confinement-probe"

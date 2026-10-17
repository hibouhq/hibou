package mcp

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/packagepolicy"
)

// check_packages (ADR-048 §7): what an agent asks before adding or
// upgrading a dependency. Same shape as the public deps.dev skill, with
// what that skill cannot know: the organization's cooldown window and
// private namespaces, its acceptances, and no outbound call from the
// developer's machine. Private packages are answered "not evaluated"
// instead of a false "not found".

const maxCheckPackages = 200

var checkPackagesTool = mcp.NewTool("check_packages",
	mcp.WithDescription("Check package versions before adding or upgrading them: release cooldown (a fresh version to wait on), malicious or unpublished versions, deprecation and low-usage look-alikes, under the organization's policy and acceptances. Call it BEFORE any new package is imported or added to dependencies. Each decision is allow, hold (with until) or deny, with a reason; evaluated=false means hibou could not say (private namespace, uncovered ecosystem, provider off), which is not a clean bill."+untrustedNote),
	mcp.WithString("org", mcp.Required(), mcp.Description("Organization slug, e.g. github/acme")),
	mcp.WithString("repo", mcp.Description("Repository slug, for its acceptances and policy")),
	mcp.WithArray("purls", mcp.Required(), mcp.Description("Package URLs with a version, e.g. pkg:npm/express@5.3.0, pkg:pypi/requests@2.32.3, pkg:maven/org.apache.logging.log4j/log4j-core@2.24.3, pkg:golang/golang.org/x/net@v0.33.0"), mcp.WithStringItems()),
)

func (s *service) handleCheckPackages(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	orgArg, ok := stringArg(request, "org")
	if !ok {
		return toolError("org is required")
	}
	purls := request.GetStringSlice("purls", nil)
	if len(purls) == 0 {
		return toolError("purls is required: at least one package URL with a version")
	}
	if len(purls) > maxCheckPackages {
		return toolError("at most 200 purls per call")
	}
	org, access, err := s.resolveOrgAndAuth(ctx, orgArg)
	if err != nil {
		return toolError(err.Error())
	}
	if err := requireOrgWideCapability(ctx, apitoken.CapComponents, apitoken.AccessRead, org.Slug); err != nil {
		return toolError(err.Error())
	}
	var repoID *uuid.UUID
	repoArg := strings.TrimSpace(request.GetString("repo", ""))
	if repoArg != "" {
		repo, err := s.store.GetRepositoryBySlug(ctx, org.ID, repoArg)
		if err != nil || repo == nil {
			return toolError(errNotFoundOrNoAccess.Error())
		}
		if !access.Allows(repo.ID) {
			return toolError(errNotFoundOrNoAccess.Error())
		}
		repoID = &repo.ID
	} else if access.Scoped {
		return toolError(errOrgWideDenied.Error())
	}

	// The repository's .hibou.yaml window is not read here: the policy
	// endpoint has it, this tool applies the instance default. An agent
	// wanting the exact gate answer runs the CI step.
	policy := s.policy.DefaultPolicy()
	decisions, err := s.policy.Evaluate(ctx, packagepolicy.Request{OrgID: org.ID, RepoID: repoID, Purls: purls, Policy: policy})
	if err != nil {
		s.log.Error().Err(err).Str("org_id", org.ID.String()).Msg("check_packages evaluation failed")
		return toolError("failed to evaluate package policy")
	}
	holds, denies := 0, 0
	for _, d := range decisions {
		switch d.Decision {
		case packagepolicy.DecisionHold:
			holds++
		case packagepolicy.DecisionDeny:
			denies++
		}
	}
	return toolJSON(map[string]any{
		"organization": orgArg,
		"repo":         repoArg,
		"window":       policy.WindowMode,
		"summary":      map[string]int{"checked": len(decisions), "holds": holds, "denies": denies},
		"decisions":    decisions,
		"note":         "allow with evaluated=false means not checked, not clean. A hold ends on its own at `until`; an organization admin can record an acceptance for an exact version.",
	})
}

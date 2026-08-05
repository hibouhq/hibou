package mcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
)

// scopedTool binds a tool to the capability a scoped API token must hold to
// call it (ADR-020). Registration goes through this type so a new tool cannot
// reach the transport without declaring one — the MCP twin of the HTTP
// routeScopes table. The wrapper is the coarse gate; handlers still bind the
// resolved org and repository, which only they can resolve from the arguments.
type scopedTool struct {
	tool       mcp.Tool
	capability apitoken.Capability
	level      apitoken.AccessLevel
	handler    server.ToolHandlerFunc
}

func (t scopedTool) register() server.ServerTool {
	return server.ServerTool{
		Tool: t.tool,
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if err := requireCapability(ctx, t.capability, t.level, "", ""); err != nil {
				return toolError(err.Error())
			}
			return t.handler(ctx, request)
		},
	}
}

func registerScopedTools(mcpSrv *server.MCPServer, tools []scopedTool) {
	registered := make([]server.ServerTool, 0, len(tools))
	for _, tool := range tools {
		registered = append(registered, tool.register())
	}
	mcpSrv.AddTools(registered...)
}

// The denial names the missing grant (ADR-020): agents parse these errors, and
// "requires components:read" is actionable where a generic refusal is a dead
// end. Capability names are public API vocabulary — nothing is leaked.
func requireCapability(ctx context.Context, cap apitoken.Capability, need apitoken.AccessLevel, org, repoSlug string) error {
	err := auth.RequireCapability(ctx, cap, need, org, repoSlug)
	if errors.Is(err, auth.ErrTokenScopeDenied) {
		return fmt.Errorf("token scope does not permit this action (requires %s:%s%s)", cap, need, scopeTarget(org, repoSlug))
	}
	return err
}

func requireOrgWideCapability(ctx context.Context, cap apitoken.Capability, need apitoken.AccessLevel, org string) error {
	err := auth.RequireOrgWideCapability(ctx, cap, need, org)
	if errors.Is(err, auth.ErrTokenScopeDenied) {
		return fmt.Errorf("token scope does not permit this action (requires %s:%s across every repository in %s — repos.mode=all)", cap, need, org)
	}
	return err
}

func scopeTarget(org, repoSlug string) string {
	if org == "" {
		return ""
	}
	if repoSlug == "" {
		return " on " + org
	}
	return " on " + org + "/" + repoSlug
}

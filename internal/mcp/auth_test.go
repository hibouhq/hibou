package mcp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
)

func scopedToolContext(t *testing.T, scope apitoken.Scope, scoped bool) context.Context {
	t.Helper()

	return auth.WithTokenAuth(context.Background(), &auth.TokenAuth{KeyID: uuid.New(), Scope: scope, Scoped: scoped})
}

func TestScopedToolEnforcesDeclaredCapability(t *testing.T) {
	t.Parallel()

	readOnly := apitoken.Scope{
		Org:         "acme",
		Repos:       apitoken.RepoSelector{Mode: apitoken.RepoAll},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapComponents: apitoken.AccessRead},
	}

	tests := []struct {
		name    string
		ctx     context.Context
		reached bool
	}{
		{"granted capability", scopedToolContext(t, readOnly, true), true},
		{"missing capability", scopedToolContext(t, apitoken.Scope{Org: "acme"}, true), false},
		{"unscoped legacy token", scopedToolContext(t, apitoken.Scope{}, false), true},
		{"no token auth", context.Background(), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reached := false
			tool := scopedTool{
				tool:       getDependencyTreeTool,
				capability: apitoken.CapComponents,
				level:      apitoken.AccessRead,
				handler: func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					reached = true
					return mcp.NewToolResultText("ok"), nil
				},
			}

			result, err := tool.register().Handler(tc.ctx, mcp.CallToolRequest{})
			if err != nil {
				t.Fatalf("handler error = %v", err)
			}
			if reached != tc.reached {
				t.Fatalf("handler reached = %v, want %v", reached, tc.reached)
			}
			if !tc.reached && !result.IsError {
				t.Fatal("denied call did not return a tool error")
			}
		})
	}
}

func TestScopedToolDeniesWriteWithReadGrant(t *testing.T) {
	t.Parallel()

	scope := apitoken.Scope{
		Org:         "acme",
		Repos:       apitoken.RepoSelector{Mode: apitoken.RepoAll},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapTriage: apitoken.AccessRead},
	}
	tool := scopedTool{
		tool:       listVulnerabilitiesTool,
		capability: apitoken.CapTriage,
		level:      apitoken.AccessWrite,
		handler: func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			t.Fatal("write tool reached with a read-only grant")
			return nil, nil
		},
	}

	result, err := tool.register().Handler(scopedToolContext(t, scope, true), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handler error = %v", err)
	}
	if !result.IsError {
		t.Fatal("denied call did not return a tool error")
	}
}

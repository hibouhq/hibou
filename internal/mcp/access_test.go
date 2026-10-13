package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// accessStore serves one org with two repositories; the user's role and
// repository grants are configurable.
type accessStore struct {
	MCPStore
	org    *store.Organization
	repos  map[string]*store.Repository
	role   string
	scoped bool
	grants map[uuid.UUID]string
}

func (s *accessStore) GetOrganizationByProviderAndSlug(_ context.Context, provider, slug string) (*store.Organization, error) {
	if provider+"/"+slug == s.org.Provider+"/"+s.org.Slug {
		return s.org, nil
	}
	return nil, nil
}

func (s *accessStore) GetOrgMemberRole(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	return s.role, nil
}

func (s *accessStore) IsRepoScopedOrgMember(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return s.scoped, nil
}

func (s *accessStore) ListUserRepoAccessInOrg(context.Context, uuid.UUID, uuid.UUID) (map[uuid.UUID]string, error) {
	return s.grants, nil
}

func (s *accessStore) GetRepositoryBySlug(_ context.Context, _ uuid.UUID, slug string) (*store.Repository, error) {
	return s.repos[slug], nil
}

func (s *accessStore) GetRefByRepoAndName(_ context.Context, repoID uuid.UUID, name string, refType store.RefType) (*store.Ref, error) {
	if name != "main" || refType != store.RefTypeBranch {
		return nil, nil
	}
	return &store.Ref{ID: repoID, RepoID: repoID, Name: name}, nil
}

func (s *accessStore) GetLatestSnapshotByRef(_ context.Context, refID uuid.UUID) (*store.Snapshot, error) {
	return &store.Snapshot{ID: refID, RefID: refID}, nil
}

func (s *accessStore) ListComponentsBySnapshotWithVulns(context.Context, uuid.UUID) ([]dbgen.ListComponentsBySnapshotWithVulnsRow, error) {
	rows := make([]dbgen.ListComponentsBySnapshotWithVulnsRow, maxListItems+20)
	for i := range rows {
		rows[i] = dbgen.ListComponentsBySnapshotWithVulnsRow{ID: uuid.New(), Name: "pkg"}
	}
	return rows, nil
}

func newAccessService() (*service, *accessStore) {
	org := &store.Organization{ID: uuid.New(), Provider: "github", Slug: "acme"}
	st := &accessStore{
		org:  org,
		role: "viewer",
		repos: map[string]*store.Repository{
			"granted": {ID: uuid.New(), OrgID: org.ID, Slug: "granted", DefaultBranch: "main"},
			"secret":  {ID: uuid.New(), OrgID: org.ID, Slug: "secret", DefaultBranch: "main"},
		},
	}
	return &service{store: st, log: zerolog.Nop()}, st
}

func callTool(t *testing.T, handler func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error), args map[string]any) (string, bool) {
	t.Helper()
	ctx := withUser(context.Background(), &store.User{ID: uuid.New()})
	request := mcp.CallToolRequest{}
	request.Params.Arguments = args
	result, err := handler(ctx, request)
	if err != nil {
		t.Fatalf("handler error = %v", err)
	}
	var text strings.Builder
	for _, content := range result.Content {
		if tc, ok := content.(mcp.TextContent); ok {
			text.WriteString(tc.Text)
		}
	}
	return text.String(), result.IsError
}

// P4: MCP applies the HTTP API's repository scoping: a collaborator reaches
// granted repositories only, gets one answer for "missing" and "not yours",
// and no org-wide tool.
func TestMCPAppliesRepositoryScoping(t *testing.T) {
	t.Parallel()

	svc, st := newAccessService()
	st.scoped = true
	st.grants = map[uuid.UUID]string{st.repos["granted"].ID: "viewer"}

	if _, isErr := callTool(t, svc.handleGetDependencyTree, map[string]any{"org": "github/acme", "repo": "granted"}); isErr {
		t.Fatal("granted repository refused")
	}
	secret, isErr := callTool(t, svc.handleGetDependencyTree, map[string]any{"org": "github/acme", "repo": "secret"})
	missing, _ := callTool(t, svc.handleGetDependencyTree, map[string]any{"org": "github/acme", "repo": "nope"})
	if !isErr || secret != errNotFoundOrNoAccess.Error() || missing != secret {
		t.Fatalf("ungranted = %q, missing = %q, want the same not-found-or-no-access answer", secret, missing)
	}
	for name, handler := range map[string]func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error){
		"impact_analysis":   svc.handleImpactAnalysis,
		"search_components": svc.handleSearchComponents,
	} {
		text, isErr := callTool(t, handler, map[string]any{"org": "github/acme", "cve_id": "CVE-1", "query": "x"})
		if !isErr || !strings.Contains(text, "specific repositories") {
			t.Errorf("%s for a scoped principal = %q, want refusal", name, text)
		}
	}

	// A scoped member with no grants left sees nothing.
	st.grants = map[uuid.UUID]string{}
	if _, isErr := callTool(t, svc.handleGetDependencyTree, map[string]any{"org": "github/acme", "repo": "granted"}); !isErr {
		t.Fatal("scoped member without grants reached a repository")
	}

	// Non-members and unknown orgs: same answer.
	st.role = ""
	member, _ := callTool(t, svc.handleGetDependencyTree, map[string]any{"org": "github/acme", "repo": "granted"})
	unknown, _ := callTool(t, svc.handleGetDependencyTree, map[string]any{"org": "github/other", "repo": "granted"})
	if member != errNotFoundOrNoAccess.Error() || unknown != member {
		t.Fatalf("non-member = %q, unknown org = %q", member, unknown)
	}
}

// P4: list outputs are capped and paged.
func TestMCPListOutputIsCapped(t *testing.T) {
	t.Parallel()

	svc, _ := newAccessService()
	first, isErr := callTool(t, svc.handleGetDependencyTree, map[string]any{"org": "github/acme", "repo": "secret"})
	if isErr || !strings.Contains(first, `"truncated": true`) || !strings.Contains(first, `"next_offset": 500`) {
		t.Fatalf("first page not truncated: %.200s", first)
	}
	second, _ := callTool(t, svc.handleGetDependencyTree, map[string]any{"org": "github/acme", "repo": "secret", "offset": float64(500)})
	if !strings.Contains(second, `"truncated": false`) || strings.Count(second, `"purl"`) != 20 {
		t.Fatalf("second page wrong: %.200s", second)
	}
	if _, isErr := callTool(t, svc.handleGetDependencyTree, map[string]any{"org": "github/acme", "repo": "secret", "offset": float64(-1)}); !isErr {
		t.Fatal("negative offset accepted")
	}
}

// P4: every tool tells the agent which fields are untrusted.
func TestMCPToolDescriptionsLabelUntrustedText(t *testing.T) {
	t.Parallel()

	for _, tool := range []mcp.Tool{listVulnerabilitiesTool, getDependencyTreeTool, impactAnalysisTool, compareRefsTool, searchComponentsTool} {
		if !strings.Contains(tool.Description, "untrusted data") {
			t.Errorf("%s description does not label untrusted text", tool.Name)
		}
	}
}

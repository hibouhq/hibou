package mcp

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type MCPStore interface {
	GetOrganizationByProviderAndSlug(ctx context.Context, provider, slug string) (*store.Organization, error)
	GetOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID) (string, error)
	GetRepositoryBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*store.Repository, error)
	GetRefByRepoAndName(ctx context.Context, repoID uuid.UUID, name string, refType store.RefType) (*store.Ref, error)
	GetLatestSnapshotByRef(ctx context.Context, refID uuid.UUID) (*store.Snapshot, error)
	ListAllVulnerabilitiesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]store.Vulnerability, error)
	ListComponentsBySnapshotWithVulns(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.ListComponentsBySnapshotWithVulnsRow, error)
	SearchComponents(ctx context.Context, orgID uuid.UUID, query string, limit, offset int) ([]dbgen.Component, int, error)
	GetAdvisoryByID(ctx context.Context, id uuid.UUID) (dbgen.Advisory, error)
	GetAdvisoriesByIDs(ctx context.Context, ids []uuid.UUID) ([]dbgen.Advisory, error)
	GetAdvisoryByAlias(ctx context.Context, alias string) (dbgen.Advisory, error)
	GetAPIKeyByHash(ctx context.Context, hash string) (*store.APIKey, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error
}

type contextKey string

const userContextKey contextKey = "mcp_user"

func UserFromContext(ctx context.Context) *store.User {
	user, _ := ctx.Value(userContextKey).(*store.User)
	return user
}

func withUser(ctx context.Context, user *store.User) context.Context {
	if user == nil {
		return ctx
	}
	return context.WithValue(ctx, userContextKey, user)
}

func New(st MCPStore, deltaSvc *delta.Service, log zerolog.Logger, serverVersion string) *server.MCPServer {
	mcpSrv := server.NewMCPServer("hibou", serverVersion)

	s := &service{store: st, delta: deltaSvc, log: log.With().Str("component", "mcp").Logger()}
	mcpSrv.AddTools(
		server.ServerTool{Tool: listVulnerabilitiesTool, Handler: s.handleListVulnerabilities},
		server.ServerTool{Tool: getDependencyTreeTool, Handler: s.handleGetDependencyTree},
		server.ServerTool{Tool: impactAnalysisTool, Handler: s.handleImpactAnalysis},
		server.ServerTool{Tool: compareRefsTool, Handler: s.handleCompareRefs},
		server.ServerTool{Tool: searchComponentsTool, Handler: s.handleSearchComponents},
	)

	return mcpSrv
}

func NewHTTPServer(mcpSrv *server.MCPServer, st MCPStore, port int, log zerolog.Logger) *server.StreamableHTTPServer {
	_ = port

	return server.NewStreamableHTTPServer(mcpSrv,
		server.WithHTTPContextFunc(authContextFunc(st, log)),
		server.WithEndpointPath("/mcp"),
		server.WithStateLess(true),
	)
}

func authContextFunc(st MCPStore, log zerolog.Logger) server.HTTPContextFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return ctx
		}

		rawKey := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if rawKey == "" {
			return ctx
		}

		apiKey, err := st.GetAPIKeyByHash(ctx, store.HashAPIKey(rawKey))
		if err != nil {
			log.Debug().Err(err).Msg("failed to load MCP API key")
			return ctx
		}
		if apiKey == nil || apiKey.User == nil {
			return ctx
		}
		if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
			return ctx
		}
		if err := st.UpdateAPIKeyLastUsed(ctx, apiKey.ID); err != nil {
			log.Debug().Err(err).Str("api_key_id", apiKey.ID.String()).Msg("failed to update MCP API key last-used timestamp")
		}

		return withUser(ctx, apiKey.User)
	}
}

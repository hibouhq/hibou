# Orchestrator Report

## Task Requested
Finish all remaining Phase 1 items: Authentication, Ingestion surface, Git forge integration (with provider abstraction for GitHub/Forgejo/Gitea/GitLab), and Frontend shell.

## Workspace Findings

### Already complete:
- Data model + migrations (17 tables, refs/snapshots/findings schema ready)
- RBAC with Casbin (internal/rbac/)
- Multi-tenant org hierarchy (orgs/teams/repos CRUD)
- Base REST API + OpenAPI (swaggo annotations, swagger UI)
- API key auth middleware (internal/server/auth.go)
- Users table has provider/provider_id columns (ready for OAuth)
- Repositories table has provider/provider_id/sync_state columns

### Remaining Phase 1 items:

**Batch 1: Auth + Git forge provider abstraction + Ingestion sqlc queries**
- internal/forge/ — Provider interface + GitHub implementation + Forgejo/Gitea stubs + GitLab stubs
- internal/auth/ — OIDC/OAuth2 login flows, session management (using gorilla/sessions + coreos/go-oidc)
- SQL queries for refs, snapshots, findings (needed by ingestion)
- sqlc generate

**Batch 2: Ingestion surface + Webhook handler**
- internal/server/uploads.go — POST /upload/sbom, /upload/sarif, /upload/findings
- internal/server/webhooks.go — POST /webhooks/{provider} (GitHub/Gitea/GitLab)
- Upload status endpoint

**Batch 3: Frontend shell**
- Vue router with routes: dashboard, orgs, repos, settings, login
- Auth store (Pinia), API client
- Layout: sidebar, tenant selector, route guards
- Placeholder views wired to live APIs

## Plan Summary

### Batch 1: Foundation layer (forge abstraction + auth + sqlc queries)

#### 1a. internal/forge/ package — Provider abstraction
Create `internal/forge/forge.go` with the core interface:
```go
type Provider interface {
    ID() string                                    // "github", "gitea", "gitlab"
    ListRepositories(ctx, installationID) ([]Repo, error)
    GetRepository(ctx, owner, name) (*Repo, error)
    ListBranches(ctx, owner, repo) ([]Branch, error)
    CreateCheckRun(ctx, owner, repo, opts) error   // PR feedback
    ValidateWebhookPayload(r *http.Request, secret) ([]byte, error)
    ParseWebhookEvent(eventType string, payload []byte) (Event, error)
}
```

Files:
- forge.go — interface + types (Repo, Branch, Event, PushEvent, PREvent, etc.)
- github.go — GitHub implementation using google/go-github
- gitea.go — Gitea/Forgejo stub (same API structure)
- gitlab.go — GitLab stub

#### 1b. internal/auth/ package — OIDC + OAuth2 + sessions
- auth.go — Manager struct, OIDC discovery, OAuth2 flows
- session.go — gorilla/sessions-based cookie sessions
- handlers: GET /auth/login, GET /auth/callback, POST /auth/logout, GET /auth/providers
- Config additions: HIBOU_OIDC_ISSUER, HIBOU_OIDC_CLIENT_ID, HIBOU_OIDC_CLIENT_SECRET, HIBOU_SESSION_SECRET

#### 1c. sqlc queries for refs, snapshots, findings
- queries/refs.sql
- queries/snapshots.sql
- queries/findings.sql
- Store adapter files: refs.go, snapshots.go, findings.go

### Batch 2: Ingestion + webhooks
- uploads.go handlers (sbom, sarif, findings)
- webhooks.go handler (provider-agnostic via forge.Provider)
- Upload status tracking

### Batch 3: Frontend shell
- Router, layout, stores, API client, placeholder views

## Workflow Status
Starting Batch 1

## Agents Used
- Orchestrator (research + planning)

## Review Status
Pending

## Blockers
None

## Final Outcome
Pending
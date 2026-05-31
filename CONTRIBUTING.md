# Contributing to hibou

## Development Environment

The recommended way to develop is using the VS Code devcontainer. It includes all tools pre-configured:

- Go 1.24+ with delve debugger
- Node.js 22 with npm
- golangci-lint
- sqlc
- PostgreSQL client

### Getting started

1. Open the project in VS Code
2. Accept the prompt to reopen in the dev container
3. Start the full dev stack (PostgreSQL, Forgejo, Trivy + OAuth + dev servers):
   ```bash
   cp .env.example .env
   make start
   ```
   This starts all Docker Compose services, creates a Forgejo admin user + OAuth2
   application, seeds data, and starts the dev servers.

4. Open http://localhost:3000 and sign in via Forgejo (or use "Dev Login" if no
   forge is configured).

### Forgejo local instance

The Docker Compose stack includes a Forgejo instance at http://localhost:3030.
Admin credentials (created by `make start`):
- Username: `hibou-admin`
- Password: `hibou-admin`

You can create test repos, webhooks, and users there.

### Multiple forge instances

hibou supports multiple forge providers via indexed environment variables:

```bash
# First forge: local Forgejo
HIBOU_FORGE_0_TYPE=forgejo
HIBOU_FORGE_0_ID=forgejo
HIBOU_FORGE_0_URL=http://localhost:3030
HIBOU_FORGE_0_CLIENT_ID=...
HIBOU_FORGE_0_CLIENT_SECRET=...

# Second forge: GitHub
HIBOU_FORGE_1_TYPE=github
HIBOU_FORGE_1_ID=github
HIBOU_FORGE_1_CLIENT_ID=...
HIBOU_FORGE_1_CLIENT_SECRET=...

# Third forge: another Forgejo (staging)
HIBOU_FORGE_2_TYPE=forgejo
HIBOU_FORGE_2_ID=forgejo-staging
HIBOU_FORGE_2_URL=https://forgejo.staging.example.com
HIBOU_FORGE_2_CLIENT_ID=...
HIBOU_FORGE_2_CLIENT_SECRET=...
```

Supported types: `github`, `forgejo`, `gitea`, `gitlab`.

### Make targets

| Target | Description |
|--------|-------------|
| `make setup` | Start postgres + seed sample data for quick dev login |
| `make start` | Start full stack, bootstrap Forgejo OAuth, seed data, run dev servers |
| `make up` | Start Docker Compose services only |
| `make down` | Stop Docker Compose services |
| `make dev` | Run Go backend + Vite frontend (hot reload) |
| `make lint` | Run all linters (sqlc diff, golangci-lint, eslint) |
| `make test` | Run all Go + frontend tests |
| `make generate` | Regenerate sqlc + swagger docs |
| `make build` | Build the hibou binary |
| `make clean` | Remove build artifacts |

## Code Organization

### Backend (Go)

- **`cmd/`** -- CLI commands (thin wrappers over internal packages)
- **`internal/api/`** -- Shared HTTP helpers (responses, pagination, validation)
- **`internal/auth/`** -- OAuth2/session authentication
- **`internal/config/`** -- Environment-based configuration
- **`internal/forge/`** -- Git forge provider abstraction (GitHub, Forgejo, GitLab)
- **`internal/rbac/`** -- Casbin-based RBAC with PostgreSQL adapter
- **`internal/server/`** -- HTTP handlers and middleware
- **`internal/store/`** -- Database access layer (sqlc-backed)

### Frontend (Vue/TypeScript)

- **`site/src/`** -- Vue 3 SPA source code
- **`site/src/api/`** -- API client
- **`site/src/layouts/`** -- App layout (sidebar, navigation)
- **`site/src/stores/`** -- Pinia stores (auth, org)
- **`site/src/views/`** -- Page-level components

## Making Changes

### Database changes

1. Create a new migration file in `internal/store/migrations/` with 5-digit numbering:
   ```text
   00002_your_change.up.sql
   00002_your_change.down.sql
   ```
2. Add or update queries in `internal/store/queries/*.sql`
3. Regenerate the Go code:
   ```bash
   make generate
   ```
4. Update adapter functions in `internal/store/` if needed

### Backend changes

1. Write or update handlers in `internal/server/`
2. Add swaggo annotations to all new handlers
3. Run lints and tests:
   ```bash
   make lint test
   ```

### Adding a new forge provider

1. Implement the `forge.Provider` interface in `internal/forge/yourprovider.go`
2. Add a case for the new type in `cmd/serve.go` (the forge factory switch)
3. Add webhook event type detection in `internal/server/webhooks.go`
4. The provider is automatically available via `HIBOU_FORGE_N_TYPE=yourprovider`

### Frontend changes

1. Work in `site/src/`
2. The Vite dev server proxies `/api` to the Go backend on port 8585

## sqlc Workflow

SQL queries live in `internal/store/queries/*.sql` and use sqlc annotations:

```sql
-- name: GetUserByID :one
SELECT id, email, display_name FROM users WHERE id = $1;
```

After editing any `.sql` file, regenerate:

```bash
make generate
```

The generated code lands in `internal/store/dbgen/`. **Never edit files in `dbgen/` directly** -- they are overwritten on every generation.

`make lint` runs `sqlc diff` to catch stale generated code.

## Testing

```bash
make test           # Run all Go and frontend tests
go test ./...       # Go tests only
cd site && npx vitest run  # Frontend tests only
```

Go integration tests (for example, store tests) require a running PostgreSQL instance. The devcontainer plus `docker compose up -d` provides this automatically.

## Commit Guidelines

- Use clear, descriptive commit messages
- Reference issue numbers where applicable
- Keep commits focused on a single change

## Architecture Decisions

Major decisions are documented as ADRs in `docs/adr/`. Consult existing ADRs before proposing changes to foundational choices.

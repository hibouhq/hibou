# hibou

Open-source DevSecOps security platform. The goal is to unify dependency risk, code findings, PR analysis, and release impact into a single multi-tenant system.

> **Status:** Early development. The core backend (API, auth, multi-tenant org management) and build pipeline are in place. Ingestion, findings, and the full UI are under active development — see [TODO.md](TODO.md) for the roadmap.

## Features

- **Multi-tenant** — organization → team → repository hierarchy with API key auth
- **Single binary** — Go backend embeds the Vue 3 SPA; one artifact to deploy
- **API-first** — REST API with JSON envelopes, pagination, and error handling
- **Cloud-native** — Helm chart for production, Docker Compose for development
- **sqlc** — type-safe database layer generated from plain SQL

## Architecture

| Layer | Technology |
|-------|-----------|
| Backend | Go, Chi v5, zerolog, sqlc, golang-migrate |
| Frontend | Vue 3, TypeScript, Pinia, Vue Router, Tailwind CSS |
| Database | PostgreSQL 16 |
| Scanner | Trivy (server mode) |
| Deployment | Helm chart, Docker, single binary |

## Quick Start

### Using the devcontainer (recommended)

1. Open in VS Code with the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
2. Reopen in container when prompted
3. Start the infrastructure:
   ```bash
   docker compose up -d
   ```
4. Copy the environment file:
   ```bash
   cp .env.example .env
   ```
5. Start the dev servers:
   ```bash
   make dev
   ```
6. Open http://localhost:3000 (frontend) or http://localhost:8080 (API)

### Manual setup

**Prerequisites:** Go 1.24+, Node.js 22+, PostgreSQL 16, golangci-lint, sqlc

1. Clone the repository
2. Install dependencies:
   ```bash
   go mod download
   cd site && npm install && cd ..
   ```
3. Start PostgreSQL and set `HIBOU_DATABASE_URL`
4. Run the dev servers:
   ```bash
   make dev
   ```

## Make Targets

| Target | Description |
|--------|-------------|
| `make` | Lint, test, and build |
| `make dev` | Run backend (air) + frontend (vite) concurrently |
| `make generate` | Run sqlc code generation |
| `make lint` | Run Go and frontend linters + check generated code |
| `make test` | Run Go and frontend tests |
| `make build` | Build frontend then Go binary |
| `make build-all` | Cross-compile for all platforms |

## Project Structure

```text
├── main.go                    # Entry point
├── cmd/                       # Cobra CLI commands
├── internal/
│   ├── api/                   # Response helpers, pagination, validation
│   ├── config/                # Environment-based configuration
│   ├── server/                # HTTP handlers, middleware, routing
│   ├── store/                 # Database layer (sqlc-generated + adapters)
│   │   ├── dbgen/             # Generated code (do not edit)
│   │   ├── queries/           # SQL query definitions
│   │   └── migrations/        # PostgreSQL migrations
│   ├── ui/                    # Embedded SPA assets
│   └── version/               # Build-time version info
├── site/                      # Vue 3 SPA source
├── chart/hibou/               # Helm chart
├── docs/adr/                  # Architecture Decision Records
└── .devcontainer/             # Dev container configuration
```

## Configuration

Configuration is via environment variables with the `HIBOU_` prefix.
See [.env.example](.env.example) for all available options.

| Variable | Default | Description |
|----------|---------|-------------|
| `HIBOU_HOST` | `0.0.0.0` | Server bind address |
| `HIBOU_PORT` | `8080` | Server port |
| `HIBOU_DATABASE_URL` | — | PostgreSQL connection string |
| `HIBOU_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `HIBOU_LOG_FORMAT` | `console` | Log format (console, json) |
| `HIBOU_TRIVY_URL` | `http://localhost:4954` | Trivy server URL |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

License to be determined.
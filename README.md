# hibou

An Open Security Intelligence Platform for the Software Lifecycle. Unify dependency risk, code findings, PR analysis, and release impact into a single multi-tenant system.

> **Status:** Early development. The core backend (API, auth, multi-tenant org management) and build pipeline are in place. Ingestion, findings, and the full UI are under active development — see [TODO.md](TODO.md) for the roadmap.
> **Disclaimer:** This project uses LLM-assisted development to iterate quickly on user experience, automation, and proactive workflows. The current focus is shipping core capabilities first, then hardening stability, security, and dogfooding practices as the project matures.

## Features

- **Multi-tenant** — organization → team → repository hierarchy with RBAC (admin, developer, auditor, release_manager, viewer)
- **Single binary** — Go backend embeds the Vue 3 SPA; one artifact to deploy
- **SBOM ingestion** — CycloneDX (JSON/XML) and SPDX (JSON) with async processing and dedup
- **Vulnerability scanning** — pluggable advisory providers (OSV.dev, NVD, GitHub Advisory, Trivy, Sonatype OSS Index) with canonical alias merging
- **Secret scanning** — Using Gitleaks, trufflehog, betterleaks and GitHub secret scanning API.
- **SARIF support** — ingest results from Semgrep, CodeQL, or any SARIF 2.1.0 producer
- **VEX management** — create, import, and export VEX statements in OpenVEX, CSAF, and CycloneDX formats
- **Automatic VEX generation** — auto-creates VEX statements on component upgrade/removal; supplier VEX propagation with expiry and re-evaluation
- **Reachability analysis** — Go call graph analysis (server-side, RTA/VTA), Java bytecode analysis (CI-side), Rust source parsing (CI-side) to auto-VEX unreachable vulnerabilities
- **Coverage integration** — multi-format ingestion (Cobertura, JaCoCo, Clover, LCOV, Go cover), PR coverage deltas, and configurable quality gates (min coverage, regression grace, diff minimum)
- **Malware detection** — flags typosquat, dependency confusion, backdoor, and cryptominer packages from OSV and OpenSSF Package Analysis
- **PR quality gates** — delta analysis (new/resolved vulns and findings) with configurable thresholds per branch pattern
- **Forge integrations** — GitHub, Forgejo/Gitea, and GitLab with PR annotations, commit statuses, and webhook events
- **Config-as-code** — `.hibou.yaml` per-repo configuration with JSON Schema and onboarding PR creation
- **Compliance reporting** — point-in-time reports with ISO 27001 control mapping and SoA generation
- **Release & client tracking** — releases, deployments, rollback history, and CVE impact analysis across clients
- **Notifications** — Slack, Teams, Discord, webhook (HMAC-signed), and email with configurable rules per org
- **Real-time updates** — WebSocket hub with per-user channels and topic subscriptions
- **Audit logging** — immutable log of 30+ action types with actor, IP, and full context
- **MCP server** — built-in Model Context Protocol server for AI assistant integration
- **CLI** — `login`, `upload`, `repos`, `status` commands for CI pipeline integration
- **API-first** — REST API with JSON envelopes, pagination, and error handling
- **Cloud-native** — Helm chart Available
- **sqlc** — type-safe database layer generated from plain SQL

## Architecture

| Layer | Technology |
|-------|-----------|
| Backend | Go, Chi v5, zerolog, sqlc, golang-migrate |
| Frontend | Vue 3, TypeScript, Pinia, Vue Router, Tailwind CSS |
| Database | PostgreSQL 18 |
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
6. Open http://localhost:8080 (frontend) or http://localhost:8585 (API)

### Manual setup

**Prerequisites:** Go 1.24+, Node.js 22+, PostgreSQL 18, golangci-lint, sqlc

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
| `HIBOU_PORT` | `8585` | Server port |
| `HIBOU_DATABASE_URL` | — | PostgreSQL connection string |
| `HIBOU_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `HIBOU_LOG_FORMAT` | `console` | Log format (console, json) |
| `HIBOU_TRIVY_URL` | `http://localhost:4954` | Trivy server URL |
| `HIBOU_MCP_ENABLED` | `true` | Enable the built-in MCP server |
| `HIBOU_MCP_PORT` | `8081` | MCP server port |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

License to be determined.

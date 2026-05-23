# ADR-005: Internal package architecture

## Status
Accepted

## Context
The SPEC calls for domain logic in well-tested internal Go packages, with HTTP handlers, CLI commands, and workers as thin adapters. A clear package layout prevents coupling and supports testability.

## Decision
All business logic lives under `internal/`. The initial package layout:

| Package | Responsibility |
|---------|---------------|
| `config` | Environment-based configuration loading |
| `server` | HTTP server, router, middleware, SPA serving |
| `ui` | Embedded SPA filesystem |
| `version` | Build-time version metadata |

Future packages (per SPEC) will include: `store`, `auth`, `rbac`, `sbom`, `sarif`, `vuln`, `scanning`, `findings`, `snapshot`, `release`, `client`, `notify`, `mcp`, `gitprovider`.

Each package exposes a service interface that accepts a `context.Context` and returns typed results. Packages depend on `store` for persistence but never on HTTP or CLI frameworks.

## Consequences
- Domain logic is testable without HTTP or CLI scaffolding.
- CLI and API share the same validation and business rules.
- New entry points (gRPC, MCP tools) can reuse the same core.
- Package boundaries are enforced by Go's import system.

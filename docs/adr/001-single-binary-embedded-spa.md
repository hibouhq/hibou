# ADR-001: Single-binary architecture with embedded SPA

## Status
Accepted

## Context
The platform needs to serve both a REST API and a Vue 3 SPA. Deployment simplicity is a key design goal — operators should be able to run a single binary without managing separate frontend and backend services.

## Decision
Use Go's `embed.FS` to embed the built SPA into the server binary. The `internal/ui` package owns the embed directive. The Vite build outputs to `internal/ui/dist/`, and the Go binary serves those files with SPA-style fallback to `index.html` for client-side routing.

In development, the frontend runs via Vite dev server with a proxy to the Go API (`make dev`).

## Consequences
- One binary to distribute, deploy, and operate.
- Frontend build is a prerequisite for `make build`; `make build-frontend` runs first.
- Development workflow uses two processes (Go API + Vite dev server) with proxy forwarding.
- The Docker image copies the pre-built SPA into the Go build stage before compilation.

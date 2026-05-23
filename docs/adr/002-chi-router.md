# ADR-002: Chi router for HTTP

## Status
Accepted

## Context
The platform needs an HTTP router that supports middleware composition, route grouping, and standard `net/http` compatibility. The router is a foundational choice that affects every API handler.

## Decision
Use `go-chi/chi` v5 as the HTTP router. Chi is lightweight, idiomatic, and fully compatible with `net/http` — handlers are standard `http.HandlerFunc` values. It provides built-in middleware for request IDs, real IP detection, panic recovery, and response wrapping.

## Consequences
- All handlers use standard `http.ResponseWriter` / `*http.Request` signatures.
- Middleware composes naturally with `r.Use()`.
- Route groups via `r.Route()` support clean API versioning (`/api/v1`).
- No framework lock-in; handlers are portable to any `net/http`-compatible router if needed later.

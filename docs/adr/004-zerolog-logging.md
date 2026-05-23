# ADR-004: Zerolog for structured logging

## Status
Accepted

## Context
The platform needs structured logging for production observability (JSON) and human-readable output for local development.

## Decision
Use `rs/zerolog` for structured logging. The logger is configured at server startup based on `HIBOU_LOG_LEVEL` and `HIBOU_LOG_FORMAT`. Console format uses `zerolog.ConsoleWriter` for development; JSON format is used in production. The logger is injected into the server and passed to middleware.

## Consequences
- Structured JSON logs are Kubernetes and log-aggregation friendly out of the box.
- Zero-allocation design keeps logging overhead minimal.
- Request logging middleware captures method, path, status, duration, and request ID per request.
- Log level is runtime-configurable via environment variable.

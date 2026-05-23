# ADR-003: Environment-based configuration

## Status
Accepted

## Context
The server needs a configuration mechanism that works across local development, Docker Compose, CI, and Kubernetes. The Twelve-Factor App methodology recommends environment variables for configuration.

## Decision
Use `caarlos0/env` v11 to parse configuration from environment variables into a typed `config.Config` struct. All variables are prefixed with `HIBOU_` to avoid collisions. Defaults are defined via struct tags. A `.env.example` file documents the full variable set.

## Consequences
- No config file parsing needed; env vars work natively in Docker, Kubernetes, and CI.
- Helm values map directly to container env vars.
- `.env.example` serves as the canonical configuration reference.
- Secrets (database URL, API keys) are injected via env vars or Kubernetes secrets, never committed.

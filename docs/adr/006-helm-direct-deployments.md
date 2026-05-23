# ADR-006: Helm chart with direct deployments

## Status
Accepted

## Context
Production deployment targets Kubernetes. The platform depends on PostgreSQL and optionally Trivy server. We need to decide whether to use Helm subcharts for dependencies or deploy them directly.

## Decision
Ship a single Helm chart under `chart/` that deploys hibou, PostgreSQL, and Trivy as direct Kubernetes resources (Deployments, Services, ConfigMaps, Secrets) — not as subcharts. This gives us full control over resource definitions, naming, labels, health probes, and upgrade behavior without inheriting opinionated upstream chart decisions.

## Consequences
- Full control over all Kubernetes manifests; no upstream chart compatibility issues.
- Operators can disable PostgreSQL or Trivy deployments via values when using external instances.
- The chart is self-contained with no `requirements.yaml` / subchart dependency management.
- We own the maintenance burden for PostgreSQL and Trivy resource definitions, but these are straightforward stateless/stateful deployments.

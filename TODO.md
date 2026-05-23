# DevSecOps Security Platform Roadmap

## Project framing

- [ ] Finalize project identity and governance
	- Decide the project name from the current placeholder set (`Wardeck`, `Bulwark`, `SecureHub`, `Fortguard`, `Bastion`) or a new candidate aligned with full-lifecycle DevSecOps.
	- Choose license, contribution model, code of conduct, maintainer structure, and release cadence.
	- Acceptance criteria hint: the repository has a stable public identity, contribution rules, and release ownership before external launch.

## Phase 0 - Project Bootstrap

- [ ] Establish repository scaffolding and baseline architecture
	- Create a Go monorepo layout for API, workers, internal packages, Cobra CLI, and embedded web assets. The binary serves as both server (`serve`) and client CLI, with shell completion support (`completion bash/zsh/fish/powershell`).
	- Initialize the Vue 3 SPA with Vite, TypeScript, Pinia, Vue Router, and a shared design token layer.
	- Define package boundaries so the backend can embed the built SPA into a single distributable binary.
	- Acceptance criteria hint: a fresh clone builds both backend and frontend locally and produces one runnable binary.

- [ ] Build the developer workflow and local toolchain
	- Add `Makefile` or `Taskfile` targets for lint, test, build, dev, code generation, and release packaging.
	- Add a devcontainer and Docker Compose stack for PostgreSQL, optional Trivy server, and local app development.
	- Standardize environment variable handling, example `.env` files, and secret injection conventions.
	- Acceptance criteria hint: a contributor can boot the full stack with one documented command path.

- [ ] Create the CI/CD baseline
	- Add GitHub Actions for Go lint/test, frontend lint/test, typecheck, binary build, container build, and release packaging.
	- Add dependency caching, artifact retention, and tagged release automation.
	- Add basic provenance goals such as checksums and release notes generation.
	- Acceptance criteria hint: pull requests run deterministic checks and tagged commits produce releasable artifacts.

- [ ] Define project conventions and architecture guardrails
	- Publish coding standards for Go and Vue, naming conventions, logging conventions, and API versioning rules.
	- Choose key libraries early: Cobra for CLI, router (`Chi`), migrations, query generation (`sqlc` or equivalent), auth/session layer, job runner, and UI primitives. Establish the `internal/` package layout from day one so domain logic lives in well-tested libraries and HTTP handlers, CLI commands, and workers are thin adapters.
	- Capture initial architecture decisions in ADRs so the first implementation phase does not drift.
	- Acceptance criteria hint: major foundational choices are documented and referenced by the initial codebase.

## Phase 1 - Core Foundation

- [ ] Design the PostgreSQL data model and migration system
	- Model organizations, teams, repositories, refs, snapshots, components, vulnerabilities, findings, releases, deployments, clients, users, roles, and notification rules.
	- Treat tagged refs as the release source of truth while adding first-class release and deployment records for lifecycle tracking, rollback history, and client impact analysis.
	- Introduce migration tooling, seed data strategy, and idempotent schema evolution rules.
	- Add query generation and repository interfaces that keep read/write paths explicit.
	- Acceptance criteria hint: the platform can create a clean database, migrate forward, and serve typed reads/writes for core entities.

- [ ] Implement authentication and session management
	- Add OIDC/OAuth2 login for SSO providers and git-provider login flows for GitHub-first onboarding.
	- Implement secure session handling, refresh behavior, logout, and tenant-aware user bootstrapping.
	- Support API keys for CI uploads with scoped permissions and expiry controls.
	- Acceptance criteria hint: both interactive users and CI systems can authenticate without bypassing RBAC.

- [ ] Introduce RBAC and policy enforcement
	- Integrate Apache Casbin with PostgreSQL-backed policies.
	- Define baseline roles: `admin`, `developer`, `auditor`, and `viewer`.
	- Map permissions to org, team, repository, and API-scope boundaries.
	- Acceptance criteria hint: policy tests demonstrate that reads, uploads, exports, and settings changes are constrained correctly.

- [ ] Deliver multi-tenant organization hierarchy
	- Implement organization -> team -> repository relationships from day one.
	- Add tenant scoping for every API path, query, background job, and audit event.
	- Build bootstrap flows for org creation, repo enrollment, and membership assignment.
	- Acceptance criteria hint: data from one organization cannot be reached or inferred by another tenant.

- [ ] Create the base REST API and OpenAPI contract
	- Stand up versioned JSON endpoints, middleware, validation, error envelopes, pagination, filtering, and sorting.
	- Cover upload status polling, PR delta and gate retrieval, clients, releases, deployments, notification rules, API keys, org membership, and RBAC administration in the public API surface.
	- Auto-generate and publish OpenAPI 3 documentation from code or source annotations.
	- Add health, readiness, and metrics endpoints for operators.
	- Acceptance criteria hint: consumers can explore a stable documented API before advanced analysis features land.

- [ ] Build the ingestion surface
	- Implement authenticated upload APIs for CycloneDX, SPDX, SARIF, and generic findings. Require ref, commit SHA, and repository identity on every upload so snapshots are pinned to exact source revisions.
	- Validate payload format, identify repo/ref ownership, persist raw artifacts where needed, and enqueue async processing.
	- Track ingestion status, failures, retryability, and audit metadata.
	- Acceptance criteria hint: a CI pipeline can submit SBOM and SARIF data and observe processing state end to end.

- [ ] Add GitHub app and webhook integration
	- Support repo discovery, installation setup, webhook verification, PR/ref mapping, and status update permissions.
	- Establish the minimum event set for push, pull request, and repository lifecycle events.
	- Prepare provider abstraction boundaries so Forgejo/Gitea and GitLab can be added later without rewriting ingestion flows.
	- Acceptance criteria hint: a GitHub-connected org can onboard repositories and tie uploads to canonical refs.

- [ ] Ship the first usable frontend shell
	- Implement the application shell, auth flow, tenant selector, sidebar navigation, theme handling, and route guards.
	- Add placeholder overview, repository, uploads, admin, and settings views wired to live APIs.
	- Build a consistent empty-state, loading-state, and error-state system.
	- Acceptance criteria hint: authenticated users can navigate a coherent shell backed by real tenant-aware data.

## Phase 2 - Analysis Engine

- [ ] Integrate SBOM vulnerability scanning with Trivy server
	- Support Trivy server connectivity as an internal service and as a Helm-managed subchart.
	- Define the scan trigger model for new snapshots, rescans, and database refresh events.
	- Persist scan provenance, DB version metadata, and retry behavior.
	- Acceptance criteria hint: an uploaded SBOM produces persisted vulnerability results linked to the originating snapshot.

- [ ] Add multi-source vulnerability enrichment
	- Query OSV.dev and NVD in addition to Trivy so vulnerability coverage is not limited to one database.
	- Implement caching keyed by component identity and vulnerability database version to avoid repeated expensive lookups.
	- Add operator controls for NVD API keys, cache retention, and refresh strategy.
	- Acceptance criteria hint: the same snapshot can be enriched from multiple sources without redundant recomputation.

- [ ] Implement the deduplication and normalization engine
	- Merge vulnerabilities reported by Trivy, OSV, NVD, and future SCA sources into unified records.
	- Normalize severity across CVSS variants and tool-native scoring into `critical`, `high`, `medium`, `low`, and `info`.
	- Aggregate fix versions, aliases, affected ranges, and reporting source metadata onto each merged vulnerability.
	- Acceptance criteria hint: the dependency view shows one coherent record per real issue rather than duplicated rows per scanner.

- [ ] Parse and store SARIF findings at scale
	- Implement SARIF 2.1.0 ingestion, rule extraction, location hashing, codeflow capture where useful, and tool metadata storage.
	- Support findings from any SARIF producer, including commercial and open-source analysis tools such as Semgrep and CodeQL.
	- Add enrichment hooks for rule catalogs, CWE metadata, and severity mapping.
	- Acceptance criteria hint: code-level findings from different SAST tools can be queried in one normalized model.

- [ ] Add generic findings ingestion for non-SARIF tools
	- Design a simple POST API for arbitrary findings with tool name, severity, file location, description, and metadata.
	- Allow custom AI detectors and niche tools to participate without forcing SARIF conversion.
	- Preserve enough structure for deduplication, filtering, and PR diffing.
	- Acceptance criteria hint: external tools without native SARIF support can still appear in repository analysis views.

- [ ] Deliver PR analysis and delta computation
	- Compare PR snapshots against the target branch latest snapshot for vulnerabilities and findings.
	- Compute new, resolved, and unchanged items with stable deduplication keys.
	- Add configurable quality gate rules for blocking conditions such as new critical vulnerabilities or high-severity code findings.
	- Acceptance criteria hint: a PR upload yields an actionable delta summary rather than a raw full snapshot dump.

- [ ] Implement GitHub PR annotations and checks
	- Post summary results as Check Runs and optionally inline review comments for code findings with stable locations.
	- Add controls to avoid noisy annotation spam and to update existing PR statuses idempotently.
	- Capture delivery failures and retry paths for provider API outages.
	- Acceptance criteria hint: the platform can decorate PRs using a standard delta-and-gate workflow without duplicating comments on re-runs.

## Phase 3 - Dashboard and Visualization

- [ ] Build the organization overview dashboard
	- Show health summaries, severity distribution, trending indicators, and top-risk repositories across the tenant.
	- Add filtering by team, repo, severity, tool, and time window.
	- Expose drilldowns that connect aggregate widgets to detailed views.
	- Acceptance criteria hint: platform operators can identify hotspots without leaving the overview page.

- [ ] Implement repository detail views and tab model
	- Add a repository landing page with tabs for `Weaknesses`, `Dependencies`, `Runtime`, and `Secrets`.
	- Keep `Runtime` and `Secrets` as visible placeholders if the full capability is not yet delivered.
	- Preserve consistent cross-tab filtering and ref selection behavior.
	- Acceptance criteria hint: users can move between code findings and dependency risk without losing context.

- [ ] Deliver the weaknesses experience
	- Build a findings table grouped and filterable by tool, rule, severity, file path, and status.
	- Support deduplicated aggregation across sources and deep-linking into raw evidence.
	- Add trend widgets for issue arrival and remediation over time.
	- Acceptance criteria hint: one repository can surface all code-level weaknesses regardless of originating scanner.

- [ ] Deliver the dependencies experience
	- Build a full dependency table with vulnerability overlays, fix-version hints, and source attribution.
	- Implement an SBOM viewer and an interactive dependency graph with search, expand/collapse, and vulnerable-node highlighting.
	- Support large graphs and tables with pagination, virtualization, or incremental loading.
	- Acceptance criteria hint: users can identify vulnerable transitive dependencies without drowning in duplicate graph noise.

- [ ] Add branch, release, and snapshot navigation
	- Model branch and release lists, detail pages, and ref-aware navigation patterns.
	- Expose latest snapshot status, scan freshness, and comparison entry points.
	- Connect client mapping views to release entities.
	- Acceptance criteria hint: the UI supports both active branches and shipped releases as first-class analysis targets.

- [ ] Deliver general-purpose ref comparison and SBOM diffing
	- Build a comparison view that accepts any two refs (branch vs release, release vs release, branch vs branch) and shows a full dependency diff: added, removed, and version-changed components, plus new and resolved vulnerabilities.
	- Include a ref-picker with autocomplete for base and target selection.
	- Show version upgrade/downgrade direction, vulnerability impact of changes, and finding deltas.
	- Expose via both API (`GET /api/v1/repos/{repo}/compare?base=...&target=...`) and CLI (`secplatform compare`).
	- Acceptance criteria hint: users can compare any two refs to see exactly what changed in the dependency tree and vulnerability posture between them.

- [ ] Build time-series trends and historical analytics
	- Add charts for vulnerability counts, finding counts, quality gate results, and remediation trends.
	- Support time-window selection, grouping, and per-tool overlays.
	- Retain enough historical snapshot data to support longitudinal reporting without expensive recomputation.
	- Acceptance criteria hint: teams can measure whether risk is improving or regressing over time.

- [ ] Introduce PR-focused review views
	- Create a PR summary page with new/resolved/unchanged findings and quality gate outcomes.
	- Mirror the fast scan-to-action model used by modern PR analysis tools while preserving drilldown into full details.
	- Provide comparison links back to branch snapshots when deeper analysis is needed.
	- Acceptance criteria hint: reviewers can triage PR risk from a focused delta screen rather than a full repository dashboard.

- [ ] Add client and delivery management
	- Implement CRUD for clients, releases, deployments, and impact lookup workflows.
	- Preserve deployment history, rollback state, environment-specific rollout tracking, and contact metadata for downstream consumers.
	- Support views such as "which clients are impacted by CVE-X" and "which releases are deployed at client Y".
	- Ensure this data remains tenant-scoped and exportable for operations teams.
	- Acceptance criteria hint: downstream release impact can be answered from the platform without external spreadsheets.

- [ ] Add global search and advanced filtering
	- Support cross-repo search for vulnerabilities, components, findings, and affected clients.
	- Provide structured filters, saved views, and sharable URLs.
	- Index key search fields without coupling the first version to an external search engine.
	- Acceptance criteria hint: security teams can answer tenant-wide impact questions in seconds.

## Phase 4 - AI, Notifications, and Integrations

- [ ] Build the embedded MCP server
	- Expose security-aware MCP tools for vulnerability listings, dependency graphs, impact analysis, and ref comparisons.
	- Reuse the platform authorization model so AI clients only see data they are entitled to access.
	- Document prompt-safe response shapes and pagination behavior for large result sets.
	- Acceptance criteria hint: an MCP-compatible assistant can query live platform data without bespoke integration code.

- [ ] Deliver the notifications subsystem
	- Implement event-driven dispatch for webhooks, Slack, Microsoft Teams, and email.
	- Add templating, retries, delivery logs, failure surfacing, and per-tenant configuration.
	- Support rate control and suppression rules for noisy repositories or transient scan churn.
	- Acceptance criteria hint: orgs can route actionable alerts to their preferred channels with auditable delivery state.

- [ ] Add an alert rules engine
	- Support configurable triggers such as new critical vulnerability, quality gate failure, release branch regression, and stale scan data.
	- Add rule scoping by org, team, repo, ref pattern, severity, and tool source.
	- Surface a dry-run or preview mode so administrators can validate rules before enabling them.
	- Acceptance criteria hint: alerts are configurable enough to be useful without requiring code changes.

- [ ] Publish an official GitHub Action
	- Create a maintained action that uploads SBOM, SARIF, and generic findings from CI pipelines.
	- Support API-key auth, PR/ref auto-detection, retries, and clear failure messages.
	- Provide reference workflows for common build systems.
	- Acceptance criteria hint: a GitHub repository can adopt the platform from CI in minutes.

- [ ] Expand the REST API to full platform coverage
	- Add CRUD for tenants, repos, client mappings, notification rules, API keys, and administrative settings.
	- Ensure every UI workflow has a public API equivalent.
	- Tighten consistency around pagination, filtering, partial updates, and idempotency.
	- Acceptance criteria hint: automation clients are not forced to rely on private or UI-only behavior.

- [ ] Deliver compliance-oriented reporting
	- Add exportable HTML and PDF reporting aimed at auditors and regulated environments.
	- Provide evidence views for findings history, vulnerability posture, policy status, and release impact.
	- Record report generation metadata for traceability.
	- Acceptance criteria hint: auditors can consume platform outputs without needing direct DB or admin access.

- [ ] Add a connected tool catalog
	- Track installed integrations, source health, last successful sync, and credential state.
	- Provide visibility into which tools are feeding data into each tenant.
	- Support operational diagnostics so broken integrations are quickly identifiable.
	- Acceptance criteria hint: administrators can tell whether the platform is healthy as an integration hub.

## Phase 5 - Ecosystem Expansion

- [ ] Add additional git provider support
	- Extend provider abstractions for Forgejo/Gitea and GitLab onboarding, webhook handling, and PR/MR decoration.
	- Reuse the GitHub-first data model without forcing provider-specific leaks through the whole system.
	- Acceptance criteria hint: a non-GitHub tenant can onboard repositories with feature parity for core ingestion flows.

- [ ] Add coverage tracking
	- Model line and branch coverage as a first-class signal alongside vulnerabilities and findings.
	- Support trend views, PR delta coverage, and simple quality gates.
	- Acceptance criteria hint: teams can correlate security posture with code health signals in one product.

- [ ] Deliver secret scanning tracking
	- Integrate with GitHub secret scanning and third-party tools such as truffleHog or gitleaks.
	- Normalize secret finding metadata and connect it to repository, ref, and remediation workflows.
	- Acceptance criteria hint: leaked secret visibility is available in the same platform workflow as SBOM and SARIF analysis.

- [ ] Add container image scanning flows
	- Support image-origin SBOM ingestion, image metadata tracking, and vulnerability reporting tied to containers.
	- Connect image analysis to repository and release entities where provenance is known.
	- Acceptance criteria hint: teams can analyze application dependencies whether they originate from source builds or shipped images.

- [ ] Add license compliance support
	- Extract license data from SBOMs, define policy rules, and surface violations in dependency views and reports.
	- Support allowlists, deny lists, and policy exceptions with audit history.
	- Acceptance criteria hint: legal and engineering teams can answer license risk questions without a separate platform.

- [ ] Design a plugin and extension model
	- Define extension points for new ingestion adapters, enrichers, notification sinks, and UI modules.
	- Decide what stays in-process versus out-of-process and how compatibility is versioned.
	- Acceptance criteria hint: ecosystem growth does not require core maintainers to merge every custom integration.

- [ ] Add SBOM export and re-export capabilities
	- Support generating or transforming stored dependency inventories back into CycloneDX or SPDX.
	- Preserve provenance and transformation metadata where possible.
	- Acceptance criteria hint: the platform can act as both a consumer and a source of SBOM data.

- [ ] Explore a Kubernetes operator
	- Auto-discover deployed versions, deployed images, or release metadata from clusters.
	- Feed runtime deployment context back into client/release impact analysis.
	- Acceptance criteria hint: operators can connect deployed reality to scanned release artifacts with minimal manual mapping.

## Cross-cutting workstreams

- [ ] Testing strategy maturity across all phases
	- Maintain Go table-driven unit tests for internal library packages, API handler tests, CLI integration tests, DB integration tests, frontend component tests with Vitest, and end-to-end tests with Playwright.
	- Add realistic fixture generation and fake-data tooling to exercise large-tenant scenarios.
	- Acceptance criteria hint: every new subsystem lands with the narrowest useful automated test coverage and regression protection.

- [ ] Documentation and developer education
	- Publish OpenAPI docs, user guides, admin runbooks, deployment guides, and integration recipes.
	- Add architecture diagrams, ADRs, onboarding docs, and troubleshooting playbooks.
	- Acceptance criteria hint: maintainers and adopters can deploy and extend the platform without reverse-engineering the codebase.

- [ ] Performance and scalability guardrails
	- Design pagination, caching, job queues, and snapshot retention with large orgs in mind.
	- Benchmark ingestion throughput, graph rendering limits, and high-cardinality search behavior.
	- Acceptance criteria hint: common large-tenant scenarios remain responsive and operationally affordable.

- [ ] Security hardening throughout delivery
	- Apply OWASP-focused input validation, CSRF/session protections, API rate limiting, secure defaults, secrets handling, and audit logging.
	- Threat-model ingestion endpoints, notification hooks, MCP interfaces, and tenant boundaries.
	- Acceptance criteria hint: the platform demonstrates credible security posture while marketing itself as a security product.

- [ ] Operational readiness and observability
	- Add structured logging, tracing, metrics, health probes, background job visibility, and audit logs.
	- Define backup, restore, migration rollback, and incident response expectations.
	- Acceptance criteria hint: operators can run the system in production without flying blind.

## Milestone map

- [ ] Milestone A - Public alpha foundation
	- Includes Phase 0 and the minimum viable slices of auth, tenancy, ingestion, and basic UI shell.

- [ ] Milestone B - Repository security intelligence
	- Includes SBOM + SARIF ingestion, vulnerability deduplication, repository tabs, and GitHub-connected workflows.

- [ ] Milestone C - PR and release intelligence
	- Includes PR delta analysis, annotations, historical trends, branch/release navigation, and client impact mapping.

- [ ] Milestone D - Platform integrations
	- Includes MCP, notifications, compliance exports, and the official GitHub Action.

- [ ] Milestone E - Ecosystem breadth
	- Includes additional git providers, coverage, secrets, license policies, plugins, and Kubernetes automation.

# DevSecOps Security Platform Specification

## Document status

This document is a living technical specification for a new open-source DevSecOps security platform. It captures the intended architecture, system boundaries, data model, API shape, and delivery strategy for a platform that unifies dependency risk, code findings, PR analysis, and downstream release impact into a single product.

## 1. Vision and goals

The platform is a unified, open-source DevSecOps security system that ingests SBOMs, SARIF, and generic findings; analyzes them across repositories, branches, releases, and pull requests; and presents them through one multi-tenant UI, API, and AI-accessible control plane. The goal is to replace fragmented tooling with a single operator-friendly platform that can answer both engineering questions such as "what changed in this PR" and governance questions such as "which clients are impacted by CVE-X".

### Key differentiators

- Broader than SBOM-only vulnerability managers: code findings, PR workflows, release tracking, and client impact are first-class concerns.
- More analysis-centric than issue aggregation systems: the primary workflow starts at repository state, ref deltas, and normalized dependency intelligence.
- Broader than code-quality-only platforms: the platform combines source findings with dependency, release, and downstream deployment context.
- Provider-aware but not provider-bound: it aggregates security data generically from APIs and file uploads and can support multiple git forges over time.

### Design principles

- Generic and extensible: data enters via APIs and normalized ingestion contracts rather than bespoke one-off integrations.
- API-first: every significant UI workflow should correspond to a documented public API.
- AI-native: the platform includes a built-in MCP server so AI assistants can query live security state safely.
- Single-binary: the backend serves the embedded SPA and background services from one Go executable for simple operations.
- Multi-tenant by design: tenant isolation is foundational, not retrofitted.
- Cloud-native but local-friendly: production deployment uses Helm while local development remains lightweight with Docker Compose.

## 2. Architecture overview

The platform is implemented as a Go service that embeds a Vue 3 single-page application using `embed.FS`. A single binary exposes the API, serves the frontend, runs asynchronous processing loops, and optionally hosts the MCP server either in-process on a separate port or as a subcommand.

### High-level component diagram

```text
                            +------------------------------+
                            |          Vue 3 SPA           |
                            |  Embedded static assets via  |
                            |         Go embed.FS          |
                            +---------------+--------------+
                                            |
                                            v
+---------------------+        +------------------------------+        +------------------+
| GitHub App/OAuth    |------->|       API Server Layer       |<-------| Built-in MCP     |
| Webhooks / Uploads  |        | Auth, REST, OpenAPI, RBAC,   |        | Server / tools   |
+---------------------+        | tenancy, query orchestration |        +------------------+
                               +------+-------------+---------+
                                      |             |
                                      |             |
                                      v             v
                         +------------------+   +-------------------+
                         | Ingestion Workers |   | Notification      |
                         | SBOM, SARIF,      |   | Dispatcher        |
                         | generic findings  |   | Webhook/Slack/    |
                         +---------+---------+   | Teams/Email       |
                                   |             +-------------------+
                                   v
                         +------------------+
                         | Scanning Workers |
                         | Trivy / OSV /    |
                         | NVD enrichment   |
                         +---------+--------+
                                   |
                                   v
                         +------------------+
                         | PostgreSQL       |
                         | System of record |
                         +------------------+
```

### CLI interface and multi-personality binary

The platform ships as a **single Go binary** that exposes different command surfaces depending on the name it is invoked as (ArgoCD pattern). At startup, the binary inspects `os.Args[0]` (after resolving symlinks) to determine its personality:

| Invocation name   | Personality     | Available commands                                    |
|-------------------|-----------------|-------------------------------------------------------|
| `hibou`           | User CLI        | login, logout, status, upload, repos, config, completion, version |
| `hibou-server`    | Server          | serve, seed, completion, version                      |
| `hibou-worker`    | Worker (future) | worker, version                                       |

- **User CLI** (`hibou`): The default personality. Only exposes client-side commands that talk to a remote Hibou server via REST API. Server-only commands like `serve` are hidden and disabled. This is what end users and CI pipelines use.
- **Server** (`hibou-server`): Exposes `serve` (starts API server, SPA, workers, MCP) and `seed` (populate sample data). User CLI commands are hidden. In the container image, a symlink `hibou-server -> hibou` is created and used as the entrypoint.
- **Worker** (`hibou-worker`, future): For scaled-out worker deployments. Only exposes worker-related commands.

This ensures that `hibou --help` on a developer's machine never shows `serve` or other server internals, keeping the CLI clean and focused. The container `Dockerfile` copies the binary as `hibou` and creates a `hibou-server` symlink for the server entrypoint.

Representative command tree (user CLI personality):

```text
hibou
├── login                    # Authenticate with a Hibou server
├── logout                   # Clear stored credentials
├── status                   # Show current auth status
├── upload
│   ├── sbom                 # Upload an SBOM file
│   ├── sarif                # Upload a SARIF file
│   └── findings             # Upload generic findings
├── repos
│   ├── list                 # List repositories
│   └── show                 # Show repository details
├── config
│   ├── set-org              # Set default organization
│   └── show                 # Show current configuration
├── completion               # Generate shell completions
│   ├── bash
│   ├── zsh
│   ├── fish
│   └── powershell
└── version                  # Print version info
```

Additional commands for vulnerabilities, dependencies, clients, and releases will be added as the API surface stabilizes.

Server personality command tree:

```text
hibou-server
├── serve                    # Start API server, SPA, workers, MCP
├── seed                     # Populate database with sample data
├── completion               # Generate shell completions
└── version                  # Print version info
```

The CLI authenticates via API key or token stored in a local config file (`~/.config/hibou/config.yaml`). All CLI commands map to public REST API calls, ensuring the CLI never bypasses the API layer.

### Internal library architecture

Business logic is abstracted into well-tested internal Go packages under `internal/`. The CLI commands, HTTP handlers, and background workers are thin adapters that delegate to these libraries. This ensures:

- Domain logic is testable in isolation without HTTP or CLI scaffolding.
- The CLI and API always share the same validation, business rules, and error semantics.
- New entry points (gRPC, MCP tools, future plugin hosts) can reuse the same core.

Indicative package layout:

```text
internal/
├── sbom/           # SBOM parsing (CycloneDX, SPDX), component extraction
├── sarif/          # SARIF 2.1.0 parsing, finding normalization
├── vuln/           # Vulnerability deduplication, severity normalization, merging
├── scanning/       # Trivy/OSV/NVD client logic, caching, enrichment
├── findings/       # Generic finding ingestion, dedup, location hashing
├── snapshot/       # Snapshot lifecycle, delta computation, PR analysis
├── release/        # Release and deployment management
├── client/         # Client registry and impact analysis
├── auth/           # Session, OIDC, API key, token management
├── rbac/           # Casbin policy management, role mapping
├── notify/         # Notification dispatch, templating, delivery tracking
├── mcp/            # MCP server tool implementations
├── gitprovider/    # Git provider abstraction (GitHub, Gitea, GitLab)
└── store/          # Database access layer (sqlc-generated + repository interfaces)
```

Each package exposes a service interface that accepts a context and returns typed results. Packages depend on `store` for persistence but never on HTTP or CLI frameworks.

### Runtime dependencies

- Required: PostgreSQL is the only mandatory external runtime dependency.
- Optional but strongly recommended: Trivy server for scalable SBOM vulnerability scanning.
- Optional integrations: OIDC provider, SMTP, Slack, Teams, and git-provider credentials.

## 3. Multi-tenancy and data model

### Tenancy hierarchy

The core hierarchy is:

`Organization -> Team -> Repository -> Ref -> Snapshot`

- Organization: the tenant root and primary security boundary.
- Team: optional grouping for repository ownership, visibility, and policy inheritance.
- Repository: a code repository connected to a git provider installation.
- Ref: a branch, tag, or pull request abstraction.
- Snapshot: an immutable point-in-time analysis record for a specific ref and ingest event.

### Conceptual entities

- `organizations`
  - Tenant root with branding, settings, integrations, and membership scope.

- `teams`
  - Optional grouping for repositories and user access delegation.

- `repositories`
  - Git-provider-linked repositories with provider metadata, default branch, sync state, and feature flags.

- `refs`
  - Canonical record for branches, tags, and PRs, including provider IDs, merge-target relationships, and latest known commit SHA.

- `snapshots`
  - Immutable analysis checkpoints tied to a ref, commit SHA, and ingest cycle. A snapshot references raw uploads, normalized dependency state, findings, and scan results. The commit SHA pins the snapshot to an exact source revision.

- `components`
  - Deduplicated software components identified primarily by PURL plus version and ecosystem metadata.

- `vulnerabilities`
  - Deduplicated advisory records merged from CVE, GHSA, OSV, NVD, Trivy, and future sources.

- `component_vulnerabilities`
  - Junction records that express which component version is affected by which vulnerability, including fix versions and source provenance.

- `findings`
  - Code-level or generic security findings with tool metadata, rule identity, location, severity, and lifecycle state.

- `clients`
  - Registered downstream consumers, installations, customers, or deployment targets, including environment profile, primary contacts, notification preferences, deployment frequency, and ownership metadata.

- `releases`
  - First-class release artifacts layered on top of tagged refs. A release records version, build metadata, artifact identifiers, provenance, publication timestamp, source ref, and the snapshot that represents the analyzed release state.

- `deployments`
  - Historical deployment records that connect a client to a specific release, including environment, deployment timestamp, status such as `active` or `rolled_back`, rollback target, rollout notes, and actor or automation provenance.

- `notification_rules`
  - Configurable alert conditions, destinations, thresholds, and suppression settings.

- `users`, `roles`, `policies`
  - Principal records, membership links, and Casbin-managed authorization policy state.

### Modeling notes

- Snapshots should be immutable to preserve history and support PR diffing and trends.
- Tagged refs remain the source of truth for release provenance, while `releases` add lifecycle metadata needed for publication, reporting, and artifact-level history.
- `deployments` replace the earlier thin `client_releases` mapping so the system can represent repeated installs, phased rollouts, partial environment coverage, and rollbacks over time.
- Components should be deduplicated globally where practical but always resolved through tenant-aware repository relationships.
- Vulnerability identity should prioritize CVE IDs, then advisory aliases such as GHSA when CVEs are absent.
- Findings should retain enough raw tool metadata to re-render source-specific detail without coupling UI logic to one scanner.

Impact analysis follows a simple lineage query: when CVE-X is found in component Y, the platform first resolves which snapshots and releases contain component Y, then resolves which clients have deployments of those releases. That chain allows the API and UI to answer both "which releases are affected" and "which client environments are currently exposed" without bypassing the normalized data model.

## 4. Ingestion pipeline

### Supported inputs

- SBOM ingestion
  - Accept CycloneDX JSON, CycloneDX XML, and SPDX JSON.
  - Extract package/component identity, dependency relationships, licenses, metadata, and source provenance.
  - Normalize component identities into `components` and snapshot-scoped component membership records.

- SARIF ingestion
  - Accept SARIF 2.1.0 payloads from any compatible producer, including commercial and open-source SAST/DAST tools such as Semgrep and CodeQL.
  - Extract runs, rules, locations, logical severities, message text, fingerprints, and code flows where useful.
  - Normalize into `findings` with a stable location hash and tool-specific metadata envelope.

- Generic findings API
  - Accept arbitrary findings for tools that do not emit SARIF.
  - Minimum payload fields: tool name, rule or category, severity, description, repository/ref/commit identity, and file or artifact location.
  - Intended for custom AI detectors, niche scanners, or internal controls.

### Upload flow

1. Authenticated caller submits an upload with repository, ref, and commit SHA context.
2. API validates identity, tenant scope, payload format, and size constraints.
3. Raw artifact metadata is persisted for traceability.
4. A new snapshot or snapshot update event is created.
5. Async processing extracts normalized records.
6. Scanning and enrichment jobs are enqueued.
7. Final status is published through the API, UI, and notification events.

### Deduplication rules during ingestion

- Components deduplicate primarily by PURL plus normalized version.
- Findings deduplicate by `(tool, rule_id, location_hash)` with optional message and fingerprint fallbacks.
- Repeated uploads for the same ref create distinct snapshots unless explicitly modeled as a replace operation.

## 5. Vulnerability scanning and deduplication

### Scanning sources

- Trivy server
  - Primary SBOM scanner for local and self-hosted vulnerability analysis.

- OSV.dev
  - Advisory enrichment and ecosystem-specific vulnerability coverage via API.

- NVD
  - Optional enrichment for CVSS, aliases, descriptions, and affected version metadata.

### Deduplication engine

The platform merges vulnerability results from multiple tools into unified `vulnerabilities` records.

### Merge strategy

- Primary identity: CVE ID.
- Secondary identity: advisory IDs such as GHSA or ecosystem-native advisory identifiers.
- Severity merge: keep the highest normalized severity and preserve source-level scores.
- CVSS merge: keep the highest score while storing all contributing vector strings where available.
- Affected ranges: union all known affected ranges.
- Fix versions: union all known fix versions and mark the source of each claim.
- Provenance: track which tools and databases reported each vulnerability.

### Merge examples

- Same CVE from two sources
  - If Trivy reports `CVE-2026-1234` with CVSS 7.5 and OSV reports the same CVE with CVSS 8.1, the dedup engine creates one vulnerability record, keeps the higher normalized severity and CVSS score, and preserves both source vectors in provenance.

- Advisory-only matching
  - If a source reports `GHSA-abcd-1234-wxyz` without a CVE and another source later reports the same advisory ID with richer metadata, the engine merges on advisory identity even though no CVE exists yet.

- Conflicting fix versions
  - If one source says the fix starts at `1.2.9` and another says `1.3.1`, the merged record stores both fix versions until version-range evidence proves one supersedes the other.

### Current-project lineage

The existing repository already demonstrates the value of merging Trivy, OSV, and NVD-style results into a unified dependency table. The new platform should preserve that capability as a central feature rather than treating each scanner as a separate silo.

### Caching and performance

- Cache vulnerability lookups by `(purl, version, db_source, db_version)` where possible.
- Invalidate caches on database refresh or configurable expiry windows.
- Batch outbound queries to OSV and NVD to minimize latency and API pressure.
- Use lessons from public SBOM platform discussions captured in the reference appendix to inform multi-source enrichment and caching strategy.

## 6. PR analysis

Pull request analysis is modeled as a comparison between the PR snapshot and the latest snapshot of the target branch.

### Core behavior

- Detect new, resolved, and unchanged vulnerabilities.
- Detect new, resolved, and unchanged code findings.
- Compute delta severity summaries and quality gate outcomes.
- Support stable comparisons even when raw tool fingerprints vary slightly between runs.

### Quality gates

Examples include:

- no new critical vulnerabilities
- no new high-severity SAST findings
- no increase in total vulnerability count above a configured threshold
- minimum coverage change constraints if coverage support is enabled later

### Provider feedback loop

- Publish a GitHub Check Run summary for each analyzed PR.
- Optionally publish inline review comments for SARIF-backed findings with stable file/line anchors.
- Keep updates idempotent so reruns refresh prior checks instead of spamming new ones.

This behavior follows the familiar PR-decoration pattern used by modern code analysis platforms, but generalizes it across dependency and security findings.

## 6b. General-purpose ref comparison

Beyond PR-specific deltas, the platform supports comparing any two refs — branch against release, release against release, two branches, or any arbitrary snapshot pair. This is the primary mechanism for answering questions like "what changed in our dependency tree between release 7.4 and 7.5" or "how does the main branch differ from the latest shipped release".

### SBOM / dependency diff

When comparing two refs, the platform computes:

- **Added components**: dependencies present in the target but not in the base.
- **Removed components**: dependencies present in the base but not in the target.
- **Version-changed components**: same PURL, different version (upgrade or downgrade).
- **New vulnerabilities**: CVEs affecting the target that were not present in the base.
- **Resolved vulnerabilities**: CVEs present in the base that are no longer present in the target.
- **Unchanged vulnerabilities**: CVEs shared by both snapshots.

### Findings diff

Code findings are also diffed using stable dedup keys, producing added, removed, and unchanged finding sets.

### Use cases

- Compare a feature branch against the release branch it will be merged into.
- Compare two releases to see what dependency changes shipped between them.
- Compare the current state of `main` against the latest release to preview upcoming risk changes.
- Audit the dependency delta before cutting a new release.

### Comparison model

Comparisons are computed on demand from persisted snapshot data. The API accepts any two ref identifiers from the same repository. The UI provides a ref-picker for base and target with autocomplete.

## 7. API design

### API style

- REST API over JSON.
- Versioned under `/api/v1`.
- OpenAPI 3.0 generated from source annotations or route contracts.
- Consistent pagination, filtering, sorting, and error response envelopes on all list endpoints.

### Authentication

- Bearer tokens based on JWTs issued from OIDC or provider auth.
- API keys for CI and automation.
- Optional short-lived upload tokens for scoped integrations in future iterations.

### Representative endpoints

- `POST /api/v1/upload`
  - Upload an SBOM, SARIF, or findings artifact. Type is auto-detected from content.

- `GET /api/v1/uploads/{id}/status`
  - Return upload processing state, validation failures, and downstream job progress.

- `GET /api/v1/orgs/{org}/repos`
  - List repositories in an organization.

- `GET /api/v1/orgs/{org}/members`
  - List organization members and effective memberships.

- `POST /api/v1/orgs/{org}/members`
  - Add a member or bind an external identity to the organization.

- `DELETE /api/v1/orgs/{org}/members`
  - Remove or revoke organization membership.

- `GET /api/v1/orgs/{org}/roles`
  - Return role definitions and effective RBAC bindings.

- `PUT /api/v1/orgs/{org}/roles`
  - Update role bindings or policy assignments for an organization.

- `POST /api/v1/orgs/{org}/notification-rules`
  - Create a notification rule.

- `GET /api/v1/orgs/{org}/notification-rules`
  - List configured notification rules.

- `PUT /api/v1/orgs/{org}/notification-rules/{rule}`
  - Update a notification rule.

- `DELETE /api/v1/orgs/{org}/notification-rules/{rule}`
  - Delete a notification rule.

- `GET /api/v1/repos/{repo}/refs/{ref}/dependencies`
  - Return a dependency list with vulnerability overlays.

- `GET /api/v1/repos/{repo}/refs/{ref}/findings`
  - Return normalized code findings.

- `GET /api/v1/repos/{repo}/refs/{ref}/vulnerabilities`
  - Return aggregated vulnerability records.

- `GET /api/v1/repos/{repo}/pulls/{pr}/delta`
  - Return PR-specific new, resolved, and unchanged findings and vulnerabilities.

- `GET /api/v1/repos/{repo}/pulls/{pr}/gate`
  - Return quality gate evaluation status and blocking conditions.

- `GET /api/v1/repos/{repo}/compare?base={ref}&target={ref}`
  - Return a full diff between any two refs: added/removed/changed components, new/resolved vulnerabilities, and added/removed findings. Supports branch-to-release, release-to-release, or any ref pair.

- `POST /api/v1/clients`
  - Create a client record with contact, environment, and deployment metadata.

- `GET /api/v1/clients`
  - List clients and their current deployment summaries.

- `GET /api/v1/clients/{client}`
  - Return a single client, including rollout profile and active deployments.

- `PUT /api/v1/clients/{client}`
  - Update client metadata, contact information, or deployment preferences.

- `DELETE /api/v1/clients/{client}`
  - Archive or delete a client record.

- `POST /api/v1/clients/{client}/deployments`
  - Record a deployment of a release to a client environment.

- `GET /api/v1/clients/{client}/deployments`
  - List deployment history for a client.

- `GET /api/v1/releases`
  - List release artifacts, publication state, and associated source refs.

- `POST /api/v1/releases`
  - Create a release record from a tagged ref or external release event.

- `POST /api/v1/users/me/api-keys`
  - Create a personal API key.

- `GET /api/v1/users/me/api-keys`
  - List active personal API keys.

- `DELETE /api/v1/users/me/api-keys/{key}`
  - Revoke a personal API key.

- `GET /api/v1/vulnerabilities/{cve}/impact`
  - Return impacted repositories, releases, and clients.

- Webhook endpoints
  - Receive GitHub app events and future provider events.

### API behavior expectations

- Every collection endpoint supports pagination, sorting, filtering, and consistent response metadata.
- Upload endpoints return a processing handle so clients can poll status.
- Expensive list endpoints should support narrow field selection or summarized response modes if needed.

### Example payloads

SBOM upload request:

```json
{
  "org": "acme",
  "repo": "payments-api",
  "ref": "refs/heads/main",
  "commit_sha": "a1b2c3d4e5f6...",
  "snapshot_label": "build-1842",
  "format": "cyclonedx-json",
  "artifact": {
    "filename": "bom.json",
    "sha256": "7b1f...",
    "content_base64": "eyJib21Gb3JtYXQiOiJDeWNsb25lRFgifQ=="
  }
}
```

SARIF upload request:

```json
{
  "org": "acme",
  "repo": "payments-api",
  "ref": "refs/pull/42/head",
  "commit_sha": "f6e5d4c3b2a1...",
  "snapshot_label": "pr-42-sast",
  "tool": "semgrep",
  "artifact": {
    "filename": "results.sarif",
    "content_base64": "eyJ2ZXJzaW9uIjoiMi4xLjAifQ=="
  }
}
```

PR delta response:

```json
{
  "repo": "payments-api",
  "pull_request": 42,
  "base_ref": "refs/heads/main",
  "head_ref": "refs/pull/42/head",
  "quality_gate": "fail",
  "summary": {
    "new_vulnerabilities": 2,
    "resolved_vulnerabilities": 1,
    "new_findings": 3,
    "resolved_findings": 0
  },
  "blocking_reasons": [
    "new critical vulnerability CVE-2026-1234"
  ]
}
```

Client deployment creation:

```json
{
  "client_id": "northwind-prod",
  "release_id": "payments-api-7.5.2+build.14",
  "environment": "production",
  "status": "active",
  "deployed_at": "2026-05-23T14:20:00Z",
  "deployed_by": "release-bot",
  "notes": "blue/green promotion complete"
}
```

Impact analysis response:

```json
{
  "vulnerability_id": "CVE-2026-1234",
  "component": {
    "purl": "pkg:maven/com.example/widget@2.4.1"
  },
  "affected_repositories": [
    "payments-api",
    "billing-worker"
  ],
  "affected_releases": [
    "payments-api-7.5.2+build.14",
    "billing-worker-3.2.0"
  ],
  "affected_clients": [
    {
      "client_id": "northwind-prod",
      "environment": "production",
      "deployment_status": "active"
    }
  ]
}
```

## 8. RBAC model

The platform uses Apache Casbin with a PostgreSQL adapter for policy persistence.

### Roles

- `admin`
  - Full organization management, settings, integrations, user management, and export permissions.

- `developer`
  - Read repository data, upload analysis artifacts, trigger scans where allowed, and manage personal API keys.

- `release_manager`
  - Manage the release lifecycle for assigned repositories: create releases, publish releases, approve or reject release gates, manage deployments to clients, and override quality gate decisions. Scoped to specific organizations and optionally to individual repositories or teams.

- `auditor`
  - Read-only access across assigned organizational scope plus permission to export compliance evidence.

- `viewer`
  - Read-only access limited to assigned repositories or teams.

### Policy examples

```text
p, admin, orgs, *, *
p, developer, repos, read, *
p, developer, uploads, create, *
p, release_manager, releases, create, *
p, release_manager, releases, publish, *
p, release_manager, gates, decide, *
p, release_manager, deployments, manage, *
p, release_manager, repos, read, *
p, auditor, reports, export, *
p, viewer, repos, read, assigned
g, alice, admin, org:acme
g, bob, developer, team:payments
g, carol, release_manager, org:acme
g, dave, release_manager, repo:acme/payments
```

### Role mapping options

- Local platform-managed role assignments.
- Optional binding from git-provider org/team roles to platform roles.
- Role scoping supports organization-level, team-level, and repository-level granularity. A release manager for one repository does not automatically have release permissions on other repositories.
- Future support for external group claims from OIDC providers.

### Scoping model

Casbin evaluates policies against a request of the form `(subject, resource_type, action, scope)`. The `scope` dimension is the org, team, or repo the role is bound to via the `g` grouping rules. A release manager assigned to `repo:acme/payments` can only perform release actions on that specific repository. The platform enforces this by including the resource's owning scope in every policy check.

Example isolation:

- `g, dave, release_manager, repo:acme/payments` grants dave release permissions only on `acme/payments`.
- Dave requesting `(dave, releases, publish, repo:acme/billing)` is denied because there is no matching grouping rule for that scope.

## 9. Frontend architecture

### Stack

- Vue 3
- TypeScript
- Pinia
- Vue Router
- Tailwind CSS plus a headless component layer such as Headless UI or Radix Vue

### Frontend design goals

- Fast navigation across org, repo, ref, and snapshot contexts.
- Shared query/filter model across tabs.
- Strong empty/loading/error-state handling.
- Dark mode by default with a toggleable theme model.

### Key views

- Org overview
  - Health grid, top risks, trends, and repo drilldowns.

- Repo detail
  - Tabbed interface with `Weaknesses`, `Dependencies`, `Runtime`, and `Secrets`.

- Dependency graph
  - D3 force-directed graph with search, expand/collapse, and vulnerability overlay, carrying forward the useful interaction pattern from the current project.

- Dependency table
  - Sortable, filterable dependency inventory with vulnerability badges, fix hints, and source provenance.

- Finding table
  - Groupable view for code findings by tool, rule, severity, and location.

- Trend dashboards
  - Time-series visualizations for vulnerabilities, findings, and quality gate state.

- PR view
  - Diff-oriented view focused on new, resolved, and unchanged items.

- Ref comparison view
  - General-purpose diff screen with base/target ref pickers, showing added/removed/changed dependencies, version upgrades/downgrades, new/resolved vulnerabilities, and finding deltas. Supports comparing any branch against any release or two releases against each other.

- Client and delivery management
  - CRUD and impact views linking released artifacts to downstream consumers.

- Admin settings
  - Integrations, auth, notification rules, and policy controls.

## 10. Notification system

The notification subsystem is event-driven and template-based.

### Trigger examples

- scan completed
- new critical vulnerability
- quality gate changed from pass to fail
- stale repository data
- release branch regression

### Delivery channels

- generic webhook
- Slack via bot API
- Microsoft Teams via incoming webhook or adaptive card-compatible payloads
- email via SMTP

### Configuration model

- Rules can be scoped per organization, repository, or ref pattern.
- Each rule maps events to one or more channels.
- Messages are rendered from Go templates with event-specific context.
- Delivery attempts are logged with retry state and last error details.

## 11. MCP integration

The platform includes a built-in MCP server so AI assistants can query live security context using structured tools.

### Initial MCP tools

- `list_vulnerabilities(repo, ref, severity_filter)`
  - Returns vulnerability summaries for a repository ref.

- `get_dependency_tree(repo, ref)`
  - Returns a dependency tree or graph representation.

- `impact_analysis(cve_id)`
  - Returns affected repositories, releases, and clients.

- `compare_refs(repo, ref1, ref2)`
  - Returns a snapshot delta between two refs.

- `search_components(purl_pattern)`
  - Finds components across an organization or tenant.

### Deployment model

- In-process on a separate port for long-running service mode, or
- Exposed as a subcommand for local/sidecar usage.

The MCP server **calls through the API service layer** (the same internal Go interfaces used by REST handlers), never directly to PostgreSQL. This ensures all RBAC, tenancy, and authorization rules are enforced identically for AI clients and human users.

## 12. Deployment

### Single binary runtime

- `hibou-server serve` starts the API, embedded SPA, background workers, and optional MCP endpoint.
- `hibou upload sbom --repo payments-api --ref refs/heads/main --commit abc123 --file bom.json` uploads an SBOM from the CLI.
- `hibou vulns impact CVE-2026-1234` queries impact analysis from the terminal.
- `hibou completion zsh > _hibou` generates shell completions.
- The binary determines its personality from `os.Args[0]`: `hibou-server` exposes server commands, `hibou` (default) exposes user CLI commands.
- In the container image, `hibou` is the single binary and `hibou-server` is a symlink to it.

### Helm chart

The Helm chart should include:

- Deployment for the main service
- PostgreSQL as either a subchart or external dependency configuration
- Trivy server as a subchart that can be auto-deployed or disabled
- Ingress and TLS configuration
- ConfigMaps and Secrets for OIDC, SMTP, notification credentials, and provider credentials

### Docker Compose

Local development should provide:

- PostgreSQL
- Trivy server
- application service in live-reload or split frontend/backend dev mode

### CI integration

- Publish an official GitHub Action such as `uses: yourorg/secplatform-action@v1` to upload SBOM and SARIF artifacts after builds.

## 13. Testing strategy

### Backend testing

- Table-driven Go unit tests for core parsing, deduplication, policy, and service logic.
- `httptest` coverage for REST handlers and middleware.
- Testcontainers-backed integration tests for PostgreSQL and other runtime dependencies.

### Frontend testing

- Vitest for component and composable tests.
- Playwright for end-to-end flows including login, uploads, repo navigation, and PR views.

### CI expectations

- Lint using `golangci-lint` and ESLint.
- Typecheck the frontend.
- Run unit and integration tests on every pull request.
- Build the production binary and embedded SPA on every pull request.

### Fixture strategy

- Carry forward the concept of a fake-data generator similar to the current repository's `scripts/generate_fake_data.py` so dashboards, graphs, and history views can be exercised before full integration maturity.

## 14. Inspiration and references

- Coder (single Go binary plus embedded SPA): https://github.com/coder/coder
- ArgoCD (Go control plane with embedded frontend): https://github.com/argoproj/argo-cd
- Dependency-Track (SBOM-based vulnerability management): https://github.com/DependencyTrack/dependency-track
- DefectDojo (finding aggregation and workflow concepts): https://github.com/DefectDojo/django-DefectDojo
- SonarCloud (PR decoration and quality gates): https://sonarcloud.io
- Apache Casbin (RBAC framework): https://github.com/apache/casbin
- Dependency-Track issue `#4528` for multi-source scanning discussion
- Dependency-Track issue `#4122` for caching and performance discussion

## Open questions

- Final project name, branding, and license remain undecided.
- Whether the first release should expose only REST plus MCP, or also add an internal gRPC boundary for worker separation, is still open.
- Whether runtime and secrets should remain placeholders in the first public release or ship with limited integrations should be decided before milestone scoping.
- Whether PostgreSQL full-text search is sufficient initially or a dedicated search backend is needed later should be validated with realistic tenant sizes.

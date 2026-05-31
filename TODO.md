# DevSecOps Security Platform Roadmap

## Project framing

- [ ] Finalize project identity and governance
	- Decide the project name from the current placeholder set (`Wardeck`, `Bulwark`, `SecureHub`, `Fortguard`, `Bastion`) or a new candidate aligned with full-lifecycle DevSecOps.
	- Choose license, contribution model, code of conduct, maintainer structure, and release cadence.
	- Acceptance criteria hint: the repository has a stable public identity, contribution rules, and release ownership before external launch.

## Phase 0 - Project Bootstrap

- [x] Establish repository scaffolding and baseline architecture
	- Create a Go monorepo layout for API, workers, internal packages, Cobra CLI, and embedded web assets. The binary uses a multi-personality pattern (ArgoCD-style): invoked as `hibou` it acts as a user CLI, invoked as `hibou-server` (symlink) it acts as the server, with shell completion support (`completion bash/zsh/fish/powershell`).
	- Initialize the Vue 3 SPA with Vite, TypeScript, Pinia, Vue Router, and a shared design token layer.
	- Define package boundaries so the backend can embed the built SPA into a single distributable binary.
	- Acceptance criteria hint: a fresh clone builds both backend and frontend locally and produces one runnable binary.

- [x] Build the developer workflow and local toolchain
	- Add `Makefile` or `Taskfile` targets for lint, test, build, dev, code generation, and release packaging.
	- Add a devcontainer and Docker Compose stack for PostgreSQL, optional Trivy server, and local app development.
	- Standardize environment variable handling, example `.env` files, and secret injection conventions.
	- Acceptance criteria hint: a contributor can boot the full stack with one documented command path.

- [x] Create the CI/CD baseline
	- Add GitHub Actions for Go lint/test, frontend lint/test, typecheck, binary build, container build, and release packaging.
	- Add dependency caching, artifact retention, and tagged release automation.
	- Add basic provenance goals such as checksums and release notes generation.
	- Acceptance criteria hint: pull requests run deterministic checks and tagged commits produce releasable artifacts.

- [x] Create the Helm chart for production deployment
	- Add a `chart/` directory with a Helm chart that deploys the hibou server, PostgreSQL, and Trivy server as direct deployments (not subcharts).
	- Include configurable values for image tags, resource limits, environment variables, ingress, persistence, and replica counts.
	- Add health probe and service definitions matching the application's `/api/v1/health` endpoint.
	- Acceptance criteria hint: `helm install` produces a working stack with hibou, PostgreSQL, and Trivy without external chart dependencies.

- [x] Scaffold the Astro documentation site
	- Add a `docs/` directory with an Astro project (Starlight theme) for user guides, admin runbooks, deployment guides, and integration recipes.
	- Add a Makefile target for building and previewing the docs site locally.
	- Acceptance criteria hint: `make docs` builds a navigable documentation site from markdown content.

- [x] Define project conventions and architecture guardrails
	- Publish coding standards for Go and Vue, naming conventions, logging conventions, and API versioning rules.
	- Choose key libraries early: Cobra for CLI, router (`Chi`), migrations, query generation (`sqlc` or equivalent), auth/session layer, job runner, and UI primitives. Establish the `internal/` package layout from day one so domain logic lives in well-tested libraries and HTTP handlers, CLI commands, and workers are thin adapters.
	- Capture initial architecture decisions in ADRs so the first implementation phase does not drift.
	- Acceptance criteria hint: major foundational choices are documented and referenced by the initial codebase.

## Phase 1 - Core Foundation

- [x] Design the PostgreSQL data model and migration system
	- Model organizations, teams, repositories, refs, snapshots, components, vulnerabilities, findings, releases, deployments, clients, users, roles, and notification rules.
	- Treat tagged refs as the release source of truth while adding first-class release and deployment records for lifecycle tracking, rollback history, and client impact analysis.
	- Introduce migration tooling, seed data strategy, and idempotent schema evolution rules.
	- Add query generation and repository interfaces that keep read/write paths explicit.
	- Acceptance criteria hint: the platform can create a clean database, migrate forward, and serve typed reads/writes for core entities.

- [x] Implement authentication and session management
	- Add OIDC/OAuth2 login for SSO providers and git-provider login flows for GitHub-first onboarding.
	- Implement secure session handling, refresh behavior, logout, and tenant-aware user bootstrapping.
	- Support API keys for CI uploads with scoped permissions and expiry controls.
	- Acceptance criteria hint: both interactive users and CI systems can authenticate without bypassing RBAC.

- [x] Introduce RBAC and policy enforcement
	- Integrate Apache Casbin with PostgreSQL-backed policies.
	- Define baseline roles: `admin`, `developer`, `auditor`, `release_manager`, and `viewer`.
	- Map permissions to org, team, repository, and API-scope boundaries.
	- Acceptance criteria hint: policy tests demonstrate that reads, uploads, exports, and settings changes are constrained correctly.

- [x] Deliver multi-tenant organization hierarchy
	- Implement organization -> team -> repository relationships from day one.
	- Add tenant scoping for every API path, query, background job, and audit event.
	- Build bootstrap flows for org creation, repo enrollment, and membership assignment.
	- Acceptance criteria hint: data from one organization cannot be reached or inferred by another tenant.

- [x] Create the base REST API and OpenAPI contract
	- Stand up versioned JSON endpoints, middleware, validation, error envelopes, pagination, filtering, and sorting.
	- Cover upload status polling, PR delta and gate retrieval, clients, releases, deployments, notification rules, API keys, org membership, and RBAC administration in the public API surface.
	- Use `swaggo/swag` to generate OpenAPI/Swagger from Go handler annotations (following the Coder pattern: annotations on handlers, generated `swagger.json` in a dedicated `apidoc/` package, Swagger UI served at `/api/v1/docs`).
	- Add health, readiness, and metrics endpoints for operators.
	- Acceptance criteria hint: consumers can explore a stable documented API before advanced analysis features land.

- [x] Build the ingestion surface
	- Implement authenticated upload APIs for CycloneDX, SPDX, SARIF, and generic findings. Require ref, commit SHA, and repository identity on every upload so snapshots are pinned to exact source revisions.
	- Validate payload format, identify repo/ref ownership, persist raw artifacts where needed, and enqueue async processing.
	- Track ingestion status, failures, retryability, and audit metadata.
	- Acceptance criteria hint: a CI pipeline can submit SBOM and SARIF data and observe processing state end to end.

- [x] Add GitHub app and webhook integration
	- Support repo discovery, installation setup, webhook verification, PR/ref mapping, and status update permissions.
	- Establish the minimum event set for push, pull request, and repository lifecycle events.
	- Prepare provider abstraction boundaries so Forgejo/Gitea and GitLab can be added later without rewriting ingestion flows.
	- Acceptance criteria hint: a GitHub-connected org can onboard repositories and tie uploads to canonical refs.

- [x] Ship the first usable frontend shell
	- Implement the application shell, auth flow, tenant selector, sidebar navigation, theme handling, and route guards.
	- Add placeholder overview, repository, uploads, admin, and settings views wired to live APIs.
	- Build a consistent empty-state, loading-state, and error-state system.
	- Acceptance criteria hint: authenticated users can navigate a coherent shell backed by real tenant-aware data.

## Phase 2 - Analysis Engine

- [x] Build the canonical advisory data model and alias resolution
	- Design a global advisory table storing one record per real vulnerability, with transitive alias merging across CVE, GHSA, OSV, PYSEC, RUSTSEC, GO-, and other identifier namespaces.
	- Store affected ranges per advisory per package (ecosystem + name + version range + fixed version), sourced from multiple providers independently.
	- Avoid the DependencyTrack duplication problem (DT#4122, DT#4528): if NVD, OSV, and Trivy all report the same issue under different IDs, the platform stores one advisory with multiple aliases and sources.
	- Be aware that aggregator databases like OSV already include GHSA, PYSEC, RUSTSEC, GO- advisories — query providers in priority order to avoid redundant lookups: OSV first (broadest aggregation), NVD for CVSS enrichment and CVEs not in OSV, then specialized providers.
	- Acceptance criteria hint: a single CVE reported by three providers results in one advisory record with three source entries and a merged alias set.

- [x] Implement the advisory provider framework
	- Define an `AdvisoryProvider` interface that all vulnerability data sources implement equally. No provider is a first-class citizen — Trivy, OSV, NVD, Sonatype, and future providers are all pluggable adapters.
	- Require batch query support where the provider API allows it (OSV: 1000/request, Sonatype OSS Index: 128/request, NVD: bulk download/mirror mode).
	- Each provider must declare its supported ecosystems, rate limits, and batch capabilities.
	- Each provider must have dedicated integration tests using recorded HTTP fixtures (go-vcr or similar), plus unit tests for response parsing, alias extraction, and error handling.
	- Initial providers: OSV.dev (REST batch), NVD (REST + optional mirror), GitHub Advisory Database (GraphQL batch), Trivy (Twirp client as scanner, DB as advisory source), Sonatype OSS Index (REST batch).
	- Acceptance criteria hint: adding a new provider requires only implementing the interface and registering it — no changes to the scan pipeline.

- [x] Implement the global advisory cache and query efficiency layer
	- Cache advisory query results at the package level (`{ecosystem}:{package_name}:{provider}`), not per-repo or per-org. If 50 repos all depend on `lodash`, the platform queries OSV once.
	- Use TTL-based cache expiry: configurable per provider (e.g., 6h for OSV, 24h for NVD), with background refresh for expired entries.
	- Track cache hit rate and last-fetched timestamps per provider for operator visibility.
	- When processing an SBOM: extract unique `(ecosystem, name, version)` tuples, deduplicate globally across the entire instance, batch-query only cache misses, then compute matches.
	- Acceptance criteria hint: reprocessing the same SBOM within the cache TTL produces zero external API calls.

- [x] Build the ecosystem-aware version comparison library
	- Implement ecosystem-specific version parsers and comparators in a standalone, heavily tested package (`internal/versioncmp/`). Each ecosystem has different versioning rules and false positives from naive string comparison are unacceptable.
	- Supported ecosystems: Go (semver with module paths, `golang.org/x/mod/semver`), npm (semver ranges), Maven (Maven version ordering), PyPI (PEP 440), Cargo (semver), NuGet (4-part semver), RubyGems (Gem::Version).
	- OS package manager versioning — these are the primary source of false positives in other tools: RPM/RHEL/Fedora/SUSE (`epoch:version-release`, `rpmvercmp` algorithm, arch stripping), Debian/Ubuntu (`epoch:upstream-revision`, `dpkg --compare-versions`), Alpine APK (Alpine-specific version ordering with pre/post suffixes and `~` sort behavior).
	- Version strings from SBOMs often include architecture suffixes (e.g., `1.2.3-1.el9.x86_64`) that must be stripped before comparison. Failure to split arch from version is a known cause of false positives.
	- Implement range matching: given a vulnerability's affected range (`>=1.0.0, <1.2.3`) and an installed version (`1.1.5`), determine whether the package is affected.
	- Require **hundreds of test cases** per ecosystem, including edge cases: pre-release versions, build metadata, epoch-prefixed versions, RPM release suffixes, distro backport versions (e.g., Debian `1.2.3-1+deb12u1` patching CVEs fixed upstream in `1.2.4`), and known false-positive scenarios from other tools.
	- Acceptance criteria hint: version comparison tests cover documented edge cases from each ecosystem's specification and produce zero false positives on a curated test suite.

- [x] Implement the scan orchestrator and vulnerability matcher
	- Build a provider-agnostic scan orchestrator that accepts an SBOM (CycloneDX or SPDX), extracts components, queries advisory providers via the cache layer, and computes vulnerability matches using the version comparison library.
	- The scanner runs as an async job triggered by SBOM upload, webhook push events, or manual rescan.
	- Persist scan provenance: which providers were queried, cache hit/miss counts, provider response times, DB version metadata, and retry behavior.
	- Compute `vuln_match` records linking each snapshot component to matching advisories via version range evaluation. Track `is_affected`, `suppressed`, `first_seen_at`, `last_seen_at`.
	- Expose per-provider last-scan timestamps so users can see when each advisory database was last queried. Surface this in the UI per repository and globally.
	- Allow users to manually trigger a rescan against one, several, or all providers — bypassing the cache TTL for that invocation. A manual rescan from one repo refreshes the global advisory cache for all queried packages, benefiting every repo that shares those dependencies.
	- All user-initiated actions (manual rescan, suppression, gate override, notification rule change) must be recorded in an immutable audit log with actor, timestamp, action, target, and context. This audit log tracks platform operations — distinct from the compliance retention of vulnerability state history.
	- Acceptance criteria hint: an uploaded SBOM produces persisted vulnerability matches linked to the originating snapshot, with full provenance of which providers contributed. Users can see freshness per provider and force a refresh. Every manual action is traceable.

- [x] Implement severity normalization and deduplication
	- Normalize severity across CVSS v2, v3.0, v3.1, v4.0, and tool-native scoring into five canonical levels: `critical`, `high`, `medium`, `low`, `info`.
	- When multiple providers report different CVSS scores for the same advisory, apply a deterministic merge strategy: prefer NVD CVSS when available, then the highest-scoring provider, with full source attribution.
	- Aggregate fix versions, affected ranges, and CWE metadata from all providers onto the canonical advisory.
	- Acceptance criteria hint: the dependency view shows one coherent record per real issue with the best available severity data, regardless of how many providers reported it.

- [x] Add malware detection support
	- Extend the advisory model with `is_malware: bool` and `malware_type` classification (typosquat, dependency confusion, backdoor, cryptominer, data exfiltration).
	- Ingest malware signals from OSV (`MALWARE` type advisories), OpenSSF Package Analysis, and ecosystem-specific sources (npm audit `ismalware` flag).
	- Surface malware findings prominently in the UI — malware is always critical severity and should be visually distinct from vulnerability findings.
	- Acceptance criteria hint: a known malicious package in an SBOM is flagged as malware with source attribution.

- [x] Parse and store SARIF findings at scale
	- Implement SARIF 2.1.0 ingestion, rule extraction, location hashing for deduplication, codeflow capture where useful, and tool metadata storage.
	- Support findings from any SARIF producer, including Semgrep, CodeQL, ESLint, and commercial SAST tools.
	- Compute stable fingerprints for deduplication: `sha256(repo + tool + rule_id + file_path + start_line)`.
	- Add enrichment hooks for CWE metadata and severity mapping from rule catalogs.
	- Acceptance criteria hint: code-level findings from different SAST tools can be queried in one normalized model without duplicates.

- [x] Add generic findings ingestion for non-SARIF tools
	- Design a simple POST API for arbitrary findings with tool name, severity, file location, description, and metadata map.
	- Allow custom AI detectors and niche tools to participate without forcing SARIF conversion.
	- Preserve enough structure (fingerprint, rule ID, file path) for deduplication, filtering, and PR diffing.
	- Acceptance criteria hint: external tools without native SARIF support can still appear in repository analysis views.

- [x] Build the event bus and subscriber architecture
	- Implement an in-process typed pub/sub event bus (`internal/events/`). Event types: `scan.requested`, `scan.completed`, `scan.failed`, `vuln.discovered`, `finding.created`, `gate.passed`, `gate.failed`, `notification.new`.
	- All business logic lives in service packages. Services publish events after completing work. Event subscribers (notification dispatcher, forge annotator, WebSocket hub) are thin consumers — no business logic duplication.
	- Keep event contracts versioned and typed so internal subscribers can evolve without breaking the scan or notification pipeline.
	- Acceptance criteria hint: scan and finding workflows publish typed events once, and multiple subscribers can react without duplicating domain logic.

- [x] Add WebSocket delivery for real-time updates
	- Add a WebSocket endpoint (`GET /api/v1/ws`) using `github.com/coder/websocket` (successor to `nhooyr.io/websocket`) for real-time frontend updates. Auth on upgrade via session cookie or Bearer token. Per-user channels with topic subscription.
	- WS messages carry the payload when small (notification, scan status, severity counts), reference-only when large (send count + signal to refetch).
	- Every piece of data is always available via REST. WebSocket is additive — the frontend works without it (graceful degradation).
	- Acceptance criteria hint: a scan completion triggers a WS push to connected users and optionally dispatches to external integrations, with zero code duplication between REST and WS paths.

- [x] Implement in-app notification system
	- Persist notifications per user in the database with type, title, body, link, severity, read/unread status, and created timestamp.
	- REST endpoints: list notifications (paginated, filterable), mark as read (single + bulk), get unread count.
	- The notification dispatcher subscribes to the event bus and creates in-app notifications based on configurable rules per org.
	- Frontend: Pinia notification store, bell icon in header with unread badge, dropdown panel, toast on new events via WebSocket.
	- Acceptance criteria hint: users see a live-updating notification badge and can review, filter, and dismiss notifications.

- [x] Build the notification dispatcher and integration framework
	- Define a `notify.Sender` interface: `Send(ctx, event) error`. Each external integration implements it.
	- Notification rules are stored per org in the database: "when {event_type} on {scope} → send to {integration}". Scopes: org-wide, team, repo, ref pattern. Filters: severity, tool source.
	- Initial integrations: Slack (incoming webhook), Microsoft Teams (Adaptive Card webhook), Discord (webhook with embeds), generic outgoing webhook (POST JSON with HMAC-SHA256 signature), email (SMTP).
	- Each integration includes: delivery logging, retry with exponential backoff, failure surfacing, rate limiting, and suppression rules for noisy repos.
	- Acceptance criteria hint: orgs can route alerts to multiple channels with configurable rules and auditable delivery state.

- [x] Deliver PR analysis and delta computation
	- Compare PR snapshots against the target branch latest snapshot for both vulnerability matches and code findings.
	- Compute new, resolved, and unchanged items using stable deduplication keys (advisory canonical ID for vulns, fingerprint for findings).
	- Implement configurable quality gate rules: max new critical vulns (default: 0), max new high vulns (default: 0), max new SAST findings by severity. Rules are stored per org/repo in the database.
	- **Branch-aware quality gates**: quality gate rules can target specific branch patterns (e.g., `main`, `release/*`, `*`). A restrictive gate on `main` does not block PRs targeting `develop` or older release branches. Gates are evaluated by matching the PR's target branch against the gate's branch pattern, most specific match wins. If no branch-specific gate matches, fall back to the repo default, then the org default.
	- Acceptance criteria hint: a PR upload yields an actionable delta summary rather than a raw full snapshot dump. A PR targeting `release/1.x` uses different gate thresholds than one targeting `main`.

- [x] Implement forge PR annotations and checks
	- Annotations are **delta-only**: only issues **newly introduced by the PR** (compared against the target branch's latest snapshot) are annotated. Existing issues in the target branch are never surfaced as PR annotations — they belong to the branch view, not the PR review.
	- Post **line-level annotations** on PR diffs for forges that support it (GitHub review comments on changed lines, Forgejo/Gitea line comments, GitLab MR discussions). Only annotate lines that are part of the PR diff. Each annotation links to the specific finding or vulnerability match.
	- Post a single **summary comment** on the PR that is **updated in place** on each CI build (not a new comment every time). The comment includes: quality gate result (pass/fail), counts of new/resolved issues by severity, delta table, and a link to the full report in Hibou. On subsequent pushes to the same PR, the existing comment is edited — never duplicated.
	- Use the existing `forge.Provider` interface — works identically for GitHub, Forgejo, and GitLab. Add `CreatePRReviewComment`, `UpsertPRComment` (create-or-update by marker), and `ListPRComments` methods.
	- Add controls to avoid annotation spam: collapse findings by rule, limit inline annotations per PR (default: 30), skip annotations on unchanged files.
	- Capture delivery failures and retry paths for forge API outages.
	- Acceptance criteria hint: a PR shows inline annotations only for newly introduced issues, one always-current summary comment, and no duplicate comments across re-runs.

- [x] Design the data retention and compliance strategy
	- Implement configurable snapshot retention per org: active (hot, queryable), archived (cold, compressed, queryable with latency), and purged.
	- Default retention: keep all snapshots for the latest 90 days in hot storage, archive older snapshots for up to 7 years (configurable), never auto-purge unless the operator explicitly requests it.
	- For compliance (SOC 2, ISO 27001, FedRAMP, PCI DSS): audit-grade retention requires preserving the full history of vulnerability state at any point in time. Store immutable snapshot records with advisory state as-of-scan timestamps.
	- Raw SBOM and SARIF artifacts go to object storage (S3/MinIO/filesystem) with references in PostgreSQL — do not bloat the primary database with multi-MB JSON payloads.
	- Advisory history: retain advisory modification history (when a CVE was published, when severity changed, when a fix was released) for compliance audit trails.
	- Maintain an immutable audit log for all user and system actions: scans triggered, suppressions applied/removed, gate overrides, configuration changes, data exports. The audit log serves operational accountability ("who did what"), while compliance retention serves regulatory evidence ("what was the state at date X"). These are complementary but distinct.
	- Provide a compliance export API: "give me the full vulnerability state of repo X as of date Y" — this requires point-in-time advisory snapshots.
	- Acceptance criteria hint: an auditor can request the vulnerability posture of any repository at any historical date and receive a complete, verifiable report.

- [x] Implement config-as-code for quality gates
	- Define a `.hibou.yaml` configuration file that lives in the repository's default branch. The file is **focused exclusively on weakness (code finding) quality gates** — branch-aware thresholds for new SAST/code findings that determine whether a PR passes or fails.
	- **Separation of concerns**:
	  - **`.hibou.yaml`** (dev team, in code): weakness/finding thresholds per branch pattern. The dev team is the authority on code quality risk tolerance.
	  - **Platform UI/API** (security team, RBAC-gated): vulnerability (CVE) gating based on severity, EPSS exploitability scores, and CISA KEV status. Advisory provider selection, suppressions, notification routing, path exclusions — all platform-only. The security team is the authority on dependency risk.
	  - **Gate overrides**: when a PR is blocked (by either weakness or vulnerability gates), an `admin` or `release_manager` can approve a gate override via the platform. The override is recorded in the immutable audit log with actor, reason, and affected CVEs/findings. This is the escape hatch — never in code.
	- Publish a **JSON Schema** (`hibou-config.schema.json`) for the config file, hosted at a well-known URL and referenced via `$schema` in the YAML. This provides IDE autocompletion and validation in VS Code (via YAML extension), JetBrains, and other editors that support JSON Schema for YAML files.
	- Example `.hibou.yaml` structure:
	  ```yaml
	  # yaml-language-server: $schema=https://hibou.dev/schemas/v1/hibou-config.schema.json
	  version: 1
	  quality_gates:
	    - branches: ["main", "release/*"]
	      weaknesses:
	        max_critical: 0
	        max_high: 0
	    - branches: ["develop", "feature/*"]
	      weaknesses:
	        max_critical: 0
	        max_high: 2
			max_medium: 15
	  ```
	- On repo onboarding (first detection via webhook or manual enrollment), Hibou opens an **onboarding PR** (like Renovate) that adds a default `.hibou.yaml` to the repo. The PR description explains what Hibou does, how the config works, and links to docs. The PR uses a bot account or the forge app identity.
	- Config is read from the default branch on every scan. Changes to `.hibou.yaml` are tracked in the audit log. Invalid config is reported as a scan warning, not a hard failure — the platform falls back to org-level defaults.
	- When `.hibou.yaml` defines weakness gates for a branch pattern, those **override** the platform DB weakness gates for matching branches. If no file-based gate matches a target branch, the platform falls back to DB-defined repo gates, then org-wide gates. Vulnerability gates from the platform DB are **always evaluated independently** — `.hibou.yaml` cannot weaken or disable them.
	- Acceptance criteria hint: merging the onboarding PR activates repo-level weakness gates. IDE users get full autocompletion on `.hibou.yaml`. Different branches can have different thresholds. Developers cannot bypass vulnerability gates or security controls via this file.

- [x] Migrate from `nhooyr.io/websocket` to `github.com/coder/websocket`
	- Replace the deprecated `nhooyr.io/websocket` dependency with its maintained successor `github.com/coder/websocket` (same API, drop-in replacement).
	- Update all import paths in `internal/ws/` and tests.
	- Acceptance criteria hint: `go.mod` references `github.com/coder/websocket`, no `nhooyr.io` imports remain.

## Phase 3 - Dashboard and Visualization

### Design Language

The UI draws inspiration from a combination of **GitHub** and **SonarCloud**:

- **GitHub** for overall structure: top navbar (brand, search, notifications bell, user avatar/photo with menu), org/repo navigation, horizontal tab navigation within repos, clean typography, and the general content layout.
- **SonarCloud** for the branch/PR inspection model: a dropdown selector that lets you switch between branches and pull requests to inspect their analysis results. However, improve upon SonarCloud's approach by adding PR lifecycle awareness (see below).
- **Coder** for the audit log UX and settings pages: filterable table with expandable rows.

The result should feel like a GitHub-native security tool — users familiar with GitHub's navigation will feel immediately at home.

- [x] Redesign the global layout and navigation
	- **Top navbar** (GitHub-style): Hibou logo/brand on the left, global search in the center, notification bell + user avatar (with photo from forge OAuth) on the right. Org selector as a dropdown next to the brand (like GitHub's org/repo switcher).
	- **Left sidebar** (narrow icon rail): icons for Dashboard, Repositories, Teams, Audit Logs, Settings. Hovering or clicking expands the label. Collapsible — 48–56px when collapsed, ~200px when expanded.
	- **User links**: clicking the avatar shows a dropdown with profile, API keys, preferences, and logout — matching GitHub's user menu pattern.
	- Remove the legacy `Uploads` sidebar entry entirely — upload status is surfaced contextually on repository pages and ingestion is an API-only concern. Replace it with `Audit Logs`.
	- Ensure the layout is responsive: on small screens the rail collapses to icons-only, on very small screens it becomes a hamburger top-nav.
	- Acceptance criteria hint: the shell looks and feels like GitHub meets a modern DevOps tool — not a 2018 admin panel.

- [x] Build the Audit Logs view (Coder-style)
	- Replace the current `Uploads` view with a full audit log page at `/orgs/:provider/:slug/audit`.
	- Display a filterable, paginated table of audit events with columns: timestamp, actor (user or system), action, resource type, resource name, IP address, and status.
	- Add filter controls above the table: multi-select dropdowns for action type (e.g., `scan.triggered`, `suppression.created`, `gate.overridden`, `config.changed`, `upload.completed`, `member.added`), resource type (repository, organization, team, API key, notification rule), actor, and date range picker.
	- Each row is expandable or links to a detail panel showing the full event payload (JSON diff for config changes, before/after for suppressions, etc.).
	- Support URL-shareable filter state via query parameters.
	- Acceptance criteria hint: an admin can answer "who changed what, when" with the same UX quality as the Coder audit log.

- [x] Build the organization overview dashboard
	- Show health summaries, severity distribution, trending indicators, and top-risk repositories across the tenant.
	- Add filtering by team, repo, severity, tool, and time window.
	- Expose drilldowns that connect aggregate widgets to detailed views.
	- Acceptance criteria hint: platform operators can identify hotspots without leaving the overview page.

- [x] Implement repository detail views with horizontal tab navigation
	- Add a repository landing page with a header showing repo name, provider badge, and a **branch/PR selector** (SonarCloud-inspired, improved).
	- Below the header, render **horizontal tabs**: `Weaknesses` | `Dependencies` | `Malware` | `Runtime` | `Secrets`. Tabs use `RouterLink` with active indicator underline (GitHub-style). No vertical stacked cards.
	- `Runtime` and `Secrets` tabs show a tasteful "coming soon" empty state (icon + short description) — not a grey card.
	- The `Malware` tab surfaces known malicious packages detected during SBOM analysis, visually distinct from standard vulnerability findings.
	- Tab selection and branch/PR selection are both reflected in the URL (`/orgs/:provider/:slug/repos/:repo/weaknesses?ref=main`) so views are shareable and bookmarkable.
	- Preserve consistent cross-tab filtering: severity, tool source, and status filters persist when switching tabs.
	- Acceptance criteria hint: users can switch between analysis domains with one click and share deep links to specific views.

- [x] Implement the branch/PR selector with lifecycle awareness
	- Inspired by SonarCloud's branch/PR picker but improved with real-time lifecycle state:
	- The selector dropdown is divided into sections: **Branches** (sorted: default branch first, then alphabetical) and **Pull Requests** (sorted: most recently updated first).
	- Each branch shows: name, quality gate status badge (pass/fail/pending), last scan date.
	- Each PR shows: PR number, title (truncated), source → target indicator, quality gate status.
	- **PR lifecycle awareness** (unlike SonarCloud): Hibou detects PR state from the forge (open, merged, closed) via webhooks. Merged/closed PRs are:
	  1. Immediately marked visually: ~~strikethrough title~~, dimmed/greyed-out row, merged badge (purple) or closed badge (red).
	  2. After a configurable grace period (default: 7 days), removed from the selector entirely. Data is retained in the DB for historical queries but no longer clutters the picker.
	- The selector has a search/filter input (like SonarCloud) for finding specific branches or PRs by name/number.
	- Support tabs within the dropdown: `All` | `Branches` | `Pull Requests` (like SonarCloud).
	- Acceptance criteria hint: the selector never shows stale merged PRs indefinitely. Users always see current, actionable branches and PRs. Merged PRs are visually struck through immediately and auto-pruned from the UI after a grace period.

- [x] Deliver the weaknesses experience
	- Build a findings table grouped and filterable by tool, rule, severity, file path, and status.
	- Support deduplicated aggregation across sources and deep-linking into raw evidence.
	- Add trend widgets for issue arrival and remediation over time.
	- Acceptance criteria hint: one repository can surface all code-level weaknesses regardless of originating scanner.

- [x] Deliver the dependencies experience
	- Build a full dependency table with vulnerability overlays, fix-version hints, and source attribution.
	- Implement an SBOM viewer and an interactive dependency graph with search, expand/collapse, and vulnerable-node highlighting.
	- Support large graphs and tables with pagination, virtualization, or incremental loading.
	- Acceptance criteria hint: users can identify vulnerable transitive dependencies without drowning in duplicate graph noise.

- [x] Add branch, release, and snapshot navigation
	- Model branch and release lists, detail pages, and ref-aware navigation patterns.
	- Expose latest snapshot status, scan freshness, and comparison entry points.
	- Connect client mapping views to release entities.
	- Acceptance criteria hint: the UI supports both active branches and shipped releases as first-class analysis targets.

- [x] Deliver general-purpose ref comparison and SBOM diffing
	- Build a comparison view that accepts any two refs (branch vs release, release vs release, branch vs branch) and shows a full dependency diff: added, removed, and version-changed components, plus new and resolved vulnerabilities.
	- Include a ref-picker with autocomplete for base and target selection.
	- Show version upgrade/downgrade direction, vulnerability impact of changes, and finding deltas.
	- Expose via both API (`GET /api/v1/repos/{repo}/compare?base=...&target=...`) and CLI (`secplatform compare`).
	- Acceptance criteria hint: users can compare any two refs to see exactly what changed in the dependency tree and vulnerability posture between them.

- [x] Build time-series trends and historical analytics
	- Add charts for vulnerability counts, finding counts, quality gate results, and remediation trends.
	- Support time-window selection, grouping, and per-tool overlays.
	- Retain enough historical snapshot data to support longitudinal reporting without expensive recomputation.
	- Acceptance criteria hint: teams can measure whether risk is improving or regressing over time.

- [x] Introduce PR-focused review views
	- Create a PR summary page with new/resolved/unchanged findings and quality gate outcomes.
	- Mirror the fast scan-to-action model used by modern PR analysis tools while preserving drilldown into full details.
	- Provide comparison links back to branch snapshots when deeper analysis is needed.
	- Acceptance criteria hint: reviewers can triage PR risk from a focused delta screen rather than a full repository dashboard.

- [x] Add client and delivery management
	- Implement CRUD for clients, releases, deployments, and impact lookup workflows.
	- Preserve deployment history, rollback state, environment-specific rollout tracking, and contact metadata for downstream consumers.
	- Support views such as "which clients are impacted by CVE-X" and "which releases are deployed at client Y".
	- Ensure this data remains tenant-scoped and exportable for operations teams.
	- Acceptance criteria hint: downstream release impact can be answered from the platform without external spreadsheets.

- [x] Add global search and advanced filtering
	- Support cross-repo search for vulnerabilities, components, findings, and affected clients.
	- Provide structured filters, saved views, and sharable URLs.
	- Index key search fields without coupling the first version to an external search engine.
	- Acceptance criteria hint: security teams can answer tenant-wide impact questions in seconds.

## Phase 4 - AI, Notifications, and Integrations

- [x] Build the embedded MCP server
	- Expose security-aware MCP tools for vulnerability listings, dependency graphs, impact analysis, and ref comparisons.
	- Reuse the platform authorization model so AI clients only see data they are entitled to access.
	- Document prompt-safe response shapes and pagination behavior for large result sets.
	- Acceptance criteria hint: an MCP-compatible assistant can query live platform data without bespoke integration code.

- [x] Deliver the notifications subsystem
	- Extend the Phase 2 notification dispatcher with advanced features: template customization per integration, delivery analytics dashboard, webhook replay for debugging, and bulk notification management.
	- Add per-integration health monitoring: last successful delivery, failure rate, circuit breaker state.
	- Support rate control and suppression rules for noisy repositories or transient scan churn.
	- **Done**: Dispatcher evaluates notification rules when routing events. Circuit breaker (5 consecutive failures, 30min probe window). Per-integration rate limiting (30/min sliding window). Integration health API (`GET /integrations/{id}/health`). Webhook replay (`POST /integrations/{id}/replay`). SSRF protection on outbound senders (private IP blocking, proxy disabled). Async dispatch uses detached background context.
	- **Remaining**: template customization, delivery analytics dashboard.
	- Acceptance criteria hint: orgs can route actionable alerts to their preferred channels with auditable delivery state and operational visibility.

- [x] Add an alert rules engine
	- Support configurable triggers such as new critical vulnerability, quality gate failure, release branch regression, and stale scan data.
	- Add rule scoping by org, team, repo, ref pattern, severity, and tool source.
	- Surface a dry-run or preview mode so administrators can validate rules before enabling them.
	- **Done**: Notification rules CRUD API (5 endpoints). Rules stored per org with event_type, conditions JSONB (severity/repo scope), destination_type+config. Dry-run preview (`POST /notification-rules/dry-run`). Team ID + ref pattern glob scoping in rule conditions. Stale scan detection (48h threshold, hourly check, publishes `scan.stale` events). Validated event types and destination types including Discord.
	- Acceptance criteria hint: alerts are configurable enough to be useful without requiring code changes.

- [x] Implement multi-personality binary
	- The single compiled binary changes its available commands based on the name it is invoked as (`os.Args[0]`).
	- **`hibou`** (default): User CLI personality. Exposes only client-side commands (`upload`, `repos`, `vulns`, `deps`, `clients`, `releases`, `config`, `completion`, `version`). Server commands like `serve` are hidden and disabled. This is what developers and CI pipelines install.
	- **`hibou-server`**: Server personality. Exposes `serve`, `migrate`, `completion`, and `version`. User CLI commands are hidden. Used as the container entrypoint via a symlink.
	- **`hibou-worker`** (future): Worker personality for scaled-out deployments.
	- Update `cmd/root.go` to inspect `os.Args[0]` (resolved past symlinks), determine the personality, and conditionally register command subtrees.
	- Update the `Dockerfile` to copy the binary as `hibou` and create a symlink `hibou-server -> hibou`. Use `hibou-server serve` as the container `CMD`.
	- Update the `Makefile` build target to produce a single `hibou` binary. The `make install` target should also create the `hibou-server` symlink.
	- Ensure `hibou --help` never shows `serve` or other server internals — keep the user CLI clean and focused.
	- This must be completed before the GitHub Action, since the action will distribute `hibou` as a user CLI tool.
	- Acceptance criteria hint: `hibou --help` shows only client commands, `hibou-server --help` shows only server commands, both resolve to the same binary file.

- [x] Auto-configure Forgejo webhooks in dev setup
	- `scripts/setup-dev.sh` now creates webhooks on all Forgejo repos for the admin user, pointing to `http://host.docker.internal:8080/api/v1/webhooks/forgejo` with HMAC-SHA256 secret validation.
	- `scripts/seed-real.sh` creates a webhook on the mirrored k9s repo after seeding.
	- `docker-compose.yml` adds `extra_hosts: ["host.docker.internal:host-gateway"]` to the forgejo service so webhooks can reach the host.
	- Webhook secret is auto-configured in `.env` as `HIBOU_FORGE_0_WEBHOOK_SECRET`.
	- Events: push, pull_request, create, delete.
	- Future: GitHub and GitLab webhook auto-configuration will follow the same pattern.
	- Acceptance criteria hint: `make start` results in Forgejo automatically notifying hibou on push and PR events.

- [x] Add org dropdown to navbar breadcrumb
	- The organization name in the top navbar now has a ChevronDown dropdown (matching the repo dropdown pattern).
	- Dropdown shows all orgs from `orgStore.orgs` with search filtering (when >= 5 orgs).
	- Current org is highlighted. Clicking an org navigates to it and closes the dropdown.
	- Dropdown only appears when there are multiple orgs.

- [x] Implement CLI UX for user personality
	- `hibou login` — authenticate with server URL + API token (interactive or `--token` flag). Validates with `/users/me`. Stores in `~/.config/hibou/config.yaml`.
	- `hibou login --sso` — opens browser to server UI for SSO login + API key creation, then prompts to paste token.
	- `hibou logout` — clears stored token.
	- `hibou status` — shows current server, org, user info, auth status.
	- `hibou upload sbom|sarif|findings` — uploads security artifacts. Supports `--server`/`--token` flags and `HIBOU_SERVER`/`HIBOU_TOKEN` env vars for CI. SARIF and findings accept `--tool` flag.
	- `hibou repos list|show` — thin wrappers over repo API.
	- `hibou config set-org|show` — manage default org context.
	- Server-side `POST /api/v1/auth/cli-token` endpoint for browser-to-CLI token exchange (session-only, rejects API key auth).
	- `internal/cliconfig/` — config file read/write with 0600 permissions.
	- `internal/cliclient/` — thin HTTP client with Bearer auth and API envelope handling.
	- Future: `vulns`, `deps`, `clients`, `releases` commands will be added as APIs stabilize.
	- Acceptance criteria hint: `hibou login && hibou repos list && hibou upload sbom sbom.json --org forgejo/devtools --repo myapp --ref refs/heads/main --sha abc123` works end-to-end.

- [x] Publish an official GitHub Action
	- Create a maintained action that uploads SBOM, SARIF, and generic findings from CI pipelines.
	- Support API-key auth, PR/ref auto-detection, retries, and clear failure messages.
	- Provide reference workflows for common build systems.
	- Acceptance criteria hint: a GitHub repository can adopt the platform from CI in minutes.
	- **Done**: Composite action for GitHub/Forgejo, GitLab CI component, unified upload endpoint with auto-detection, binary download from server, multi-file support. Coverage upload supported.

- [x] Expand the REST API to full platform coverage
	- Add CRUD for tenants, repos, client mappings, notification rules, API keys, and administrative settings.
	- Ensure every UI workflow has a public API equivalent.
	- Tighten consistency around pagination, filtering, partial updates, and idempotency.
	- **Done**: Integrations CRUD (5 endpoints), Notification Rules CRUD (5 endpoints), Quality Gates CRUD (5 endpoints), Org Members CRUD (4 endpoints: list/add/remove/update-role with last-admin protection), Team Members CRUD (4 endpoints), Suppression management (suppress/unsuppress with audit logging), Repository CRUD coverage for enrollment/update/removal (3 endpoints), Settings API (GET/PUT with partial-update merge preserving unknown JSONB keys, TLP validation) — 30 new endpoints total. Cross-org authz enforced. FK violation handling. Integration config redacted for non-admin reads.
	- Acceptance criteria hint: automation clients are not forced to rely on private or UI-only behavior.

- [x] Deliver compliance-oriented reporting
	- Add exportable HTML and PDF reporting aimed at auditors and regulated environments.
	- Provide evidence views for findings history, vulnerability posture, policy status, and release impact.
	- Record report generation metadata for traceability.
	- **ISO 27001:2022 compliance evidence**: generate per-control evidence exports mapping platform data to Annex A.8 technological controls. The platform can produce auditor-ready evidence for:
	  - **A.8.8 Management of technical vulnerabilities**: vulnerability inventory per repo/org, scan freshness per provider, remediation timeline (first_seen → fixed), VEX statements with justification and provenance, quality gate history
	  - **A.8.25 Secure development lifecycle**: quality gate pass/fail history per branch, PR analysis results, config-as-code audit trail
	  - **A.8.28 Secure Coding**: SAST findings inventory, remediation trends, tool coverage per repo
	  - **A.8.29 Security Testing in Dev & Acceptance**: test coverage metrics, SAST/SCA gate results per release, PR annotation delivery proof
	  - **A.8.4 Access to source code** (partial): audit log of platform actions (who accessed what, who changed what), RBAC policy export
	  - **A.8.7 Protection against malware** (partial): malware detection results from SBOM analysis, secret scanning results (when implemented)
	  - **A.8.19 Installation of software** (partial): SBOM inventory per deployment/release, component version tracking, EOL status
	  - **A.8.30 Outsourced Development** (partial): supply chain visibility via SBOM, supplier VEX import history, license compliance status
	- **Statement of Applicability (SoA) export**: generate a pre-filled SoA document mapping which Annex A controls the platform covers, with links to the relevant evidence reports. This helps organizations document their ISMS control selection.
	- **Point-in-time compliance snapshot**: "give me the full vulnerability and compliance posture of repo X as of date Y" — requires the existing retention and advisory history infrastructure.
	- **Done**: JSON API for compliance export (`GET /compliance/export`), ISO 27001 evidence report (`GET /compliance/iso27001`) with 9 Annex A.8 controls (A.8.4, A.8.7, A.8.8, A.8.19, A.8.25, A.8.26, A.8.28, A.8.29, A.8.30), Statement of Applicability (`GET /compliance/soa`). Point-in-time snapshots via `?date=` parameter. VEX-aware compliance reports (VEXStatus, VEXJustification, VEXSource fields, expiry anchored to asOfDate).
	- **Remaining**: HTML/PDF rendering for auditor-facing export (JSON API complete).
	- Acceptance criteria hint: auditors can consume platform outputs without needing direct DB or admin access. An ISO 27001 auditor can pull evidence for A.8.8 and A.8.28 directly from the platform.

- [x] Add a connected tool catalog
	- Track installed integrations, source health, last successful sync, and credential state.
	- Provide visibility into which tools are feeding data into each tenant.
	- Support operational diagnostics so broken integrations are quickly identifiable.
	- **Done**: `GET /orgs/{p}/{s}/tool-catalog` derives tool health from existing data — advisory providers (from `scan_providers`), SAST tools (from `findings`), VEX sources (from `vex_statements`), SBOM ecosystems (from `components`), coverage formats (from snapshots). Health status: healthy/degraded/unhealthy/inactive based on recency and error state. No new tables — pure aggregation.
	- Acceptance criteria hint: administrators can tell whether the platform is healthy as an integration hub.

## Phase 5 - Ecosystem Expansion

- [x] Add additional git provider support
	- Extend provider abstractions for Forgejo/Gitea and GitLab onboarding, webhook handling, and PR/MR decoration.
	- Reuse the GitHub-first data model without forcing provider-specific leaks through the whole system.
	- GitLab provider fully implemented: all 13 `forge.Provider` methods using raw `net/http` against GitLab REST API v4. Webhook validation via `X-Gitlab-Token` (constant-time compare). Push Hook and Merge Request Hook event parsing. File create vs update detection. Separate webhook project type for namespace string vs object mismatch. Forgejo/Gitea provider was already complete.
	- Acceptance criteria hint: a non-GitHub tenant can onboard repositories with feature parity for core ingestion flows.


- [ ] Deliver secret scanning tracking
	- Integrate with GitHub secret scanning and third-party tools such as truffleHog or gitleaks or betterleaks. (should be tool agnostic thus extensible, we should be able to select one or many providers)
	- WHen new repo detected, a full scan must be done on the repo, then we should have some kind of hook on github api to intercept push and analyse pushed changes.
	- ideally we should stop the push, and if possible get a message to the user that git pushed it. (to avoid exposition) take example on gitgardian and github secrets detection feature. update this current task then with the plan. Maybe create an adr file too.
	- Normalize secret finding metadata and connect it to repository, ref, and remediation workflows.
	- Acceptance criteria hint: leaked secret visibility is available in the same platform workflow as SBOM and SARIF analysis.

- [ ] Add container image scanning flows
	- Support image-origin SBOM ingestion, image metadata tracking, and vulnerability reporting tied to containers.
	- Store **image digest** (`sha256:...`) as an additional identifier on snapshot records alongside commit SHA. This provides immutable, content-addressed artifact identity for compliance audits.
	- Support **multiple SBOMs per release** using the label system (see below) — a source-code SBOM and a container-image SBOM may coexist for the same release, distinguished by labels like `artifact=source` vs `artifact=container`.
	- Connect image analysis to repository and release entities where provenance is known.
	- Acceptance criteria hint: teams can analyze application dependencies whether they originate from source builds or shipped images, with each artifact uniquely identified by its digest.

- [ ] Add generic label system for snapshots, components, and findings
	- Implement key/value labels (`map[string]string`) on snapshots, components, and findings — same pattern as Kubernetes labels or GitHub issue labels but with `key=value` semantics.
	- Built-in label keys with well-known semantics: `scope` (prod/dev/test), `artifact` (source/container/infra), `environment` (staging/prod), `team`. Custom keys are unrestricted.
	- Labels are settable via upload API (`--label scope=prod --label team=platform`), `.hibou.yaml` defaults, and UI/API post-hoc editing.
	- All list/search/filter APIs support label selectors (Kubernetes-style): `?labels=scope=prod,team=platform`. Quality gates can scope by label: "only gate on `scope=prod` components."
	- UI: labels shown as colored badges on snapshots/components, filterable in all table views.
	- Auto-populated labels where possible: parse CycloneDX `scope` field → `scope=prod`/`scope=dev`, SARIF tool name → `tool=semgrep`, upload source → `source=ci`/`source=manual`.
	- Acceptance criteria hint: `hibou upload sbom sbom.json --label scope=prod --label artifact=container --label team=payments` tags the snapshot, and filtering by `scope=prod` in the UI shows only production dependencies.

- [ ] Add license compliance support
	- Extract license data from SBOMs (CycloneDX and SPDX both carry per-component license fields), store normalized SPDX license identifiers per component.
	- Define **license policies** per org: allowed list (e.g., MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC) and denied list (e.g., GPL-3.0, AGPL-3.0, SSPL, EUPL). Policies are RBAC-gated — only admins and auditors can modify them.
	- **PR quality gate integration**: when a PR introduces a new dependency with a denied license, the quality gate fails. Delta computation compares new components' licenses against the org policy. Same pattern as vulnerability gating — license violations appear in the PR summary comment and forge annotations.
	- License overview dashboard: component count by license, license distribution chart, policy violation list, and drill-down to affected repos/components.
	- Support policy exceptions with justification, expiry, and audit trail (same pattern as VEX suppressions).
	- Take inspiration from SonarQube license compliance, FOSSA, and Snyk License for UX patterns.
	- Acceptance criteria hint: a PR that adds a GPL-3.0 dependency to a project with a deny-GPL policy fails the quality gate with a clear explanation.

- [x] Add VEX (Vulnerability Exploitability eXchange) support
	- Replace the boolean suppression model with standards-compliant VEX statements. Store status (not_affected, affected, fixed, under_investigation), justification, impact/action statements, source tracking, supplier attribution, and expiry per advisory+scope.
	- Support three scoping levels for VEX statements: org-wide (applies to all repos), repo-level, and component-level (purl-specific). Most specific scope wins during evaluation.
	- Implement VEX document ingestion via the unified upload endpoint with auto-detection:
	  - **OpenVEX** (OpenSSF standard): parse JSON-LD documents, map statements to internal model. Component-centric, PURL-based.
	  - **CSAF VEX** (OASIS CSAF 2.0 Profile 5, `csaf_vex`): parse full document structure. Product-centric (vendor → product → version tree, not PURL). Mandatory: `product_tree`, `vulnerabilities` with `product_status` buckets. `known_not_affected` MUST have impact via `flags` (machine-readable VEX justification labels) or `threats` (human-readable). `known_affected` MUST have `remediations`. Extract `flags.label` as primary justification source, `remediations` as action statements, `threats` as impact statements, TLP distribution labels as metadata.
	  - **CycloneDX VEX**: extract `vulnerabilities[].analysis` fields during SBOM ingestion. Component-centric, PURL-based.
	- Implement VEX document export/generation in OpenVEX and CSAF 2.0 formats. Export per repo+ref, per org, or per advisory. Generated CSAF documents satisfy Profile 5: `document` metadata (Hibou as publisher, category `tool`, TLP label, revision history), `product_tree` from platform data, `vulnerabilities` with `flags` for `known_not_affected` and `remediations` for `known_affected`.
	- **Done**: VEX core complete — OpenVEX/CSAF/CycloneDX parsers with multi-product fan-out, OpenVEX+CSAF export (Profile 5 compliant), full CRUD API (`/vex` with create/list/get/update/delete + export), VEX upload auto-detection, VEX-aware delta/gate filtering (per advisory+component pair), VEX status in compliance reports, scope precedence (component > repo > org), expired statement detection. CSAF parser uses `product_identification_helper.purl`. Non-CVE IDs handled correctly in export.
	- **CSAF Provider Infrastructure** (future, post-dogfooding): act as a CSAF provider by serving `/.well-known/csaf/provider-metadata.json`, ROLIE feeds (RFC 8322, Atom-based JSON per TLP level for automated discovery), directory-based distribution (year folders, `index.txt`, `changes.csv` for delta sync, SHA-256/SHA-512 hash files), and `/.well-known/security.txt` reference. Same pattern as Red Hat's production infrastructure (`csaf_trusted_provider` role, separate `/advisories/` and `/vex/` directories, PGP signing).
	- **CSAF Consumer / Upstream Sync** (future): configure upstream supplier CSAF provider URLs → poll their ROLIE feed or `changes.csv` → auto-import relevant VEX statements for components present in the org's repos → supplier propagation closes the supply chain loop (Red Hat publishes `known_not_affected` → platform imports → all repos using that component get the statement automatically).
	- **Remaining** (advanced VEX features):
	  - **Auto-fixed**: detect when a component is upgraded past an advisory's fixed version and auto-create `status=fixed` with provenance.
	  - **Auto-not-present**: detect when a component disappears from SBOM between snapshots and auto-create `status=not_affected, justification=component_not_present`.
	  - **Supplier propagation**: when VEX is imported from a supplier, auto-apply to all repos consuming that component. Configurable auto-accept or review-required per org.
	  - **Expiry and re-evaluation**: statements with `expires_at` automatically revert to `under_investigation` and trigger notifications.
	  - **Source code reachability analysis**: prove `vulnerable_code_not_in_execute_path` with machine evidence.
	    - **Go (server-side, fully automated)**: platform clones repo via forge credentials (works on GitHub/GitLab/Forgejo), builds static call graph with `golang.org/x/tools/go/callgraph` (RTA/VTA), matches against OSV affected symbols. Shallow clone, analyze, delete. No new permissions needed. Opt-in per org.
	    - **Java (CI-side, opt-in)**: `hibou analyze reachability --lang java` CLI command runs in CI after compilation. Auto-discovers `target/classes` and `build/classes`; explicit `--bytecode` overrides for complex multi-module builds (hundreds of Maven modules, Ant). Builds call graph from bytecode (ASM-based CHA), uploads reachability report.
	    - **Rust (CI-side, opt-in, best-effort)**: `hibou analyze reachability --lang rust` runs in CI. Uses `cargo metadata` + tree-sitter source parsing to match against RustSec/OSV affected symbols (~13% of advisories have function data). Two-tier confidence: high-confidence results auto-generate VEX, low-confidence results surface as triage hints. Honest about limitations — no false `not_affected`.
	    - **Multi-language**: repos with multiple languages use `--lang java,rust` (comma-separated). Go runs server-side automatically. Each analyzer runs independently per ecosystem.
	    - **Out of scope**: Python/JS/TS (dynamic dispatch too imprecise), C/C++ (function pointers, macros), OS packages (binary, no source).
	    - **Large repo performance** (2M+ LOC): dependency-scoped analysis (only analyze modules transitively importing the vulnerable package), incremental call graph caching per commit, hard timeout with graceful degradation, bounded worker pool for server-side Go analysis (SSA ≈ 2-4GB RAM for large repos).
	    - **Call graph visualization** (low priority, post-dogfooding): render the proof subgraph ("why is this CVE reachable/unreachable") in the UI — filtered to entry points → transitive path → vulnerable symbol. DOT export for CLI. Not the full repo call graph. **Deferred until core VEX + reachability are working and dogfooded on our own GitHub repos.**
	- Integrate VEX status into quality gate evaluation: `not_affected` and `fixed` excluded from counts, `affected` counted, `under_investigation` configurable per gate.
	- Provide full CRUD API for manual VEX statements, bulk org-wide statements, and VEX document import/export endpoints.
	- ADR: `docs/adr/009-vex-integration.md`.
	- Acceptance criteria hint: a supplier-published CSAF VEX document can be imported, auto-propagated to affected repos, and immediately reduce noise in quality gates — without manual per-repo triage.

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
	- Maintain the Astro documentation site (`docs/`) with user guides, admin runbooks, deployment guides, and integration recipes.
	- Publish Swagger/OpenAPI docs via `swaggo/swag`-generated `swagger.json` served at `/api/v1/docs`.
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

- [ ] ISO 27001:2022 Annex A compliance mapping
	- The platform naturally covers a subset of Annex A.8 (Technological Controls) for monitored applications. This workstream tracks explicit coverage and gaps.
	- **Controls the platform fully covers (✅)**:
	  - **A.8.8 Management of technical vulnerabilities**: SBOM ingestion, SCA, advisory matching, severity normalization, VEX exploitability tracking, quality gates, remediation guidance, scan freshness monitoring. Core platform capability.
	  - **A.8.25 Secure development lifecycle**: quality gates per branch, PR analysis, config-as-code (`.hibou.yaml`), onboarding PR, audit trail. SDL is enforced via the gate model.
	  - **A.8.28 Secure Coding**: SARIF ingestion from any SAST tool (Semgrep, CodeQL, ESLint, commercial), findings deduplication, PR annotations on new issues, weakness quality gates.
	  - **A.8.29 Security Testing in Dev & Acceptance**: coverage tracking (upload done, metrics pending), SAST/SCA gates as acceptance criteria, PR-level delta analysis.
	- **Controls the platform partially covers (🔵)**:
	  - **A.8.4 Access to source code**: RBAC (Casbin) for platform access, audit log for all actions, forge credentials management. Does not manage git-level permissions (that's the forge's job).
	  - **A.8.7 Protection against malware**: malware detection in SBOMs (OSV MALWARE advisories), malicious package flagging. Gap: secret scanning not yet implemented.
	  - **A.8.19 Installation of software on operational systems**: SBOM inventory per release, component tracking, container image digest tracking (planned). Gap: no runtime agent — platform tracks what's built, not what's deployed (K8s operator planned).
	  - **A.8.26 Application security requirements**: quality gates enforce security requirements on PRs. Gap: no formal security requirements template or threat modeling integration.
	  - **A.8.30 Outsourced Development**: supply chain visibility via SBOM, supplier VEX import, license compliance (planned). Gap: no contractual requirement tracking.
	- **Controls outside platform scope**: A.8.1-A.8.3 (user devices), A.8.5-A.8.6 (authentication — platform uses forge OAuth), A.8.9-A.8.18 (network, physical, infra), A.8.20-A.8.24 (network security, web filtering), A.8.27 (secure architecture — organizational process), A.8.31-A.8.34 (environment separation, change management, testing environments, audit independence).
	- Acceptance criteria hint: the platform documentation includes an ISO 27001 Annex A.8 mapping table that auditors can reference. Compliance reports generate evidence per control.

- [ ] Operational readiness and observability
	- Add structured logging, tracing, metrics, health probes, background job visibility, and audit logs.
	- Define backup, restore, and incident response expectations. But no migration rollback, user must do backup before any upgrades.
	- Acceptance criteria hint: operators can run the system in production without flying blind.

- [ ] Add coverage tracking
	- Model line and branch coverage as a first-class signal alongside vulnerabilities and findings.
	- Support trend views, PR delta coverage, and simple quality gates.
	- Acceptance criteria hint: teams can correlate security posture with code health signals in one product.
	- **Upload support done**: Unified upload endpoint auto-detects Cobertura, JaCoCo, Clover, LCOV, and Go cover profile formats. ADR-008 accepted.
	- **Remaining**: coverage parsing/metric extraction, snapshot grouping implementation, coverage gate evaluation in delta service, PR coverage comparison, line coverage UI, diff coverage.
	- **Config ready**: `.hibou.yaml` supports coverage thresholds (min_coverage, grace, diff_minimum), exclude patterns, and upload window. `--complete` flag designed for instant gate feedback.

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

## Side quest

- [x] Replace current config by go-viper.

- [ ] Add dev vs prod dependency classification
	- Uses the generic label system: components carry `scope=prod`, `scope=dev`, or `scope=test` labels.
	- Auto-detect from SBOM data when available: CycloneDX `scope` field (`required` → `scope=prod`, `optional` → `scope=dev`), npm devDependencies, Maven `scope:test`, Go build tags.
	- Allow manual override via `.hibou.yaml`: `dev_patterns: ["@types/*", "*-test-*"]` for cases where SBOM tooling doesn't preserve scope.
	- Quality gates can filter by scope label: "only gate on `scope=prod` dependencies" to avoid blocking PRs on dev-only vulnerability churn.
	- UI: dependency table shows scope badge, filterable by scope.
	- Acceptance criteria hint: a critical CVE in a devDependency does not fail the prod quality gate when scope filtering is enabled.

- [ ] Add outdated dependency and EOL tracking
	- **EOL tracking via endoflife.date** (primary): use the free public API (`https://endoflife.date/api/{product}.json`) to detect end-of-life runtimes, frameworks, and major dependencies. Covers 300+ products (Node.js, Python, Java, Go, PostgreSQL, .NET, etc.) with EOL dates, latest versions, LTS status. No auth required.
	- Auto-detect products from SBOM data: map component ecosystem/name to endoflife.date product slugs. Surface EOL warnings prominently — an EOL runtime is a security risk even without specific CVEs.
	- Cache endoflife.date responses with TTL (data changes infrequently). Store EOL status as a component-level signal.
	- **Outdated detection via direct registry queries**: query each ecosystem's public registry API to resolve latest versions. Same pattern as Renovate — go to the source of truth. Supported registries:
	  - npm: `registry.npmjs.org/{pkg}` → `dist-tags.latest`
	  - PyPI: `pypi.org/pypi/{pkg}/json` → `info.version`
	  - Go: `proxy.golang.org/{mod}/@latest`
	  - Maven Central: `search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}&rows=1&wt=json`
	  - crates.io: `crates.io/api/v1/crates/{crate}` → `crate.max_stable_version`
	  - NuGet: `api.nuget.org/v3-flatcontainer/{pkg}/index.json` → last entry
	  - RubyGems: `rubygems.org/api/v1/gems/{gem}.json` → `version`
	- **Deduplication**: extract unique `(ecosystem, name)` tuples across the entire instance — not per-repo or per-snapshot. If 50 repos use `lodash`, query npm once. Same global dedup pattern as the advisory cache.
	- **Caching**: cache latest-version responses with configurable TTL per ecosystem (default: 24h — releases don't happen every hour). Background refresh for popular packages. Cache key: `{ecosystem}:{package_name}`.
	- **Batch where possible**: npm bulk endpoint, Go module proxy list mode. For registries without batch APIs, use bounded concurrency with rate limiting.
	- UI: Dependencies tab shows EOL badge (red for EOL, amber for approaching EOL), outdated version badge (current vs latest), filterable.
	- Quality gate option: fail if PR introduces or retains an EOL runtime/framework.
	- Acceptance criteria hint: the dependency table shows Node.js 18 as "EOL since 2025-04-30" with a red badge, and lodash 4.17.15 as "latest: 4.17.21 (6 versions behind)". Processing 10 repos that share 80% of their deps produces far fewer registry calls than 10× the unique package count.

- [ ] Add EPSS-based quality gate thresholds
	- Allow quality gate rules to include EPSS (Exploit Prediction Scoring System) thresholds: e.g., "block if any new vulnerability has EPSS > 0.7".
	- EPSS scores are already stored on advisories via NVD enrichment. Extend gate evaluation to check EPSS alongside severity.
	- Combine with CISA KEV (Known Exploited Vulnerabilities) catalog: vulns on KEV list are always critical regardless of CVSS.
	- Acceptance criteria hint: a high-EPSS vulnerability blocks a PR even if its CVSS severity is only "medium".

- [x] Add Prometheus metrics endpoint
	- Expose `/metrics` endpoint with key operational metrics: scan counts, scan duration histograms, cache hit rates per provider, advisory counts, component counts, active WebSocket connections, notification delivery success/failure rates.
	- Provide pre-built Grafana dashboard JSON so operators don't need to query the DB directly (addressing the DependencyTrack pattern of wiring Grafana to Postgres).
	- Acceptance criteria hint: operators can monitor platform health via standard Prometheus/Grafana stack without direct DB access.

- [ ] Add suppression-as-code workflow
	- Support a `.hibou-suppressions.yaml` file in repositories for developer-owned weakness/SAST finding suppressions, gated behind PR approval.
	- Security team VEX suppressions remain platform-only (UI/API, RBAC-gated) — never in code.
	- Acceptance criteria hint: developers can suppress false-positive SAST findings via code review workflow, with full audit trail.

# Hibou Threat Model

Last updated: May 2026
Version: 1.0
Scope: This document covers Hibou's production and development attack surface as implemented in the Go API server, embedded SPA, PostgreSQL data store, forge integrations, webhook ingestion, upload pipeline, notification system, MCP endpoint, and supported deployment patterns described in the repository as of May 2026.

## Executive Summary

Hibou is a multi-tenant DevSecOps platform that ingests security artifacts such as SBOMs, SARIF, VEX documents, and generic findings; correlates them with repository and release context; and exposes that state through a web UI, REST API, CLI, and built-in MCP server. The platform's highest-value assets are authentication material, tenant-scoped security findings, integration secrets, audit evidence, and the integrity of repository-to-snapshot lineage. This threat model uses STRIDE to evaluate those assets across Hibou's main trust boundaries: browser to SPA, Internet to ingress, ingress to application, application to PostgreSQL, application to Trivy and forge APIs, and MCP clients to the MCP server.

The strongest built-in controls already present in the codebase are transport-aware session cookie settings derived from `HIBOU_BASE_URL`, HMAC-signed session and OAuth state cookies in `internal/auth/auth.go`, API key hashing in `internal/auth/middleware.go`, a hybrid authorization model that combines handler-level org-role checks with Casbin-backed enforcement in some paths, forge webhook HMAC validation when webhook secrets are configured plus per-provider IP allowlisting and rate limiting in `internal/server/server.go` and `internal/server/ipallowlist.go`, upload size enforcement in `internal/server/uploads.go`, audit logging intended to provide append-only operational history, and SSRF protection for outbound notifications in `internal/notify/dispatcher.go`. The container image also reduces runtime attack surface by using a distroless base image and building static binaries with `CGO_ENABLED=0` in the repository `Dockerfile`.

The key residual risks are concentrated around configuration mistakes and exposure management rather than obviously unsafe default code paths. The most important examples are the shipped default `HIBOU_SESSION_SECRET`, which allows forged session and OAuth state cookies if left unchanged; long-lived bearer API keys; stateless HMAC-signed sessions that cannot be selectively revoked server-side without rotating `HIBOU_SESSION_SECRET`; optional MCP exposure on a separate listener enabled by default; permissive behavior while a dynamic forge IP allowlist has not loaded yet; webhook routes that skip HMAC validation entirely when operators leave webhook secrets unset; `/api/v1/auth/dev-login`, which issues a local admin session when no forge providers are configured; operational risk from running Docker Compose with default development credentials; and the general blast radius of compromised CI runners or compromised forge applications that legitimately possess secrets and upload authority. These risks are tractable, but they require deployment hardening and regular review.

## System Overview

Hibou is implemented as a single Go binary with multiple personalities. In server mode, it serves an embedded SPA, hosts the REST API, processes uploads and webhooks, writes to PostgreSQL, dispatches notifications, and optionally starts a second HTTP listener for the MCP server. The main HTTP server is initialized in `cmd/serve.go` and `internal/server/server.go`. Authentication is handled through OAuth/OIDC providers and bearer API keys. Authorization is hybrid: many handlers perform direct organization membership and role checks, while some paths use Casbin-backed policy enforcement. Production deployment is expected on Kubernetes via the Helm chart, while local development uses Docker Compose with PostgreSQL, Forgejo, and Trivy.

```text
                                Trust Boundary TB-1
                         Internet / CI / MCP clients / browsers
     +-----------+        +-------------+        +-------------------+
     | Browser   |<------>| Ingress/TLS |<------>| CI runners        |
     +-----+-----+        +------+------+        +---------+---------+
           |                       |                         |
           | TB-0                  | TB-2                    |
           v                       v                         v
     +-------------------------------------------------------------+
     | Hibou API + Embedded SPA + Workers                          |
     | - chi router, auth middleware, webhook protection           |
     | - upload parsing and snapshot creation                      |
     | - RBAC checks, audit logging, notification dispatch         |
     +-----------+-------------------+-------------------+---------+
                 |                   |                   |
                 | TB-3              | TB-4              | TB-5
                 v                   v                   v
       +----------------+   +-------------------+   +----------------+
       | PostgreSQL     |   | Trivy / OSV / NVD |   | Forge APIs     |
       | system of      |   | enrichment        |   | OAuth/webhooks |
       | record         |   +-------------------+   +----------------+
       +----------------+
                 |
                 | TB-6
                 v
       +----------------+
       | Artifact store |
       | filesystem     |
       +----------------+

                     Separate listener when enabled (TB-7)
                          +--------------------------+
                          | MCP HTTP server          |
                          | internal/mcp + queries   |
                          +--------------------------+
```

### Security-Relevant Implementation Notes

- Session cookie name: `hibou_session`
- OAuth state cookie name: `hibou_oauth_state`
- Main server listener: `HIBOU_HOST` + `HIBOU_PORT`
- MCP listener: `HIBOU_MCP_ENABLED` + `HIBOU_MCP_PORT`
- Database connection string: `HIBOU_DATABASE_URL`
- Upload ceiling: `HIBOU_MAX_UPLOAD_SIZE`
- Artifact storage path: `HIBOU_ARTIFACT_PATH`
- Forge secrets and policy: `HIBOU_FORGE_N_CLIENT_ID`, `HIBOU_FORGE_N_CLIENT_SECRET`, `HIBOU_FORGE_N_WEBHOOK_SECRET`, `HIBOU_FORGE_N_IP_ALLOWLIST`, `HIBOU_FORGE_N_RATE_LIMIT_RPS`, `HIBOU_FORGE_N_ALLOWED_CIDRS`
- Session signing secret: `HIBOU_SESSION_SECRET`

## Asset Inventory

| Asset | Why it matters | Primary location / path | Main threats |
| --- | --- | --- | --- |
| User credentials and OAuth tokens | Initial identity proof for interactive login | Forge provider flow, `internal/auth/auth.go` | Spoofing, token theft, forge compromise |
| Session tokens | Authenticated browser session for UI and API | `hibou_session` cookie | Spoofing, information disclosure |
| API keys | Non-interactive bearer credentials for CLI and CI | `Authorization: Bearer`, DB hash lookup in `internal/auth/middleware.go` | Brute force, leakage, replay |
| SBOM, SARIF, VEX, findings payloads | Core customer security data and provenance | Upload APIs, snapshots, artifact store | Tampering, exfiltration, DoS |
| Vulnerability and dependency intelligence | Drives prioritization and compliance outputs | PostgreSQL, Trivy, OSV, NVD derived state | Tampering, stale data, disclosure |
| PostgreSQL data | System of record for tenants, policy, findings, audit logs | `HIBOU_DATABASE_URL` target | Tampering, disclosure, DoS |
| Forge secrets | Required for OAuth, GitHub App mode, webhook validation | `HIBOU_FORGE_N_*` env vars / secrets | Disclosure, spoofing, privilege escalation |
| Artifact store contents | Raw upload evidence and derived artifacts | Filesystem under `HIBOU_ARTIFACT_PATH` | Tampering, deletion, disclosure |
| Audit logs | Accountability for admin and system actions | `audit_logs` table, documented as append-only operational history but not DB-enforced immutable storage | Repudiation, tampering |
| MCP tools and responses | AI-accessible security state and actions | `cmd/serve.go`, `internal/mcp` | Data leakage, privilege misuse |
| Notification configurations | Outbound destinations and operational alerts | Integrations table, dispatcher | SSRF, repudiation, disclosure |

## Trust Boundaries

```text
TB-0  Browser <-> SPA assets served by Hibou
TB-1  Internet <-> Ingress / TLS termination
TB-2  Ingress <-> Hibou application server
TB-3  Hibou application <-> PostgreSQL
TB-4  Hibou application <-> Trivy / OSV / NVD services
TB-5  Hibou application <-> Forge APIs and webhook senders
TB-6  Hibou application <-> Local artifact filesystem
TB-7  MCP clients <-> Dedicated MCP listener
```

1. Internet to ingress: public network entry for browsers, CI runners, and webhook senders. Main risks are spoofing, flood traffic, and TLS or routing mistakes.
2. Ingress to application: reverse proxy headers influence request handling. `internal/server/server.go` uses `middleware.RealIP`, so proxy trust configuration matters.
3. Application to database: all tenant data, API keys, RBAC policies, and audit logs cross this boundary.
4. Application to Trivy: scanner and enrichment results influence downstream findings. Availability and trust in returned data matter.
5. Application to forge APIs: OAuth exchanges, repository discovery, webhook validation, and commit status updates cross this boundary.
6. Application to MCP clients: a separate listener can expose privileged read or action capabilities to AI tooling.
7. Browser to SPA: user-controlled browsers receive static assets and cookies; XSS and token exposure risks concentrate here.

## Threat Actors

| Actor | Capability | Likely goals | Relevant surfaces |
| --- | --- | --- | --- |
| External attacker | Unauthenticated Internet access, commodity tooling | Account compromise, data exfiltration, service disruption | Public ingress, OAuth endpoints, webhook routes, upload endpoints |
| Malicious insider | Legitimate Hibou user or cluster operator | Tenant data theft, role escalation, evidence tampering | API, RBAC administration, database access, Kubernetes secrets |
| Compromised CI runner | Valid API key and repository context | Poison uploads, flood service, exfiltrate data reachable with token | Upload APIs, CLI token workflows, public endpoint |
| Compromised forge | Control of OAuth or webhook sender identity | Fake events, token abuse, repository state manipulation | OAuth callbacks, webhook routes, GitHub App flows |
| Supply chain attacker | Control over dependency, container, or external scanner update path | Execute code, poison results, persist in build or runtime | Go modules, npm packages, Trivy image, base images |

## STRIDE Analysis

### Spoofing

| ID | Threat | Affected components | Severity | Likelihood | Existing mitigations | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| S-1 | OAuth state forgery against `/api/v1/auth/callback` to bind an attacker-controlled authorization code to a victim browser session. Relevant to OWASP A07:2021 Identification and Authentication Failures. | Browser, auth handlers, forge provider callbacks | High | Medium | `internal/auth/auth.go` generates 32-byte random state, stores it in an HMAC-signed `hibou_oauth_state` cookie with 10-minute lifetime, validates provider ID and timestamp, then clears the cookie on success. Cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` when `HIBOU_BASE_URL` is HTTPS. | If `HIBOU_BASE_URL` is left blank or HTTP in front of a misconfigured proxy, cookies may be less protected. Stateless state handling still depends entirely on `HIBOU_SESSION_SECRET` secrecy. |
| S-2 | Session cookie theft or replay via browser compromise, proxy logging, or XSS elsewhere in the deployment. | Browser, session middleware, reverse proxies | High | Medium | Session cookie is HMAC-signed in `internal/auth/auth.go`, `HttpOnly`, `SameSite=Lax`, and optionally `Secure`. Expiry is 7 days. User record is reloaded from DB each request. | Cookie contents are not encrypted, only integrity-protected. There is no per-session server-side revocation list; selective revocation requires rotating `HIBOU_SESSION_SECRET` or removing the underlying user. |
| S-3 | API key brute force or credential stuffing against bearer-token protected upload and API routes. | API, `authenticateBearerToken`, DB | High | Low | API keys are hashed before lookup with `store.HashAPIKey`, so plaintext secrets are not stored. Expiry is enforced when set, and last-used timestamps are recorded. | No explicit global auth rate limit is visible in the reviewed paths. Long-lived CI tokens remain high-value bearer secrets if leaked. |
| S-4 | Webhook sender spoofing to fake push or PR events. | `/api/v1/webhooks/{provider}`, forge integrations | High | Medium | Provider-specific `ValidateWebhookPayload` enforces HMAC validation when `HIBOU_FORGE_N_WEBHOOK_SECRET` is configured. `webhookProtection` adds optional per-provider IP allowlisting and rate limiting. GitHub IPs auto-refresh every 6 hours from `/meta`. | `internal/server/ipallowlist.go` allows requests until the dynamic allowlist loads successfully, so first-start posture depends on webhook secret validation alone. GitHub, Forgejo, and GitLab all skip signature verification entirely if operators leave webhook secrets unset. |
| S-5 | Forged upload identity by reusing a stolen CLI or CI API key to submit malicious findings under a legitimate repository. | Upload API, snapshots, audit trail | High | Medium | Uploads require bearer authentication and validate repository/ref payload structure before snapshot creation. Audit and snapshot lineage preserve actor association. | API keys are bearer-only; there is no request signing or workload identity binding. A compromised runner can impersonate the pipeline until key rotation. |
| S-6 | Forged `hibou_session` and `hibou_oauth_state` cookies when `HIBOU_SESSION_SECRET` is left at the shipped default value `change-me-in-production`. Anyone who knows the default can mint valid cookies and bypass normal login. | Browser sessions, OAuth callback flow, auth middleware | Critical | Medium | Cookies are HMAC-signed and time-bounded, and deployments can override `HIBOU_SESSION_SECRET`. | `internal/config/config.go` ships a known static default. If operators do not replace it before exposure, both interactive sessions and OAuth state validation can be forged remotely. |

### Tampering

| ID | Threat | Affected components | Severity | Likelihood | Existing mitigations | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| T-1 | SBOM or SARIF payload tampering in transit or at source to hide vulnerable components or inject false findings. Relevant to OWASP A08:2021 Software and Data Integrity Failures. | Upload pipeline, snapshot creation, downstream analysis | High | Medium | TLS is expected at ingress. Upload handlers enforce auth, normalize request context, and preserve raw artifact lineage. Deduplication and snapshot immutability reduce accidental overwrite risk. | Hibou trusts authenticated uploaders for content truthfulness. It does not cryptographically attest uploaded artifacts or verify provenance by default. |
| T-2 | Database record manipulation to alter severity, role assignments, audit evidence, or tenant ownership. | PostgreSQL, RBAC adapter, findings state | Critical | Low | SQL access is mediated through store queries and Casbin adapter paths. Schema comments position audit logs as append-only operational history. | A DB administrator or compromised application pod with DB credentials can still tamper directly unless DB-level least privilege, append-only controls, backups, and monitoring are in place. |
| T-3 | Artifact storage tampering or deletion on the local filesystem under `HIBOU_ARTIFACT_PATH`. | Filesystem object store, retention worker | High | Medium | Artifact storage is at least isolated behind application code, and retention runs through a controlled worker. | Filesystem storage lacks intrinsic object immutability or integrity verification. Host or pod compromise can alter or remove evidence without cryptographic detection. |
| T-4 | Webhook payload modification between sender and Hibou. | Forge webhooks, repo/ref state updates | High | Low | Forge HMAC validation in provider implementations rejects modified payloads when webhook secrets are configured. Optional IP allowlists reduce attack surface. | If secrets are weak, reused, or unset, tampering resistance drops to network-level protections only. |

### Repudiation

| ID | Threat | Affected components | Severity | Likelihood | Existing mitigations | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| R-1 | Unlogged administrative actions such as org setting changes, repo enrollment changes, or integration edits. | Org settings, repo admin, integrations | High | Medium | Reviewed server handlers call `CreateAuditLog` with actor, IP, and user-agent context. `internal/server/settings.go` records old and new settings. Schema comments describe `audit_logs` as append-only operational history. | Coverage is strong but not obviously universal across every handler in the codebase. New routes can be added without audit logging unless review discipline enforces it, and the database does not enforce immutable audit storage on its own. |
| R-2 | Upload origin disputes where a pipeline denies sending a malicious or malformed artifact. | Upload APIs, snapshot lineage | Medium | Medium | Uploads are tied to authenticated users/API keys; API key last-used timestamps are updated; snapshots preserve repository/ref/commit metadata. | Without workload identity, signed provenance, or per-request signatures, Hibou can prove which key was used, not which exact runner or job possessed it. |
| R-3 | Notification delivery disputes about whether an alert was sent or failed. | Notification dispatcher, integrations | Medium | Medium | `internal/notify/dispatcher.go` writes audit logs containing event type, body, destination status, and error context for both success and failure. Integration health is updated with failure counts and timestamps. | The audit trail reflects Hibou's send attempt, not independent proof of downstream system receipt or human acknowledgement. |

### Information Disclosure

| ID | Threat | Affected components | Severity | Likelihood | Existing mitigations | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| I-1 | Database credential exposure through environment leaks, Helm misconfiguration, or debug output. | Application config, Kubernetes secrets, Docker Compose | Critical | Medium | Secrets are expected to be injected via Kubernetes secrets or environment variables. Distroless runtime reduces interactive shell exposure. | `internal/config/config.go` has permissive development defaults, and `docker-compose.yml` uses `hibou:hibou` credentials. Production hardening is an operator responsibility. |
| I-2 | API key leakage in logs, CI output, or browser storage. | CLI, CI workflows, HTTP headers | High | Medium | API keys are hashed at rest and never need to be stored in browser cookies. | Bearer tokens still appear in process environments, CI secret stores, or reverse proxy logs if mishandled. No proof-of-possession control exists. |
| I-3 | Exfiltration of SBOM, findings, or vulnerability data across tenant boundaries. Relevant to OWASP A01:2021 Broken Access Control. | REST API, SPA, RBAC, database queries | Critical | Medium | Multi-tenancy is a first-class design goal in `SPEC.md`. Reviewed handlers commonly gate access with direct org membership and role lookups, and some paths use Casbin-backed policy checks. Most API routes are nested under org/repo scoping. | This remains a high-impact class because the authorization model is split across handler logic and policy enforcement. Any IDOR, missing role check, or drift between those mechanisms would directly expose customer security posture. Broad regression testing is required. |
| I-4 | Session token exposure through insecure transport or misconfigured cookie policy. | Browser, ingress, auth config | High | Low | `CookieSecure()` derives secure-cookie behavior from `HIBOU_BASE_URL`; cookies are `HttpOnly` and `SameSite=Lax`. | Leaving `HIBOU_BASE_URL` empty in production or terminating TLS incorrectly can silently weaken cookie protection. |
| I-5 | Forge secret leakage, including webhook secret, client secret, GitHub App private key, or app ID metadata. | Environment secrets, Kubernetes, CI | Critical | Medium | Secrets are logically separated by forge index and expected to reside in secret stores. | Hibou does not provide an in-process secret manager. Any pod exec, env dump, or misconfigured secret projection can expose forge credentials. |
| I-6 | MCP data leakage if the dedicated MCP listener is exposed beyond intended clients or mapped to overly broad tool permissions. | MCP server, AI clients | High | Medium | MCP runs on a separate listener from the main API and routes through service-layer abstractions rather than direct DB access. | `HIBOU_MCP_ENABLED` defaults to true. Exposure depends on network policy and whatever auth the MCP HTTP wrapper enforces. Operators must treat this as a sensitive admin interface. |

### Denial of Service

| ID | Threat | Affected components | Severity | Likelihood | Existing mitigations | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| D-1 | Upload flood using valid or invalid credentials to create excessive parse and persistence work. | Upload APIs, DB, artifact store, workers | High | Medium | Upload body size is capped with `http.MaxBytesReader` using `HIBOU_MAX_UPLOAD_SIZE`. Auth is required for uploads. | No reviewed global per-user upload rate limit exists. A valid API key can still generate costly workload within the allowed size limit. |
| D-2 | Webhook flood from Internet sources or botnets. | Webhook routes, logs, DB | High | Medium | Optional per-provider per-IP rate limiting via `HIBOU_FORGE_N_RATE_LIMIT_RPS`, plus IP allowlists and HMAC validation. `ReadHeaderTimeout` is set to 10 seconds. | If rate limiting is not configured, a public webhook route still absorbs request parsing and signature validation work. Distributed traffic can bypass per-IP controls. |
| D-3 | Large payload parsing or decompression pressure from oversized SBOM/SARIF documents. | Upload handlers, parsers, memory | High | Medium | Max request size is enforced before JSON decode. | Valid but complex payloads under the size limit can still consume CPU and memory during parsing and normalization. |
| D-4 | Database connection exhaustion or slow-query amplification. | PostgreSQL, API server | High | Medium | Readiness checks and graceful shutdown exist; application paths reuse a single DB handle. | No reviewed query budget, per-tenant quota, or circuit breaker protects against pathological heavy query patterns. |
| D-5 | Trivy scanner overload or external dependency slowdown leading to stale analysis. | Trivy, scan workers, notifications | Medium | Medium | Trivy is optional but expected; stale scan checker and notifications provide visibility. | Hibou depends on external availability for enrichment quality. A degraded Trivy service can back up analysis pipelines. |

### Elevation of Privilege

| ID | Threat | Affected components | Severity | Likelihood | Existing mitigations | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| E-1 | Authorization bypass through missing handler checks, direct-role logic mistakes, or inconsistent object scoping across the mixed authorization model. | REST API, org/repo handlers, Casbin-backed paths | Critical | Medium | Reviewed handlers often use `GetOrgMemberRole` and explicit role checks, while some paths rely on Casbin-backed enforcement. Org-scoped roles include `admin`, `developer`, `release_manager`, `auditor`, `viewer`. | Authorization is only as strong as route-by-route coverage and consistency between hand-written checks and policy-backed paths. A single missed or divergent handler becomes a direct privilege boundary failure. |
| E-2 | Tenant isolation breach through IDOR on organization, repository, client, or snapshot identifiers. | API routes, DB lookups, UI | Critical | Medium | Route structure is largely tenant-aware, and the data model is designed around org-rooted hierarchy. | This remains a primary residual risk because UUIDs and slugs alone do not enforce authorization. Thorough negative tests are required. |
| E-3 | Admin role escalation by a malicious insider editing role bindings or policy storage. | Org member management, Casbin grouping policies, DB | High | Low | Role assignments are mediated through server handlers and stored centrally; admin changes can be audited. | Operators with direct DB access or compromised app credentials could still elevate privileges out of band. |
| E-4 | MCP tool abuse to access or mutate more data than an API user should reach. | MCP server, AI agent integrations | High | Medium | The design intent in `SPEC.md` is for MCP tools to reuse the same API/service-layer rules rather than bypass them. | MCP introduces a second control plane. Its exposure, auth model, and tool granularity require explicit review whenever new MCP tools are added. |
| E-5 | Insecure direct object reference on org/repo resources that allows cross-tenant reads or writes with otherwise valid auth. Mapped to OWASP A01:2021 Broken Access Control. | Org, repo, client, release, snapshot endpoints | Critical | Medium | Nested resource routing, RBAC, and auditability reduce accidental misuse. | This class is too important to mark closed without dedicated authorization tests for every major route family. |
| E-6 | Exposure of `/api/v1/auth/dev-login` in a deployment that has no forge providers configured. The route creates or reuses a local `dev-admin` user and issues an authenticated admin session cookie. | Auth routes, zero-provider deployments, Docker Compose-style environments | High | Medium | `DevLoginHandler` refuses requests when any forge provider is configured, and the route is documented as development-only. | A zero-provider deployment exposed beyond localhost or a trusted private network effectively exposes one-step admin login. This is a configuration threat, not a theoretical edge case. |

## Data Flow Analysis

### 1. OAuth Login Flow

```text
Browser -> GET /api/v1/auth/login?provider=X
        -> Hibou generates random state and HMAC-signed oauth cookie
        -> Browser redirected to forge OAuth authorization endpoint
Forge   -> callback with code + state
Browser -> GET /api/v1/auth/callback?provider=X&code=...&state=...
Hibou   -> validates cookie signature + timestamp + provider
        -> exchanges code for provider token
        -> reads user identity from forge
        -> upserts user in PostgreSQL
        -> sets signed hibou_session cookie
```

Controls applied:

- OAuth state randomness and HMAC validation in `internal/auth/auth.go`
- `HttpOnly`, `SameSite=Lax`, and conditional `Secure` cookie flags
- Session lifetime limit of 7 days
- Provider-specific callback URL generation from `HIBOU_BASE_URL` or forwarded headers

### 2. SBOM / SARIF Upload Flow

```text
CI runner or CLI -> POST /api/v1/upload with Bearer API key
                 -> SessionAuth loads API key user from hashed lookup
                 -> Hibou enforces MaxBytesReader using HIBOU_MAX_UPLOAD_SIZE
                 -> JSON decoded and request normalized
                 -> artifact content base64-decoded and type auto-detected
                 -> snapshot created and processing pipeline continues
                 -> raw lineage and status stored in PostgreSQL / artifact store
```

Controls applied:

- Bearer auth in `internal/auth/middleware.go`
- Request size cap in `internal/server/uploads.go`
- Input validation and format detection before processing
- Snapshot lineage for traceability and post-incident review

### 3. Webhook Processing Flow

```text
Forge -> POST /api/v1/webhooks/{provider}
      -> optional IP allowlist middleware
      -> optional per-IP rate limiter
      -> provider HMAC verification when webhook secret is configured
      -> event type header extraction
      -> payload parsed into push / PR event
      -> repository lookup and ref state update in PostgreSQL
```

Controls applied:

- `webhookProtection` middleware in `internal/server/server.go`
- GitHub dynamic `/meta` CIDR refresh and optional static CIDRs in `internal/server/ipallowlist.go`
- Provider `ValidateWebhookPayload()` before any state mutation in `internal/server/webhooks.go` when a webhook secret is configured

### 4. MCP Tool Call Flow

```text
MCP client -> dedicated MCP HTTP listener (default enabled on separate port)
           -> internal/mcp server instance
           -> service/store queries for tenant data and analysis
           -> structured tool response back to client
```

Controls applied:

- Separate listener and startup path in `cmd/serve.go`
- Architectural intent to call service-layer abstractions instead of direct DB access from AI clients

Residual concern:

- MCP is effectively a second admin-facing API surface and should be network-restricted even if functionally correct.

### 5. Notification Dispatch Flow

```text
Internal event bus -> notification dispatcher
                   -> integration config selected
                   -> destination address validated against private IP / metadata IP deny rules
                   -> sender posts webhook / Slack / Teams / email
                   -> delivery outcome written to audit log and integration health state
```

Controls applied:

- SSRF guard in `validateNotificationAddress()` blocking loopback, RFC1918, link-local, and `169.254.169.254`
- Audit logs for delivered and failed attempts
- Circuit-breaker and failure counters in dispatcher health logic

## Deployment-Specific Threats

### Kubernetes via Helm

Primary threats:

- Secret exposure through environment variables, mis-scoped secrets, or overly broad RBAC.
- MCP listener or API service exposed by ingress or service definitions beyond intended audience.
- Pod-to-pod lateral movement if network policies are absent.
- Persistent volume tampering affecting PostgreSQL or artifact storage.

Deployment guidance:

- Keep `HIBOU_BASE_URL` aligned with the actual HTTPS endpoint so cookie security flags stay correct.
- Store `HIBOU_SESSION_SECRET`, `HIBOU_DATABASE_URL`, and all `HIBOU_FORGE_N_*` values in Kubernetes secrets, not ConfigMaps.
- Expose only the main HTTP service publicly; restrict the MCP listener with NetworkPolicy or a private Service.
- Use separate service accounts, read-only root filesystems where feasible, and backup/restore testing for PostgreSQL and artifact volumes.

### Hetzner Single-Node Deployment

Primary threats:

- Larger blast radius because application, database, artifacts, and ingress may share one host.
- Host compromise directly exposes filesystem artifact data and local secrets.
- Limited redundancy raises DoS and ransomware impact.

Deployment guidance:

- Treat the host as a high-value system: SSH key-only access, firewalling, patch management, disk encryption, and monitored backups.
- Avoid colocating unrelated services on the same node.
- Use external managed backups or off-node snapshot export for PostgreSQL and artifact data.

### Docker Compose Development Environment

Primary threats:

- `docker-compose.yml` intentionally uses default credentials and exposes PostgreSQL, Forgejo, and Trivy on localhost ports.
- Development OAuth and webhook flows may use HTTP, not HTTPS.
- `/api/v1/auth/dev-login` remains available whenever no forge providers are configured, so exposing a Compose-style deployment beyond localhost creates an admin-session issuance path.
- Developers may accidentally reuse dev settings in production.

Deployment guidance:

- Treat Compose as non-production only.
- Never expose the Compose stack directly to the Internet.
- Override `HIBOU_SESSION_SECRET` even in shared test environments, and disable or firewall zero-provider deployments that would expose `/api/v1/auth/dev-login`.
- Use separate secrets and separate forge applications for development.

## Supply Chain Considerations

Hibou's supply chain risk includes Go modules, npm packages for the site build, the `aquasec/trivy:latest` image used in Compose, PostgreSQL images, forge container images for development, and the distroless runtime base image in the `Dockerfile`. These map most directly to OWASP A06:2021 Vulnerable and Outdated Components and OWASP A08:2021 Software and Data Integrity Failures.

Key observations:

- The runtime image is minimized by using `gcr.io/distroless/base-debian12`, which reduces shell-based post-exploitation options.
- Build stages rely on external registries for Node.js, Go, npm dependencies, and Go modules. Lockfiles and module sums help, but they do not eliminate malicious upstream release risk.
- `docker-compose.yml` tracks `aquasec/trivy:latest`, which increases update velocity but also nondeterminism. Pinning by digest is preferable for controlled environments.
- Hibou's own product mission suggests it should generate and publish its own SBOM for the shipped binary and container image, then continuously scan that SBOM.

Recommended supply-chain controls:

- Pin container images by digest in deployment manifests.
- Continuously scan Go and npm dependency trees and alert on exploitable issues.
- Produce a release SBOM for Hibou itself and sign release artifacts.
- Review transitive dependency changes in both Go and npm lockfiles during release approval.

## Residual Risks & Recommendations

| Priority | Residual risk | Why it remains | Recommended mitigation |
| --- | --- | --- | --- |
| P1 | Default `HIBOU_SESSION_SECRET` left unchanged | `internal/config/config.go` ships a known static default, so sessions and OAuth state are forgeable if operators do not override it | Fail startup when `HIBOU_SESSION_SECRET` is unset or equal to the default, rotate any environment that ever exposed the default, and add deployment checks for secret uniqueness. |
| P1 | Stateless session revocation gap | Signed cookies can be validated without server-side session storage | Add server-side session records or token versioning so single-user session revocation does not require global secret rotation. |
| P1 | MCP listener exposure | Separate control plane may be reachable if operators expose default port or omit auth review | Disable MCP by default in exposed environments, or require explicit enablement plus network policy and authentication review. |
| P1 | Cross-tenant authorization regressions | Multi-tenant security depends on consistent authorization across hand-written org-role checks and Casbin-backed paths on every route | Add route-level authorization tests for every org/repo/client/release endpoint family, including negative IDOR cases and mixed-model policy drift checks. |
| P1 | Bearer API key replay from compromised CI | Keys are transferable secrets with no workload binding | Add short-lived scoped upload tokens, OIDC workload identity, or signed request support for CI uploads. |
| P1 | Zero-provider `dev-login` exposure | `POST /api/v1/auth/dev-login` issues a local admin session whenever no forge providers are configured | Disable the route outside explicit development mode, or fail startup when no providers are configured on a non-local deployment. |
| P2 | Dynamic forge allowlist warm-up window | Requests are allowed until the dynamic IP list loads | Persist last-known-good IP ranges, fail closed when webhook secrets are absent, and alert on allowlist refresh failure. |
| P2 | Webhook authenticity depends on operator configuration | GitHub, Forgejo, and GitLab skip HMAC verification if their webhook secret is unset | Require non-empty webhook secrets for enabled webhook providers and surface health warnings when validation is effectively disabled. |
| P2 | Artifact store integrity | Filesystem storage can be altered by host or pod compromise | Add checksums, append-only evidence records, and optional object storage with versioning/immutability. |
| P2 | Upload resource exhaustion below max size | Valid but expensive payloads can still consume CPU and memory | Add per-user and per-org upload rate limits, parser timeouts, and worker queue quotas. |
| P2 | Production secret management drift | Environment-based secret injection is easy to misconfigure | Publish a hardened deployment baseline covering secret stores, rotation cadence, audit requirements, and Kubernetes RBAC minimums. |
| P3 | Notification delivery non-repudiation limits | Audit shows send attempt, not recipient receipt | Add optional signed delivery receipts or webhook retry response capture for high-assurance integrations. |
| P3 | Supply chain nondeterminism in dev images | `latest` tags and unpinned upstreams increase uncertainty | Pin Compose images by digest for reproducible security testing and document update cadence. |

## Review Schedule

This threat model should be reviewed:

- At least every 6 months
- Before any major authentication or authorization redesign
- Before exposing new public endpoints, especially new webhook or MCP tools
- Before changing deployment topology, such as adding multi-node workers or external object storage
- After any material security incident, credential leak, or cross-tenant defect

Recommended review process:

1. Re-read `SPEC.md`, deployment docs, and all auth, RBAC, server, notification, and MCP entry points.
2. Diff new routes, background workers, and integrations added since the previous version.
3. Re-score STRIDE entries whose likelihood changed because of deployment posture, new controls, or incidents.
4. Verify mitigation claims against code and configuration, not design intent alone.
5. Publish a new dated version and link it from security or operations documentation.

# ADR-007: Canonical advisory model with provider-agnostic architecture

## Status
Accepted

## Context
Vulnerability databases (NVD, OSV, GHSA, Trivy DB, Sonatype) report the same real-world vulnerability under different identifiers. DependencyTrack suffered from storing each provider's output as a separate record, inflating vulnerability counts and confusing users (DT#4122, DT#4528).

Additionally, naive version comparison produces false positives. Each package ecosystem (npm, Maven, PyPI, Go, Cargo, NuGet) and OS package manager (RPM, dpkg, APK) has different versioning rules that must be respected. RPM epoch:version-release parsing and architecture suffix stripping are particularly common sources of false positives.

The platform must also support compliance regimes (SOC 2, ISO 27001, PCI DSS) that require long-term data retention — years, not days.

## Decision

### Canonical Advisory Model
Store one advisory record per real vulnerability. Multiple identifiers (CVE-2024-1234, GHSA-abcd, PYSEC-2024-567) are stored as aliases on the same record. Alias resolution is transitive: if A=B and B=C, then A=B=C.

### Provider Equality
All vulnerability data sources implement a single `AdvisoryProvider` interface. No provider is privileged. Providers are queried in priority order based on coverage efficiency:

1. **OSV.dev** first — already aggregates GHSA, PYSEC, RUSTSEC, GO-, and others. Batch API (1000/req). Avoids redundant queries to sources OSV already covers.
2. **NVD** second — enriches CVEs not in OSV with CVSS scores and CWE data. Supports bulk download for mirror mode.
3. **GitHub Advisory Database** — GraphQL batch queries for GitHub-native advisories.
4. **Trivy** — queried via its Twirp RPC API as a client, and as an advisory source via its vulnerability DB.
5. **Sonatype OSS Index** — batch API (128/req), strong Maven/Java coverage.

### Global Package-Level Cache
Advisory queries are cached globally by `{ecosystem}:{package_name}:{provider}`. If 50 repos depend on `lodash`, we query each provider once. Cache TTLs are configurable per provider (default: 6h for OSV, 24h for NVD).

### Ecosystem-Aware Version Comparison
A standalone `internal/versioncmp/` package implements per-ecosystem version parsers and range matchers covering both language ecosystems (Go, npm, Maven, PyPI, Cargo, NuGet, RubyGems) and OS package managers (RPM/RHEL/Fedora/SUSE with `epoch:version-release` and `rpmvercmp`, Debian/Ubuntu with `dpkg --compare-versions`, Alpine APK). OS package versioning is the primary source of false positives in other tools — version strings must be split from arch suffixes and epochs must be parsed correctly. Each ecosystem's comparator has hundreds of test cases, including edge cases from the ecosystem's specification and known false-positive scenarios.

### Data Retention
- Hot storage: all snapshots from the last 90 days (configurable), fully queryable.
- Archive: older snapshots compressed and retained for up to 7 years (configurable) for compliance.
- Raw SBOMs and SARIF files stored in object storage (S3/MinIO/filesystem), referenced from PostgreSQL.
- Advisory modification history is retained indefinitely for point-in-time compliance queries.
- Never auto-purge unless an operator explicitly requests it.

### Real-Time via WebSocket
WebSocket (`github.com/coder/websocket`) for push notifications. REST remains the primary data API — WebSocket is additive and carries small payloads (status changes, notification counts). All business logic lives in service packages; both REST handlers and WS hub are thin consumers.

## Consequences
- Adding a new vulnerability provider requires only implementing the `AdvisoryProvider` interface.
- The alias resolution layer must handle conflicting data from multiple providers (severity disagreements, different affected ranges) with a deterministic merge strategy.
- The version comparison library is a critical correctness component and requires investment in test coverage.
- Storage grows primarily with advisory database size (~1 GB baseline) plus per-snapshot component data. Advisory data is shared globally across all tenants.
- Compliance retention increases storage linearly with time but can use compressed archive tiers.
- The cache layer introduces eventual consistency: a newly published CVE may not appear until the cache TTL expires or a manual refresh is triggered.

const API_BASE = '/api/v1'

export interface User {
  id: string
  email: string
  display_name: string
  avatar_url?: string
  provider: string
  is_instance_admin?: boolean
  can_triage_cves?: boolean
}

// Instance-wide announcement banner, managed by instance admins in
// /settings/banners and rendered at the top of every page.
export interface AnnouncementBanner {
  id: string
  message: string
  background_color: string
  enabled: boolean
}

// Postgres nullable columns serialize as {…, Valid} wrappers on some legacy
// endpoints; helpers below unwrap them.
export interface SqlNullTime {
  Time: string
  Valid: boolean
}

export interface SqlNullInt32 {
  Int32: number
  Valid: boolean
}

export interface SqlNullUUID {
  UUID: string
  Valid: boolean
}

export interface OrgMember {
  org_id: string
  user_id: string
  role: string
  /**
   * 'forge' roles are owned by the permission sync and replaced on its next
   * run, so they are shown read-only: offering to edit one offers a change
   * that silently reverts.
   */
  source: 'forge' | 'invite'
  created_at: string
  user?: User
}

export const ORG_MEMBER_ROLES = ['admin', 'developer', 'release_manager', 'auditor', 'viewer'] as const

export interface OrgIntegration {
  id: string
  org_id: string
  name: string
  integration_type: string
  config: Record<string, unknown>
  enabled: boolean
  last_success_at: SqlNullTime
  last_failure_at: SqlNullTime
  failure_count: number
  created_at: string
  updated_at: string
}

export const INTEGRATION_TYPES = ['webhook', 'slack', 'teams', 'discord', 'email'] as const

export interface IntegrationReplayResult {
  integration_id: string
  requested: number
  replayed: number
  skipped: number
}

export interface NotificationRule {
  id: string
  org_id: string
  name: string
  event_type: string
  conditions: Record<string, unknown>
  destination_type: string
  destination_config: Record<string, unknown>
  enabled: boolean
  created_at: string
  updated_at: string
}

// Event types emitted on the internal bus that notification rules can match.
// Must stay in sync with isValidNotificationEventType (Go) — listing an event
// the API rejects makes the rule form fail on save.
export const NOTIFICATION_EVENT_TYPES = [
  'vulnerabilities.found',
  'malware.detected',
  'gate.failed',
  'gate.passed',
  'scan.completed',
  'scan.failed',
  'scan.stale',
] as const

export interface QualityGate {
  id: string
  org_id: string
  repo_id: SqlNullUUID
  name: string
  description: string
  max_critical: number
  max_high: number
  max_medium: SqlNullInt32
  max_new_findings: SqlNullInt32
  finding_severities: string[]
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface QualityGateInput {
  repo_id?: string
  name: string
  description: string
  max_critical: number
  max_high: number
  max_medium?: number
  max_new_findings?: number
  enabled: boolean
}

export interface Organization {
  id: string
  name: string
  slug: string
  display_name: string
  provider: string
  forge_url?: string
  role?: string
}

export interface OnboardableAccount {
  provider: string
  account: string
  slug: string
  status: 'imported' | 'importable' | 'pending'
}

export type RepoLifecycleStatus = 'discovered' | 'active' | 'archived' | 'deleted'

export interface Team {
  id: string
  name: string
  slug: string
  org_id: string
}

export interface Repository {
  id?: string
  name: string
  slug: string
  org_id?: string
  provider: string
  provider_id: string
  default_branch: string
  sync_state?: string
  full_name?: string
  html_url?: string
  description?: string
  private?: boolean
  visibility?: 'public' | 'private' | 'internal'
  enrolled?: boolean
  status?: RepoLifecycleStatus
  last_scanned?: string | null
  outdated?: boolean
  // Viewer may open the repo-scoped audit log (org admin or owning-team admin).
  viewer_can_audit?: boolean
}

export interface Client {
  id: string
  org_id: string
  name: string
  slug: string
  labels?: Record<string, string>
  client_type: string
  contact_email?: string
  contact_name?: string
  metadata?: Record<string, unknown>
  notification_prefs?: Record<string, unknown>
  deployments_count?: number
  last_deployment_at?: string
  active_version?: string
  created_at: string
  updated_at: string
}

export interface Release {
  id: string
  repo_id: string
  ref_id: string
  snapshot_id?: string
  version: string
  build_metadata?: Record<string, unknown>
  artifact_ids?: unknown[]
  provenance?: Record<string, unknown>
  html_url?: string
  // Releases are derived (ADR-024): from a version tag's analysis or a forge release event.
  source: 'tag' | 'forge'
  published_at?: string
  created_at: string
  // Re-tag divergence: the tag moved to another commit while clients run this build.
  pending_snapshot_id?: string
  diverged_at?: string
}

// One client currently on a release, via an active deployment (ADR-024).
export interface ReleaseClient {
  deployment_id: string
  client_id: string
  slug: string
  name: string
  environment: string
  deployed_at: string
}

// Release enriched with its pinned snapshot's open-risk posture (ADR-024).
export interface ReleaseWithRisk extends Release {
  ref_name: string
  commit_sha?: string
  pending_commit_sha?: string
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  kev_open: number | null
  malware_open: number
  open_finding_count: number
  last_scanned_at?: string
  clients: ReleaseClient[]
}

export interface Deployment {
  id: string
  client_id: string
  release_id: string
  environment: string
  status: string
  deployed_at: string
  deployed_by?: string
  notes?: string
  release_version?: string
  created_at: string
}

export interface ClientImpact {
  vulnerabilities: Array<{
    canonical_id: string
    severity: string
    component_name: string
    release_version: string
  }>
}

export interface SearchResult {
  type: 'vulnerability' | 'component' | 'client'
  id: string
  title: string
  subtitle: string
  severity?: string
  metadata?: Record<string, unknown>
}

export interface SearchResponse {
  results: SearchResult[]
  pagination: { page: number; per_page: number; total: number }
}

export interface EnhancedRef {
  id: string
  repo_id: string
  name: string
  ref_type: string
  provider_id?: string
  merge_target_ref_id?: string
  merge_target_ref_name?: string
  pr_number?: string
  pr_state?: string
  pr_title?: string
  pr_source_branch?: string
  pr_merged_at?: string
  pr_closed_at?: string
  latest_commit_sha?: string
  latest_snapshot_id?: string
  latest_snapshot_status?: string
  latest_snapshot_date?: string
  created_at?: string
  updated_at?: string
}

export interface Snapshot {
  id: string
  ref_id: string
  commit_sha: string
  status: string
  tag?: string
  build_url?: string
  run_id?: string
  run_number?: string
  pr_number?: string
  pr_target_branch?: string
  /** PLAN §2: on PR builds, what CI actually built — the ephemeral merge
   * commit it checked out, and the base commit that merge used. */
  merge_commit_sha?: string
  base_commit_sha?: string
  created_at: string
}

export interface SnapshotFile {
  id: string
  kind: string
  format?: string
  tool_name?: string
  filename: string
  size_bytes: number
  sha256?: string
  content_type?: string
  download_url: string
  created_at: string
}

/** A file a producer did not analyse (ADR-034 §2). */
export interface SkippedFile {
  path: string
  /** timeout | too_large | parse_error | resource_limit | other */
  reason: string
}

export interface ProducerRun {
  id: string
  snapshot_id: string
  artifact_id?: string
  run_index: number
  producer: string
  version?: string
  config_digest?: string
  scope: 'full' | 'partial'
  scope_declared: boolean
  scope_paths: string[]
  outcome: 'completed' | 'partial' | 'failed' | ''
  skipped_files: SkippedFile[]
  finding_count: number
  detail?: string
  created_at: string
}

/** One producer's scan coverage on a snapshot, compared with the previous
 * finished snapshot of the ref. */
export interface ProducerCoverage {
  producer: string
  status: 'ran' | 'new' | 'missing' | 'pending'
  outcome?: 'completed' | 'partial' | 'failed'
  version?: string
  previous_version?: string
  scope?: 'full' | 'partial'
  scope_declared: boolean
  scope_paths: string[]
  finding_count: number
  skipped_files: SkippedFile[]
  detail?: string
  runs: ProducerRun[]
}

export interface SnapshotProducerRuns {
  snapshot_id: string
  commit_sha: string
  previous_snapshot_id?: string
  previous_commit_sha?: string
  producers: ProducerCoverage[]
}

/** One entry of the org tool catalog (internal/toolcatalog). */
export interface ToolCatalogEntry {
  name: string
  category: 'advisory_provider' | 'sast' | 'secret_scanning' | 'sbom_generator' | 'vex_source' | 'coverage'
  status: 'healthy' | 'degraded' | 'unhealthy' | 'inactive'
  last_seen_at: string
  last_success_at?: string
  last_error_at?: string
  last_error?: string
  data_points: number
  repo_count: number
  last_outcome?: 'completed' | 'partial' | 'failed'
  warning?: string
  resolution_policy?: ProducerPolicyKind
  policy_threshold?: number
}

/** How a producer's absent findings are resolved (ADR-034 §5). */
export type ProducerPolicyKind = 'coverage' | 'consecutive-absence' | 'explicit' | 'retired'

export interface ProducerPolicy {
  producer: string
  policy: ProducerPolicyKind
  threshold: number
  updated_at: string
}

export interface ToolCatalog {
  org_name: string
  generated_at: string
  tools: ToolCatalogEntry[]
}

/** Scanner applicability of a repository (ADR-035 §3). */
export interface ScannerCapability {
  language: string
  capability: string
  /** "declared" or "measured:<where>" */
  evidence: string
}

export interface ApplicabilityResult {
  revision: string
  status: 'complete' | 'truncated' | 'unknown'
  file_count: number
  languages: Record<string, number>
  modules: Array<{ root: string; build_system: string; manifest: string; languages: string[] }>
  exclusions: Array<{ path: string; reason: string }>
  applicable: Array<{ scanner_id: string; preview?: boolean; modules: string[]; languages: string[]; capabilities: ScannerCapability[]; reason: string }>
  text_only: boolean
  owner_exclusions?: Array<{ path: string; reason: string; languages: string[]; applied: boolean; blocked?: string }>
}

export interface RepoScopeOverride {
  id: string
  kind: 'exclude' | 'module_root'
  path: string
  reason: string
  created_at: string
}

export interface RepoApplicability {
  id: string
  ref_name: string
  commit_sha: string
  detection_revision: string
  catalog_revision: string
  status: ApplicabilityResult['status']
  result: ApplicabilityResult
  created_at: string
}

export interface ScannerCatalogEntry {
  id: string
  name: string
  engine_version: string
  license: string
  support_status: 'supported' | 'preview'
  prerelease: boolean
  notes?: string
  capabilities: ScannerCapability[]
  rulesets: string[]
}

export interface ScannerCatalog {
  revision: string
  mode: 'upstream' | 'mirror' | 'offline'
  scanners: ScannerCatalogEntry[]
  rulesets: Array<{ id: string; name: string; license: string; status: string; notes?: string }>
  /** The imported offline bundle, in offline mode only. */
  bundle?: OfflineBundleStatus
}

export interface OfflineBundleStatus {
  created_at?: string
  catalog_revision?: string
  matches_catalog: boolean
  error?: string
}

/** A scan plan job (ADR-035 §4). */
export interface ScanPlanJob {
  id: string
  scanner_id: string
  status: 'ready' | 'blocked'
  blocked_reason?: string
  targets: string[]
  exclusions: string[]
  scope: 'full' | 'partial'
  capabilities: ScannerCapability[]
  artifact?: { url: string; sha256: string; source: string }
  ruleset?: string
  prerequisites: string[]
  rationale: string
}

export interface ScanPlan {
  digest: string
  mode: 'baseline' | 'full' | 'sweep'
  mode_reason: string
  commit_sha: string
  runner: { os: string; arch: string }
  applicability_status: string
  jobs: ScanPlanJob[]
}

/** Scanner policy (ADR-035 §5). */
export interface ScannerDecision {
  scanner_id: string
  state: 'required' | 'enabled' | 'recommended' | 'disabled' | 'off' | 'not_applicable'
  source: 'org-requirement' | 'repo' | 'org-default'
  repo_mode: 'inherit' | 'enabled' | 'disabled'
  requirements?: string[]
  exempted?: string[]
  applicable: boolean
  preview?: boolean
  reason: string
}

export interface ScannerRequirement {
  id: string
  language: string
  capability: string
  scanner_ids: string[]
  freshness_days: number
  enforcement: 'advisory' | 'blocking'
  created_at: string
}

export interface CoverageException {
  id: string
  repo_id: string
  repo_slug?: string
  requirement_id: string
  scope: string
  reason: string
  status: 'requested' | 'approved' | 'rejected'
  expires_at: string
  created_at: string
}

/** One repository × scanner cell of the org coverage matrix (ADR-035 §6). */
export interface ScanCoverageCell {
  repo_id: string
  repo_slug?: string
  repo_name?: string
  scanner_id: string
  state: string
  reason: string
  configured: string
  required: boolean
  enforcement?: string
  last_run_at?: string
  last_commit?: string
  computed_at: string
}

export interface ComponentDelta {
  purl?: string
  name: string
  version?: string
  base_version?: string
  head_version?: string
  ecosystem?: string
}

export interface SBOMDiff {
  added: ComponentDelta[]
  removed: ComponentDelta[]
  version_changed: ComponentDelta[]
  unchanged: ComponentDelta[]
  summary: {
    total_base: number
    total_head: number
    added: number
    removed: number
    version_changed: number
    unchanged: number
  }
}

export type SBOMCompareFormat = 'spdx-json' | 'cyclonedx-json'

export interface CompareSBOMsRequest {
  base_artifact_id?: string
  base_content?: string
  base_format?: SBOMCompareFormat
  head_artifact_id?: string
  head_content?: string
  head_format?: SBOMCompareFormat
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  /** No source rates it yet (ADR-038 §3); between medium and low. */
  unknown: number
  low: number
  info: number
}

/** One CVSS rating (ADR-038). Score is absent for an unscored v4.0 vector. */
export interface CVSSRating {
  score?: number
  version?: string
  vector?: string
}

/** Exploitation probability in the next 30 days, from FIRST's daily file. */
export interface EPSSScore {
  cve_id: string
  score: number
  percentile: number
  date?: string
}

/** One rater's statement about a finding's advisory (ADR-038 §2). */
export interface FindingRating {
  rater: string
  provider: string
  version?: string
  vector?: string
  score?: number
  /** The rater's own severity word, when it publishes one. */
  label?: string
  severity: string
  /** The rating the finding's severity comes from. */
  used?: boolean
}

export interface AuditLogEntry {
  id: string
  actor_id?: string
  actor_type: string
  actor_display: string
  action: string
  resource_type: string
  resource_id: string
  context?: Record<string, unknown>
  ip_address: string
  created_at: string
}

// Instance-wide audit row: the org-scoped shape plus the owning organization
// (absent for instance-level events such as banner updates and admin grants).
export interface InstanceAuditLogEntry extends AuditLogEntry {
  org_provider?: string
  org_slug?: string
}

// ADR-025 instance jobs observability. Kinds: secret_scan,
// artifact_processing, advisory_scan. Statuses: queued, running, complete,
// failed, cancelled.
// ADR-039: the persisted storage usage sample. Usage only, never prices.
export interface StorageSection {
  collected_at: string
  duration_seconds: number
  error?: string
}

export interface StorageTableUsage {
  name: string
  table_bytes: number
  index_bytes: number
  live_rows: number
  dead_rows: number
}

export interface StoragePostgres extends StorageSection {
  database_bytes: number
  tables: StorageTableUsage[]
  connections_used: number
  connections_max: number
  xid_age: number
  oldest_transaction_seconds?: number
  cache_hit_ratio?: number
}

export interface StorageLedger extends StorageSection {
  kinds: { kind: string; objects: number; bytes: number }[]
}

export interface StorageBackend extends StorageSection {
  objects: number
  bytes: number
  truncated: boolean
  volume_capacity_bytes?: number
  volume_free_bytes?: number
}

export interface StorageSample {
  postgres?: StoragePostgres
  ledger?: StorageLedger
  backend?: StorageBackend
}

export type MetricsExposure = 'disabled' | 'dedicated_port' | 'token' | 'public'

export interface InstanceStorage {
  sample: StorageSample | null
  enabled: boolean
  interval_seconds: number
  inventory_enabled: boolean
  inventory_interval_seconds: number
  artifact_backend: string
  metrics_exposure: MetricsExposure
}

export interface InstanceJobKindCounts {
  kind: string
  queued: number
  running: number
  completed_24h: number
  failed_24h: number
  oldest_queued_at?: string
}

// One replica in the worker registry. Resource numbers are self-reported and
// process-level (not cgroup limits). running_jobs is derived from the claim
// columns; active_jobs is the replica's own report.
export interface InstanceWorker {
  id: string
  hostname: string
  pid: number
  version?: string
  loops: string[]
  started_at: string
  last_heartbeat_at: string
  stopped_at?: string
  cpu_percent?: number
  memory_rss_bytes?: number
  heap_alloc_bytes?: number
  goroutines?: number
  gomaxprocs?: number
  active_jobs: number
  running_jobs: number
  status: 'online' | 'stale' | 'stopped'
}

export interface InstanceJobsOverview {
  kinds: InstanceJobKindCounts[]
  workers: InstanceWorker[]
  heartbeat_interval_seconds: number
}

export interface InstanceJobRun {
  kind: string
  id: string
  label: string
  detail?: string
  status: string
  queued_at: string
  started_at?: string
  finished_at?: string
  worker_id?: string
  attempts: number
  error?: string
}

export interface InstanceJobsTimeline {
  window: string
  since: string
  runs: InstanceJobRun[]
  max_rows: number
  truncated: boolean
}

export interface InstanceJobStatsBucket {
  kind: string
  bucket: string
  completed: number
  failed: number
  p50_duration_seconds: number
  p95_duration_seconds: number
  p50_wait_seconds: number
  p95_wait_seconds: number
}

export interface InstanceJobBaseline {
  kind: string
  samples: number
  p50_duration_seconds: number
  p95_duration_seconds: number
  p50_wait_seconds: number
  p95_wait_seconds: number
}

export interface InstanceJobsStats {
  window: string
  since: string
  bucket_seconds: number
  buckets: InstanceJobStatsBucket[]
  baselines: InstanceJobBaseline[]
}

export type InstanceJobsWindow = '1h' | '6h' | '24h' | '7d'

// ADR-043 §4: how this org treats membership-wide CLI/IDE login tokens.
export type LoginTokensPolicy = 'allow' | 'read_only' | 'deny'

export interface OrgSettings {
  vex_auto_propagate: boolean
  vex_reachability_analysis: boolean
  default_tlp_label: string
  login_tokens: LoginTokensPolicy
  /** Dependency policy (ADR-048 §3, ADR-045 §6): the org floor a repository can only tighten. */
  dependency_cooldown_window?: string
  dependency_cooldown_enforcement?: '' | 'inherit' | 'advisory' | 'blocking' | string
  dependency_install_config?: '' | 'require' | 'warn' | 'off' | string
  dependency_private_namespaces?: string[]
  trusted_declared_scopes?: string[]
}

/** One not-shipped list entry with where it comes from (ADR-045 §6). */
export interface ShippingEntry {
  id?: string
  pattern: string
  reason?: string
  source: 'default' | 'organization' | 'repository' | '.hibou.yaml' | string
  created_by?: string
  created_at?: string
  overridden?: boolean
}

export interface ShippingInfo {
  entries: ShippingEntry[]
  overrides?: string[]
  uploaded_sbom: boolean
  sbom_covers?: string[]
  undeclared_modules?: string[]
  trusted_declared_scopes?: string[]
  can_edit: boolean
}

export interface NotShippedEntry {
  id: string
  org_id: string
  repo_id?: string
  pattern: string
  reason: string
  created_by?: string
  created_at: string
}

// Effective .hibou.yml configuration (or its DB-backed fallback) as the
// server resolved it for the default branch.
export interface RepoConfigGate {
  branches: string[]
  // ADR-037 §8: caps NEW first-party code findings (sast, dast, manual…).
  code?: { enabled?: boolean | null; max_critical?: number | null; max_high?: number | null; max_medium?: number | null }
  // ADR-037 §7: deny NEW findings of any type by CWE.
  cwe?: { deny?: string[]; deny_tree?: string[]; deny_sets?: string[]; deny_categories?: string[]; types?: string[]; min_severity?: string }
  vulnerabilities?: { enabled?: boolean | null; max_critical?: number | null; max_high?: number | null; max_medium?: number | null; max_unknown?: number | null; max_new_total?: number | null }
  licenses?: { deny_categories?: string[]; deny?: string[]; allow?: string[]; deny_unknown?: boolean | null }
  secrets?: { max_new?: number | null }
  coverage?: { min_coverage?: number | null; grace?: number | null; diff_minimum?: number | null }
}

// Where a value in the effective configuration came from. Provenance is the
// point of the view: a threshold with no source is what makes a gate feel
// arbitrary.
export type EffectiveSource = 'file' | 'repo-gate' | 'org-gate' | 'org-policy' | 'default' | 'always'

export type EffectiveSectionStatus = 'enforced' | 'not-configured' | 'disabled'

export interface EffectiveRule {
  label: string
  value: string
  source: EffectiveSource
  detail?: string
}

export interface EffectiveSection {
  name: string
  status: EffectiveSectionStatus
  rules: EffectiveRule[]
  note?: string
}

export interface EffectiveConfig {
  branch: string
  file_gate_matched: boolean
  file_gate_branches?: string[]
  config_present: boolean
  // true = the file could not be read, which is not the same as it having no
  // gates. Collapsing the two would report an unknown as an absence.
  file_unavailable: boolean
  enforcement: 'advisory' | 'blocking'
  enforcement_source: EffectiveSource
  // Absent when no stored gate is enabled.
  gate_source?: 'repo-gate' | 'org-gate'
  sections: EffectiveSection[]
  warnings: string[]
}

export interface RepoConfig {
  version: number
  quality_gates?: RepoConfigGate[]
  coverage?: { exclude?: string[] }
  upload?: { window?: string }
}

export interface Ref {
  id: string
  repo_id: string
  name: string
  ref_type: string
  latest_commit_sha?: string
}

export type FindingPresence = 'reported' | 'not_rechecked' | 'unconfirmed'

export interface Vulnerability {
  /** Advisory is on a known-exploited catalog (CISA KEV / ENISA EUVD). */
  kev?: boolean
  id: string
  type: string
  snapshot_id: string
  title: string
  description: string
  primary_identifier_kind?: string
  primary_identifier_value?: string
  severity: string
  original_severity?: string
  severity_override_reason?: string
  status: string
  state_comment?: string
  detected_at: string
  scanner_name?: string
  scanner_vendor?: string
  file_path?: string
  start_line?: number
  end_line?: number
  fingerprint: string
  component_name?: string
  component_version?: string
  component_purl?: string
  ecosystem?: string
  advisory_id?: string
  language?: string
  confidence?: string
  // The rating the finding uses and who gave it (ADR-038 §2): for an OS
  // package, its distro's own rating.
  cvss?: CVSSRating
  rated_by?: string
  epss?: EPSSScore
  /** Raters fall in different severity bands: the list marks it. */
  ratings_disagree?: boolean
  /** Every rating; on list rows only when raters disagree. */
  ratings?: FindingRating[]
  // Every CWE the finding carries, with its title (ADR-037): from the
  // scanner rule, the advisory, SARIF result taxa, a manual declaration, or
  // the finding type (secrets are CWE-798).
  cwes?: FindingCWE[]
  secret_type?: string
  // Secret findings: the commit that introduced the leak and its author, so a
  // reader knows which credential to rotate and who to ask.
  commit_sha?: string
  author_email?: string
  verified?: boolean
  first_seen_at?: string
  last_seen_at?: string
  has_remediation?: boolean
  remediation_link?: string
  // CI call-graph verdict (govulncheck): reachable | not_reachable | unknown.
  reachability?: string
  // Open PRs whose latest gate run resolves this fingerprint.
  fixed_in_prs?: Array<{ fingerprint: string; ref_name: string; number?: string; title?: string; verified_base_sha?: string }>
  /** deps.dev signals of the affected package version (ADR-048 §8); absent means not evaluated. */
  signals?: ComponentSignals
  /** Whether the affected component reaches clients (ADR-045 §6); absent when not computed. */
  shipped?: boolean
  shipped_reason?: string
  solution?: string
  // Provenance (ADR-020): who produced this finding. 'scanner' is an ingested
  // tool report, 'human' a person, 'agent' an API token acting for an agent.
  origin?: FindingOrigin
  origin_api_key_id?: string
  origin_token_name?: string
  origin_owner_type?: string
  origin_owner_id?: string
  // Presence (ADR-034): 'reported' when the producer reported the finding on
  // this snapshot; 'not_rechecked' / 'unconfirmed' when it was carried
  // forward because nothing re-checked it. Still open either way.
  presence?: FindingPresence
  presence_reason?: string
  last_seen_snapshot_id?: string
  last_seen_commit?: string
  consecutive_absences?: number
  /** Delta resolutions only: fixed | file_removed | no_longer_reported | producer_changed. */
  resolution_reason?: string
  // Server-side acceptance projection (ADR-023); absent = open.
  acceptance?: FindingAcceptance
  // Server-side dispute projection (ADR-026); absent = suppression uncontested.
  dispute?: FindingDispute
  metadata?: Record<string, unknown>
  created_at: string
  updated_at: string
}

export type FindingOrigin = 'scanner' | 'human' | 'agent'

// ADR-020 fine-grained tokens. Capabilities map to product surfaces, not routes.
export type TokenCapability =
  | 'coverage'
  | 'vulnerabilities'
  | 'triage'
  | 'quality_gates'
  | 'components'
  | 'secrets'
  | 'uploads'
  | 'admin'

export type TokenAccessLevel = 'none' | 'read' | 'write'

export interface TokenScope {
  owner?: { type: 'user' | 'org'; id: string }
  org: string
  // Set (and `org` empty) on a device-login token that reaches every org its
  // owner belongs to (ADR-043 §4). Only `hibou login` mints these.
  orgs?: { mode: 'memberships' }
  repos: { mode: 'all' | 'list'; slugs?: string[] }
  permissions: Partial<Record<TokenCapability, TokenAccessLevel>>
}

export type ApiKeyApprovalStatus = 'pending' | 'approved' | 'rejected'

// ADR-043 device login, as the /device approval page sees it.
export type DeviceLoginPreset = 'cli' | 'read-only'

export interface DeviceLoginOrgReach {
  provider: string
  slug: string
  name: string
  role: string
  policy: LoginTokensPolicy
  effective_role: string
}

export interface DeviceLoginRequest {
  user_code: string
  client_id: string
  client_label: string
  client_name: string
  requester_ip: string
  created_at: string
  expires_at: string
  requested_preset: DeviceLoginPreset
  presets: { key: DeviceLoginPreset; permissions: Partial<Record<TokenCapability, TokenAccessLevel>> }[]
  orgs: DeviceLoginOrgReach[]
  default_expires_at: string
  max_expires_at: string
}

export type SearchPresetSurface = 'findings'

export interface SearchPreset {
  id: string
  scope_type: 'user'
  surface: SearchPresetSurface
  name: string
  query: string
  created_at: string
  updated_at: string
}

export interface ApiKey {
  id: string
  user_id: string
  name: string
  description: string
  // Absent/null means a legacy unscoped token carrying the owner's full access.
  scopes?: TokenScope | null
  owner_type: string
  owner_id?: string
  expires_at?: string
  last_used_at?: string
  created_at: string
  // ADR-022 amendment: a member-requested org token stays 'pending' — and
  // fails authentication — until an org admin approves it.
  approval_status: ApiKeyApprovalStatus
  approved_by?: string
  approved_at?: string
  // Creator's name; populated by the org key list so admins can see who
  // requested a pending token.
  created_by_display?: string
}

// Aggregated finding-detail payload (drawer): finding + advisory + decision +
// VEX + where the fingerprint is currently detected.
/** A named CWE group: a ranking/OWASP set or a MITRE View 1400 category. */
export interface CWESetRef {
  slug: string
  name: string
  /** Position in a ranked set (CWE Top 25). */
  rank?: number
}

export type FindingCWESource = 'rule' | 'advisory' | 'sarif_result' | 'declared' | 'type'

/** A CWE a finding carries (ADR-037). The title is always present when the
 * embedded MITRE catalog knows the id. */
export interface FindingCWE {
  id: number
  name: string
  abstraction?: string
  deprecated?: boolean
  source: FindingCWESource
  category?: CWESetRef
  /** Named sets (Top 25, OWASP) — on the finding detail only. */
  sets?: CWESetRef[]
}

/** The compact CWE shape: id plus title. */
export interface CWERef {
  id: number
  name: string
}

/** One catalog entry, as completion and hover show it. */
export interface CWECatalogEntry {
  id: number
  name: string
  abstraction?: string
  deprecated?: boolean
  category?: CWESetRef
  sets?: CWESetRef[]
  /** View 1000 entries under this one (what cwe-tree: adds). */
  descendants?: number
  /** View 1000 parents, nearest first (what a cwe-tree: query would name). */
  ancestors?: number[]
}

export interface CWECatalogResponse {
  version: string
  entries: CWECatalogEntry[]
}

export interface CWESetSummary {
  slug: string
  name: string
  kind: 'ranking' | 'owasp' | 'category'
  member_count: number
}

export interface CWESetsResponse {
  version: string
  sets: CWESetSummary[]
  categories: CWESetSummary[]
}

/** One CWE present in a scope of findings (the CWE list). */
export interface CWEUsage {
  id: number
  name: string
  abstraction?: string
  deprecated?: boolean
  category?: CWESetRef
  sets?: CWESetRef[]
  total: number
  by_type: Record<string, number>
  max_severity: string
  /** View 1000 sub-types under this CWE (what cwe-tree: would add). */
  descendants?: number
}

export interface CWEUsageReport {
  cwes: CWEUsage[]
  /** Findings in scope carrying no CWE — coverage gaps, never hidden. */
  no_cwe: number
  total_findings: number
}

export interface FindingAdvisory {
  canonical_id: string
  title?: string
  description?: string
  /** The advisory's headline: NVD first, else the strongest rater. */
  severity?: string
  cvss?: CVSSRating
  rated_by?: string
  is_malware?: boolean
  malware_type?: string
  fixed_versions?: string[]
  references?: string[]
  aliases?: string[]
  /** When the advisory became public, on upstream's clock — not ours. */
  published_at?: string
}

/**
 * The finding's exploited-catalog listing (ADR-032). On the detail, not the
 * advisory: the gate also blocks findings matched on a bare identifier with no
 * advisory row, and the badge must cover exactly what the gate blocks.
 * Presence is the flag.
 */
export interface FindingKEV {
  /** Catalogs listing it ("cisa", "euvd"), deduplicated. */
  sources: string[]
  entries?: Array<{ source: string; identifier: string; cve_id: string }>
  /** When the first-listed catalog recorded it as exploited (YYYY-MM-DD). */
  date_added?: string
  /** CISA BOD 22-01 remediation deadline — binding on US federal agencies only. */
  due_date?: string
  /** True when CISA marks the entry as used in ransomware campaigns. */
  ransomware_use?: boolean
}

// One entry of a finding's timeline. `scan` events are what the scanners
// observed across snapshots; `activity` events are decisions a human or a token
// recorded — the audit log, narrowed to this one finding.
export interface FindingHistoryEvent {
  source: 'scan' | 'activity' | 'advisory'
  kind: string
  at: string
  ref_name?: string
  ref_type?: string
  commit_sha?: string
  severity?: string
  from?: string
  to?: string
  action?: string
  actor_type?: string
  actor_display?: string
  detail?: Record<string, unknown>
}

export interface FindingHistory {
  events: FindingHistoryEvent[]
  truncated: boolean
}

/** Lifecycle of a manual or agent-filed finding (ADR-034 §4). */
export interface FindingAssertion {
  fingerprint: string
  last_confirmed_at?: string
  last_confirmed_by?: string
  last_confirmed_api_key_id?: string
  closed_kind?: 'resolved' | 'retracted'
  closed_at?: string
  closed_reason?: string
  updated_at: string
}

export interface FindingDetail {
  /** Manual and agent findings only. */
  assertion?: FindingAssertion
  finding: Vulnerability
  advisory?: FindingAdvisory
  kev?: FindingKEV
  acceptance?: FindingAcceptance
  dispute?: FindingDispute
  vex?: Array<{ status: string; justification?: string; source: string; statement?: string }>
  occurrences: Array<{ ref_name: string; ref_type: string; commit_sha: string; snapshot_at: string; status: string }>
  /** deps.dev signals of the affected package version (ADR-048); absent means not evaluated. */
  signals?: ComponentSignals
  /** Package policy verdict on each proposed upgrade target (ADR-048 §8). */
  remediation?: RemediationVersion[]
}

export interface RemediationVersion {
  version: string
  purl: string
  /** advisory (fixed_versions) or deps.dev (recommended version). */
  source: 'advisory' | 'deps.dev' | string
  decision?: 'allow' | 'hold' | 'deny' | string
  in_cooldown: boolean
  cooldown_until?: string
  reason?: string
  warnings?: string[]
  evaluated: boolean
}

export interface CreatedApiKey {
  // Shown once at creation or rotation, never retrievable again.
  key: string
  api_key: ApiKey
}

export interface UnscopedKeyExposure {
  id: string
  name: string
  member_id: string
  member_display: string
  member_email: string
  expires_at?: string
  last_used_at?: string
  created_at: string
}

// A deduplicated scan-rule descriptor (one per tool+rule_id). Findings link to
// it by (scanner_name, primary_identifier_value); the UI joins locally.
export interface ScanRule {
  tool: string
  rule_id: string
  name: string
  short_description?: string
  full_description?: string
  help_uri?: string
  help_markdown?: string
  default_level?: string
  security_severity?: string
  precision?: string
  cwes: CWERef[]
  tags: string[]
}

// Per-option result counts for each vulnerability filter dimension. Each record
// maps an option value (e.g. severity "high", a scanner name, a file path) to
// the number of findings it would match under the current filters.
export interface VulnerabilityFacets {
  type: Record<string, number>
  severity: Record<string, number>
  status: Record<string, number>
  tool: Record<string, number>
  file: Record<string, number>
  /** Busiest 20 CWEs under the current filter, keyed by numeric id ("79"). */
  cwe?: Record<string, number>
}

export interface Advisory {
  id: string
  canonical_id: string
  aliases?: string[]
  title: string
  severity: string
  cvss_score?: number
  is_malware: boolean
  malware_type?: string
  // Every CWE the advisory maps to, with titles (ADR-037).
  cwes?: CWERef[]
  // Optional enriched fields — populated once the backend exposes them
  // (see TODO-BACKEND-deps-nodata.md). Rendered with graceful fallbacks.
  summary?: string
  /** The finding this advisory raised on the component in this snapshot; opens it in the findings view. */
  fingerprint?: string
  fixed_versions?: string[]
  references?: string[]
  source?: string
}

export interface ComponentWithVulns {
  id: string
  name: string
  version: string
  ecosystem: string
  purl: string
  vuln_count: number
  highest_severity?: string
  advisories?: Advisory[]
  // Optional enriched fields (backend TODO). Graceful when absent.
  sources?: string[]
  fixed_versions?: string[]
  usage_paths?: string[][]
  licenses?: string[]
  /** deps.dev package signals (ADR-048); absent means not evaluated, never clean. */
  signals?: ComponentSignals
  /** Inventory provenance (ADR-045 §5). Absent fields mean no source said. */
  relationship?: 'direct' | 'indirect' | 'unknown'
  scopes?: string[]
  modules?: string[]
  resolution?: 'recorded' | 'declared'
  registry?: 'public' | 'private'
  /** Artifacts that reported the component: uploaded SBOM file names, or the extractor's document. */
  inventory_sources?: string[]
  /** Whether the component reaches clients (ADR-045 §6); false stays listed, never hidden. */
  shipped?: boolean
  shipped_reason?: string
  /** A list pattern overruled by an uploaded SBOM that reports the component. */
  shipped_ignored?: string
  /** Declared range of an unresolved component (ADR-045 §2.2). */
  constraint?: string
  /** Image layer that introduced the component, when an image source recorded it (ADR-045 §10). */
  layer?: number
  /** The layer belongs to the base image rather than the application's own layers. */
  base_image?: boolean
}

/** One package version's signals from deps.dev (ADR-048 §2). */
export interface ComponentSignals {
  published_at?: string
  /** Set only while the cooldown is still running; the server computes it at read time. */
  cooldown_until?: string
  in_cooldown: boolean
  deprecated: boolean
  deprecated_reason?: string
  low_usage: boolean
  /** Popular packages deps.dev suggests instead of a low-usage look-alike. */
  alternatives?: string[]
  /** The version is no longer on the public registry. */
  unpublished: boolean
  recommended_version?: string
  source: string
  fetched_at: string
}

export interface ComponentUpdate {
  name: string
  ecosystem: string
  purl: string
  base_version: string
  head_version: string
  base_vuln_count: number
  head_vuln_count: number
  licenses?: string[]
}

export type AcceptanceReasonKind = 'risk_accepted' | 'false_positive'

export type VexJustification =
  | 'component_not_present'
  | 'vulnerable_code_not_present'
  | 'vulnerable_code_not_in_execute_path'
  | 'vulnerable_code_cannot_be_controlled_by_adversary'
  | 'inline_mitigations_already_exist'

export interface FindingAcceptance {
  id?: string
  repo_id?: string
  fingerprint?: string
  // ADR-023: one decision (row exists = accepted), reason_kind says why.
  reason_kind: AcceptanceReasonKind
  reason: string
  labels?: string[]
  vex_justification?: VexJustification
  accepted_by?: string
  expires_at?: string
  created_at?: string
}

// ADR-026: the human-axis override for an in-source suppression. Row exists =
// the suppression is contested and the finding counts as open again.
export interface FindingDispute {
  id?: string
  repo_id?: string
  fingerprint?: string
  reason: string
  disputed_by?: string
  created_at?: string
}

export interface ComponentEntry {
  name: string
  version: string
  ecosystem: string
  purl: string
  vuln_count: number
  licenses?: string[]
}

export interface ComponentGraphNode {
  ref: string
  name: string
  version: string
  ecosystem: string
  vuln_count: number
}

export interface ComponentGraphEdge {
  ref: string
  depends_on: string[]
}

export interface ComponentGraph {
  root_ref: string
  nodes: ComponentGraphNode[]
  edges: ComponentGraphEdge[]
}

// Org-wide aggregated vulnerability: a vulnerability annotated with its repo.
export interface OrgVulnerability extends Vulnerability {
  repo_slug: string
  repo_name: string
}

// Org-wide aggregated component: a component plus the repos it appears in.
export interface OrgComponent extends ComponentWithVulns {
  repos: string[]
}

// Category names come from the backend (internal/license) rather than being
// re-derived here — a duplicated SPDX prefix table would drift.
export type LicenseCategory =
  | 'public-domain'
  | 'permissive'
  | 'weak-copyleft'
  | 'copyleft'
  | 'network-copyleft'
  | 'source-available'
  | 'unknown'

// The denominators behind every other number on the license page. Without them
// "no AGPL found" is indistinguishable from "nothing was scanned".
export interface OrgLicenseCoverage {
  repos_enrolled: number
  repos_with_snapshot: number
  repos_with_components: number
  components_total: number
  // No license metadata at all — an SBOM generator problem.
  undeclared: number
  // Declared but unrecognized by the catalog — a catalog problem.
  unrecognized: number
}

export interface OrgLicenseCategoryStat {
  category: LicenseCategory
  components: number
  repos: number
}

export interface OrgLicenseStat {
  license: string
  category: LicenseCategory
  components: number
  repos: number
  // Conjunctive: every operand's obligations apply at once.
  has_and: boolean
  // Elective: the category shown is the alternative a consumer would pick.
  has_or: boolean
}

export interface OrgLicenseRepoStat {
  slug: string
  name: string
  components: number
  undeclared: number
  by_category: Partial<Record<LicenseCategory, number>>
  snapshot_at?: string
  snapshot_status?: string
}

export interface OrgLicenseOverview {
  coverage: OrgLicenseCoverage
  categories: OrgLicenseCategoryStat[]
  licenses: OrgLicenseStat[]
  repos: OrgLicenseRepoStat[]
}

// One row of the license drilldown.
export interface OrgLicenseComponent {
  purl: string
  name: string
  version: string
  ecosystem: string
  licenses: string[]
  category: LicenseCategory
  repos: string[]
  // false = the SBOM carried no license at all, as opposed to carrying one the
  // catalog does not recognize.
  declared: boolean
}

export interface OrgLicenseComponentQuery {
  license?: string
  category?: string
  repo?: string
  undeclared?: boolean
  page?: number
  per_page?: number
}

// How a repository's own license policy compares to the org's. Only 'looser'
// and 'mixed' are compliance departures: a repository tightening its own policy
// needs no attention.
export type OrgLicenseRelation = 'equivalent' | 'stricter' | 'looser' | 'mixed'

// One axis on which a repository's policy departs from the org's. base and
// override are already rendered by the backend (set axes as comma-joined lists),
// so the UI must not re-derive them.
export interface OrgLicensePolicyDiff {
  field: string
  direction: OrgLicenseRelation
  // The full sets on each side. Unreadable on a real policy — render added and
  // removed instead, and keep these for a tooltip at most.
  base: string
  override: string
  // The delta for set-valued axes; absent on scalar axes like deny_unknown.
  added?: string[]
  removed?: string[]
}

export interface OrgLicensePolicySpec {
  deny_categories: string[]
  deny: string[]
  allow: string[]
  exempt_purls: string[]
  deny_unknown: boolean
  evaluate: 'new' | 'all'
}

export interface OrgLicensePolicyRepo {
  slug: string
  name: string
  // 'organization' = inherits, 'repository' = declares its own (replacing, not
  // merging), 'none' = no policy applies at all.
  source: 'organization' | 'repository' | 'none'
  relation?: OrgLicenseRelation
  differences?: OrgLicensePolicyDiff[]
  // The repository's config could not be fetched — an unknown, not a pass.
  unreadable: boolean
}

// What a candidate policy would flag, before anyone adopts it. Costs no forge
// requests — it reads stored components.
export interface OrgLicenseSimulation {
  // The denominator: "12 would be flagged" means nothing without it.
  components_total: number
  components_flagged: number
  // Components a rule would have flagged but exempt_purls clears.
  exempted: number
  repos_total: number
  // Only repositories with at least one flagged component, worst first.
  repos: Array<{ slug: string, name: string, count: number }>
  licenses: OrgLicenseStat[]
}

export interface OrgLicensePolicyOverview {
  configured: boolean
  policy?: OrgLicensePolicySpec
  // Already sorted departures-first by the backend; do not re-sort.
  repos: OrgLicensePolicyRepo[]
  // false = repositories were NOT checked (the scan is opt-in). An empty `repos`
  // with repos_scanned false means "unknown", never "no overrides".
  repos_scanned: boolean
  total: number
  inheriting: number
  overriding: number
  departures: number
  unreadable: number
}

// The write body. A save REPLACES the policy wholesale — there is no partial
// update, so every field travels on every save. enabled:false retires the
// policy without deleting it.
export interface OrgLicensePolicyInput {
  deny_categories: string[]
  deny: string[]
  allow: string[]
  exempt_purls: string[]
  deny_unknown: boolean
  evaluate: 'new' | 'all'
  enabled: boolean
}

export interface RefSummary {
  vulnerabilities: SeverityCounts
  malware_open: number
  kev_open: number | null
  components_total: number
  coverage_line_rate?: number | null
  tests_total?: number | null
  snapshot_date?: string
  snapshot_status?: string
}

export interface DeltaResult {
  new_vulnerabilities: Vulnerability[]
  resolved_vulnerabilities: Vulnerability[]
  /** Base findings the head build did not re-check (ADR-034 §6): not fixed,
   * still counted. Each carries presence_reason. */
  not_rechecked_vulnerabilities?: Vulnerability[]
  unchanged_vulnerabilities: number
}

export interface CoverageDiffTotals {
  format: string
  line_rate: number | null
  branch_rate: number | null
  lines_valid: number
  lines_covered: number
  branches_valid: number
  branches_covered: number
}

export interface CoverageFileDelta {
  file_path: string
  change: 'added' | 'removed' | 'improved' | 'regressed'
  base_line_rate: number | null
  head_line_rate: number | null
  line_rate_delta: number | null
  base_lines_covered: number
  head_lines_covered: number
  base_lines_valid: number
  head_lines_valid: number
  // New-code lens: of the lines this comparison changed, how many are
  // instrumented and covered. null rate = nothing measurable changed here.
  new_lines: number
  new_covered: number
  new_line_rate: number | null
}

export interface CoverageDiff {
  base: CoverageDiffTotals | null
  head: CoverageDiffTotals | null
  line_rate_delta: number | null
  branch_rate_delta: number | null
  files: CoverageFileDelta[]
  unchanged_files: number
  new_lines: number
  new_covered: number
  new_line_rate: number | null
  new_code_truncated: boolean
}

export interface PatchFileCoverage {
  file_path: string
  covered_lines: number
  uncovered_lines: number
  rate: number | null
  covered_line_numbers: number[] | null
  uncovered_line_numbers: number[] | null
  hunks?: string
  head_covered_lines?: number[]
  head_uncovered_lines?: number[]
  base_covered_lines?: number[]
  base_uncovered_lines?: number[]
}

export interface PatchCoverage {
  covered_lines: number
  uncovered_lines: number
  rate: number | null
  truncated: boolean
  files: PatchFileCoverage[]
}

export interface TestDiffTotals {
  format: string
  total: number
  passed: number
  failed: number
  skipped: number
  errors: number
  duration_seconds: number
}

export interface TestCaseDelta {
  suite: string
  name: string
  classname: string
  file_path: string
  change: 'added' | 'removed' | 'status_changed' | 'slower' | 'faster'
  base_status: string
  head_status: string
  base_duration_seconds: number
  head_duration_seconds: number
  duration_delta_seconds: number
  message: string
}

export interface TestDiff {
  base: TestDiffTotals | null
  head: TestDiffTotals | null
  duration_delta_seconds: number
  added: TestCaseDelta[]
  removed: TestCaseDelta[]
  status_changed: TestCaseDelta[]
  slower: TestCaseDelta[]
  faster: TestCaseDelta[]
  unchanged: number
}

export interface CompareResult {
  base: {
    ref_name: string
    snapshot_id: string
    commit_sha: string
    date: string
    scan_status?: string
  }
  head: {
    ref_name: string
    snapshot_id: string
    commit_sha: string
    date: string
    scan_status?: string
  }
  delta: DeltaResult
  component_diff: {
    added: ComponentEntry[]
    removed: ComponentEntry[]
    updated: ComponentUpdate[]
    unchanged: number
    // Every license in the base snapshot, including the unchanged components
    // the diff lists no entries for. Optional: older servers omit it.
    base_licenses?: string[]
  }
  coverage_diff: CoverageDiff | null
  patch_coverage?: PatchCoverage | null
  test_diff: TestDiff | null
  gate?: {
    passed: boolean
    configured: boolean
    reasons: string[]
    // Disclosures that must not fail the gate: license violations that were
    // waived, exempted, or inherited from the target branch. Separate from
    // `reasons` because `passed` is derived from that list's length.
    notes?: string[]
  } | null
  // 'persisted' = same verdict the forge check shows; 'computed' = live.
  gate_source?: 'persisted' | 'computed'
  gate_commit?: string
  pr?: {
    number: number
    title: string
    source_branch: string
    target_branch: string
    state: string
  } | null
}

// Quality-gate outcome for a pull request (deep-link target of forge PR checks).
export interface PRGate {
  pr_number: number
  head_sha: string
  context: string
  state: 'success' | 'failure' | 'pending'
  conclusion?: 'success' | 'failure' | 'neutral'
  enforcement: 'advisory' | 'blocking'
  passed: boolean
  reasons: string[]
  target_url?: string
  source: 'persisted' | 'computed' | 'pending'
  updated_at?: string
  // Manual maintainer override. Empty string means no override is active.
}

export interface TrendPoint {
  snapshot_id: string
  date: string
  commit_sha: string
  findings_critical: number
  findings_high: number
  findings_medium: number
  findings_unknown: number
  findings_low: number
  findings_info: number
  vulns_critical: number
  vulns_high: number
  vulns_medium: number
  vulns_unknown: number
  vulns_low: number
  vulns_info: number
  components_total: number
}

// Top-level numbers are the aggregate of every report in the snapshot;
// per-tool reports (identified by report_id, since formats can repeat) are
// listed under `reports`.
export interface CoverageReport {
  snapshot_id: string
  line_rate: number | null
  branch_rate: number | null
  lines_valid: number
  lines_covered: number
  branches_valid: number
  branches_covered: number
  format: string
  files: CoverageFile[]
  reports?: CoverageFormatReport[]
  // Present only when ?since=<ref> requested the new-code lens.
  new_code?: CoverageNewCode
}

export interface CoverageNewCode {
  baseline: string
  base_sha: string
  lines: number
  covered: number
  line_rate: number | null
  truncated: boolean
  file_paths: string[]
}

export interface CoverageFormatReport {
  report_id: string
  scope?: string
  line_rate: number | null
  branch_rate: number | null
  lines_valid: number
  lines_covered: number
  branches_valid: number
  branches_covered: number
  format: string
  files: CoverageFile[]
}

export interface SecretScanJob {
  id: string
  repo_id: string
  ref_name: string
  mode: string
  status: string
  attempts: number
  last_error?: string
  created_at: string
  started_at?: string
  finished_at?: string
}

export interface CoverageSource {
  path: string
  commit_sha: string
  content: string
  lines: Array<{ number: number; hits: number; branches_covered: number; branches_valid: number; is_new?: boolean }>
}

export interface CoverageFile {
  file_path: string
  canonical_path: string
  line_rate: number | null
  branch_rate: number | null
  lines_valid: number
  lines_covered: number
  branches_valid: number
  branches_covered: number
}

export interface TestCase {
  suite: string
  name: string
  classname: string
  status: 'passed' | 'failed' | 'skipped' | 'error'
  duration_seconds: number
  message: string
  file_path: string
}

export interface TestReport {
  format: string
  total: number
  passed: number
  failed: number
  skipped: number
  errors: number
  duration_seconds: number
  cases: TestCase[]
}

export interface RepoDashboardEntry {
  repo_id?: string
  repo_name: string
  repo_slug: string
  provider_id: string
  full_name: string
  provider: string
  enrolled: boolean
  status: RepoLifecycleStatus
  vulnerabilities: SeverityCounts
  malware_open: number
  kev_open: number | null
  components_total: number
  last_scanned?: string
  outdated: boolean
}

export interface OrgDashboard {
  repos: RepoDashboardEntry[]
  totals: {
    vulnerabilities: SeverityCounts
    malware_open: number
    kev_open: number | null
    components_total: number
  }
  coverage: {
    total_accessible: number
    enrolled: number
    discovered: number
    active: number
    archived: number
    outdated: number
  }
}

export interface SyncReposResponse {
  synced: boolean
  outcome: 'synced' | 'provider_not_configured' | 'no_installations' | 'no_matching_installation'
  provider: string
  account: string
  repo_count: number
  summary: OrgDashboard['coverage']
}

export function forgeCommitUrl(forgeUrl: string | undefined, providerID: string | undefined, sha: string): string | null {
  if (!forgeUrl || !providerID) return null
  return `${forgeUrl}/${providerID}/commit/${sha}`
}

export interface Notification {
  id: string
  type: string
  title: string
  body: string
  link: string
  severity?: string
  status: 'unread' | 'read'
  created_at: string
}

export interface AuthProvider {
  id: string
  name: string
}

export interface PaginatedResponse<T> {
  data: T[]
  pagination: { page: number; per_page: number; total: number }
}

export interface ApiResponse<T> {
  data: T
  error?: { code: number; message: string }
}

export type CliOS = 'linux' | 'darwin' | 'windows'
export type CliArch = 'amd64' | 'arm64'

export interface ServerVersion {
  current: string
  current_url?: string
  latest?: string
  update_available: boolean
  release_url?: string
  checked_at?: string
}

/** A product watched because its advisories carry no package coordinates upstream. */
export interface WatchedProduct {
  id: string
  label: string
  product_keys: string[]
  vendor_keys: string[]
  /**
   * Null means nothing has ever matched. That is either safety or a wrong name,
   * and the distinction is the whole reason this field is on the row.
   */
  last_matched_at: string | null
  created_at: string
  pending_triage: number
}

export interface WatchPreviewItem {
  cve_id: string
  published_at: string | null
  severity: string
  cvss_score: string | null
  summary: string
}

export interface WatchPreview {
  total: number
  matches: WatchPreviewItem[]
}

export interface WatchCandidate {
  name: string
  ecosystem: string
  repo_count: number
  version_count: number
}

export interface CreateWatchedProductInput {
  label: string
  product_keys?: string[]
  vendor_keys?: string[]
}

export interface TriageQueueItem {
  id: string
  cve_id: string
  label: string
  severity: string
  cvss_score: string | null
  summary: string
  published_at: string | null
  queued_at: string
}

export interface TriageRange {
  product: string
  introduced: string
  fixed: string
  last_affected: string
}

export interface TriageCandidate {
  name: string
  ecosystem: string
  version: string
  repo_count: number
}

export interface TriagePackage {
  ecosystem: string
  name: string
}

export interface TriageDetail extends TriageQueueItem {
  assigner: string
  record_updated_at: string | null
  first_seen_at: string
  ranges: TriageRange[]
  candidates: TriageCandidate[]
  existing_mapping: TriagePackage[]
}

export interface AdvisoryActivityEvent {
  cve_id: string
  kind: string
  /** True when the change happened upstream rather than here. */
  external: boolean
  occurred_at: string
  observed_at: string
  detail: Record<string, unknown> | null
}

export interface FeedHealth {
  at: string
  revision: string
  seen: number
  stored: number
  queued: number
  revised: number
  withdrawn: number
  failed: number
  queued_ids: string[] | null
  /** Reason the most recent sweep failed. Absent when it succeeded. */
  error?: string
  /** When the current run of failures began — how long it has been broken. */
  failing_since?: string
}

/** Which commit the advisory corpus was seeded from, and how old it is. */
export interface CorpusState {
  commit: string
  /** The upstream commit's own date — not when the seed ran. */
  committed_at?: string
}

/** One exploited-catalog mirror's sync state (ADR-032). */
export interface KEVSourceHealth {
  source: string
  /** Last SUCCESSFUL sync; stays in place while error is set. */
  at?: string
  catalog_version?: string
  released?: string
  entries?: number
  skipped?: number
  error?: string
  failing_since?: string
}

export interface KEVHealth {
  /** When the sync loop last completed a pass, successful or not. */
  at: string
  sources: KEVSourceHealth[]
  /** The configured sync cadence, so staleness is judged against the schedule. */
  interval_seconds?: number
}

/** Package-signals sync state (ADR-048 §6): a live provider's "last pass". */
export interface DepsDevHealth {
  /** When the loop last completed a pass, successful or not. */
  at: string
  succeeded_at?: string
  duration_ms?: number
  candidates?: number
  private?: number
  unsupported?: number
  looked_up?: number
  stored?: number
  error?: string
  failing_since?: string
  interval_seconds?: number
  url?: string
}

/** A built-in dependency extraction job (ADR-045 §4.1). */
export interface DepExtractionJob {
  id: string
  repo_id: string
  ref_name: string
  commit_sha?: string
  reason: 'push' | 'release' | 'enrollment' | 'manual' | 'lazy' | string
  snapshot_id?: string
  status: 'pending' | 'processing' | 'complete' | 'failed'
  attempts: number
  last_error?: string
  created_at: string
  started_at?: string
  finished_at?: string
}

export interface DepExtractionModule {
  path: string
  files: string[]
  complete: boolean
  reason?: string
  ecosystems: string[]
  /** Install-time cooldown setting per package manager (ADR-048 §3.1). */
  install_config?: DepInstallConfig[]
}

export interface DepInstallConfig {
  tool: string
  path: string
  setting: string
  present: boolean
  window_seconds?: number
  value?: string
  note?: string
}

export interface DepUpdaterConfig {
  tool: 'renovate' | 'dependabot' | string
  path: string
  present: boolean
  window_seconds?: number
  value?: string
}

export interface DepExtractionRun {
  id: string
  snapshot_id: string
  commit_sha: string
  extractor_version: string
  component_count: number
  modules: DepExtractionModule[]
  updaters?: DepUpdaterConfig[]
  reused_from?: string
  created_at: string
}

/** One inventory source of a release (ADR-046 §4): an artifact with its origin and state. */
export interface ReleaseSource {
  id: string
  filename: string
  tool: string
  tool_version?: string
  origin: 'ci' | 'hibou' | 'manual' | string
  sha256?: string
  component_count: number
  created_at: string
  /** Recorded after the release date: retroactive evidence. */
  after_release: boolean
  revoked: boolean
  revoke_reason?: string
  revoked_at?: string
  metadata?: Record<string, unknown>
  extractor_version?: string
}

export interface ReleaseSources {
  sources: ReleaseSource[]
  components: Array<{ purl: string; name: string; version: string }>
  current_extractor_version?: string
  /** The ready-to-copy command to record deliverables (ADR-046 §4.1). */
  record_command: string
  can_revoke: boolean
}

export interface DepExtractionStatus {
  enabled: boolean
  ref: string
  job?: DepExtractionJob
  run?: DepExtractionRun
  /** What this server extracts with; an older run is re-extracted by the upgrade pass. */
  current_extractor_version?: string
}

export interface AdvisoryActivity {
  events: AdvisoryActivityEvent[]
  health: FeedHealth | null
  corpus: CorpusState | null
  kev?: KEVHealth | null
  depsdev?: DepsDevHealth | null
}

export interface InstanceMembership {
  org_id: string
  org_slug: string
  provider: string
  role: string
}

export interface InstanceGrant {
  role: string
  org_slug: string
  org_id: string | null
  suspended: boolean
  reason: string
}

export interface InstanceMember {
  user_id: string
  email: string
  display_name: string
  /** Forge-derived and read-only: the sync owns these. */
  memberships: InstanceMembership[]
  /** Operator-owned; the sync never writes them. */
  grants: InstanceGrant[]
}

class ApiClient {
  private async request<T>(path: string, opts?: RequestInit): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
      ...opts,
      headers: { 'Content-Type': 'application/json', ...opts?.headers },
    })

    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      throw new Error(body?.error?.message || `HTTP ${res.status}`)
    }

    if (res.status === 204) {
      return undefined as T
    }

    return res.json()
  }

  getProviders() {
    return this.request<ApiResponse<AuthProvider[]>>('/auth/providers')
  }

  getMe() {
    return this.request<ApiResponse<User>>('/users/me')
  }

  /** Rejects when the server refused the logout: the session is still live. */
  logout() {
    return this.request<void>('/auth/logout', { method: 'POST' })
  }

  listApiKeys() {
    return this.request<ApiResponse<ApiKey[]>>('/users/me/api-keys')
  }

  getDeviceLogin(userCode: string) {
    return this.request<ApiResponse<DeviceLoginRequest>>(`/auth/device?user_code=${encodeURIComponent(userCode)}`)
  }

  approveDeviceLogin(body: { user_code: string; preset: DeviceLoginPreset; expires_at: string }) {
    return this.request<ApiResponse<{ status: 'approved'; token_name: string }>>('/auth/device/approve', {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  denyDeviceLogin(userCode: string) {
    return this.request<ApiResponse<{ status: 'denied' }>>('/auth/device/deny', {
      method: 'POST',
      body: JSON.stringify({ user_code: userCode }),
    })
  }

  createApiKey(body: { name: string; description?: string; scopes: TokenScope; expires_at: string }) {
    return this.request<ApiResponse<CreatedApiKey>>('/users/me/api-keys', {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  updateApiKey(
    keyID: string,
    body: { name?: string; description?: string; scopes?: TokenScope; expires_at?: string },
  ) {
    return this.request<ApiResponse<ApiKey>>(`/users/me/api-keys/${keyID}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    })
  }

  rotateApiKey(keyID: string) {
    return this.request<ApiResponse<CreatedApiKey>>(`/users/me/api-keys/${keyID}/rotate`, {
      method: 'POST',
    })
  }

  deleteApiKey(keyID: string) {
    return this.request<void>(`/users/me/api-keys/${keyID}`, { method: 'DELETE' })
  }

  listSearchPresets(surface: SearchPresetSurface) {
    return this.request<ApiResponse<SearchPreset[]>>(`/users/me/search-presets?surface=${surface}`)
  }

  createSearchPreset(body: { surface: SearchPresetSurface; name: string; query: string }) {
    return this.request<ApiResponse<SearchPreset>>('/users/me/search-presets', {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  updateSearchPreset(presetID: string, body: { name: string; query: string }) {
    return this.request<ApiResponse<SearchPreset>>(`/users/me/search-presets/${presetID}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    })
  }

  deleteSearchPreset(presetID: string) {
    return this.request<void>(`/users/me/search-presets/${presetID}`, { method: 'DELETE' })
  }

  // Org-owned tokens (ADR-020/022): managed by any org admin, survive the
  // creator leaving. Any member can create one (non-admins get a pending
  // request); management and review require an admin browser session.
  listOrgApiKeys(provider: string, slug: string) {
    return this.request<ApiResponse<ApiKey[]>>(`/orgs/${provider}/${slug}/api-keys`)
  }

  // Legacy full-access tokens owned by org members — the org's real token risk
  // surface until they are restricted or expire. Admin-only, visibility-only.
  listOrgTokenExposure(provider: string, slug: string) {
    return this.request<ApiResponse<UnscopedKeyExposure[]>>(`/orgs/${provider}/${slug}/api-keys/exposure`)
  }

  createOrgApiKey(
    provider: string,
    slug: string,
    body: { name: string; description?: string; scopes: TokenScope; expires_at: string },
  ) {
    return this.request<ApiResponse<CreatedApiKey>>(`/orgs/${provider}/${slug}/api-keys`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  updateOrgApiKey(
    provider: string,
    slug: string,
    keyID: string,
    body: { name?: string; description?: string; scopes?: TokenScope; expires_at?: string },
  ) {
    return this.request<ApiResponse<ApiKey>>(`/orgs/${provider}/${slug}/api-keys/${keyID}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    })
  }

  rotateOrgApiKey(provider: string, slug: string, keyID: string) {
    return this.request<ApiResponse<CreatedApiKey>>(`/orgs/${provider}/${slug}/api-keys/${keyID}/rotate`, {
      method: 'POST',
    })
  }

  // Approve a member-requested org token so it can authenticate; the scope
  // ceiling is re-validated server-side at review time.
  approveOrgApiKey(provider: string, slug: string, keyID: string) {
    return this.request<ApiResponse<ApiKey>>(`/orgs/${provider}/${slug}/api-keys/${keyID}/approve`, {
      method: 'POST',
    })
  }

  rejectOrgApiKey(provider: string, slug: string, keyID: string) {
    return this.request<ApiResponse<ApiKey>>(`/orgs/${provider}/${slug}/api-keys/${keyID}/reject`, {
      method: 'POST',
    })
  }

  deleteOrgApiKey(provider: string, slug: string, keyID: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/api-keys/${keyID}`, { method: 'DELETE' })
  }

  listOrgs() {
    return this.request<PaginatedResponse<Organization>>('/orgs')
  }

  listOnboardableOrgs() {
    return this.request<ApiResponse<OnboardableAccount[]>>('/orgs/onboardable')
  }

  createOrg(body: { name: string; slug: string; display_name: string; provider?: string }) {
    return this.request<ApiResponse<Organization>>('/orgs', {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  getOrg(provider: string, slug: string) {
    return this.request<ApiResponse<Organization>>(`/orgs/${provider}/${slug}`)
  }

  listTeams(provider: string, slug: string) {
    return this.request<PaginatedResponse<Team>>(`/orgs/${provider}/${slug}/teams`)
  }

  // Org members are forge-synced (permission sync / first login); the UI only
  // manages roles and removal. Mutations are admin-enforced server-side.
  listTriageQueue(provider: string, slug: string) {
    return this.request<ApiResponse<TriageQueueItem[]>>(`/orgs/${provider}/${slug}/triage`)
  }

  getTriageItem(provider: string, slug: string, itemID: string) {
    return this.request<ApiResponse<TriageDetail>>(`/orgs/${provider}/${slug}/triage/${itemID}`)
  }

  decideTriageItem(
    provider: string,
    slug: string,
    itemID: string,
    body: { packages?: TriagePackage[]; dismiss?: boolean },
  ) {
    return this.request<void>(`/orgs/${provider}/${slug}/triage/${itemID}/decision`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  /** One advisory's history: what happened to it anywhere, upstream included. */
  getAdvisoryEvents(advisoryID: string) {
    return this.request<ApiResponse<AdvisoryActivityEvent[]>>(
      `/instance/advisories/${encodeURIComponent(advisoryID)}/events`,
    )
  }

  /** The whole instance's advisory activity, with feed health and corpus age. */
  listAdvisoryEvents(limit = 50) {
    return this.request<ApiResponse<AdvisoryActivity>>(`/instance/advisories/events?limit=${limit}`)
  }

  listInstanceMembers() {
    return this.request<ApiResponse<InstanceMember[]>>('/instance/members')
  }

  grantLocalRole(body: { user_id: string; role: string; org_id?: string }) {
    return this.request<void>('/instance/members/grants', {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  revokeLocalRole(body: { user_id: string; role: string; org_id?: string }) {
    return this.request<void>('/instance/members/revocations', {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  listWatchCandidates() {
    return this.request<ApiResponse<WatchCandidate[]>>('/instance/advisories/watches/candidates')
  }

  listWatches() {
    return this.request<ApiResponse<WatchedProduct[]>>('/instance/advisories/watches')
  }

  /**
   * Which advisories name a set of products. Used to answer "would this watch
   * have caught anything?" before the watch exists — a wrong name otherwise
   * produces silence, and silence looks exactly like safety.
   *
   * A filter on the advisories collection, not a browser: the server refuses an
   * unfiltered list, because the corpus is ~382,000 records.
   */
  listAdvisories(products: string[], limit = 10) {
    const params = new URLSearchParams()
    products.forEach(product => params.append('product', product))
    params.set('limit', String(limit))
    return this.request<ApiResponse<WatchPreview>>(`/instance/advisories?${params.toString()}`)
  }

  createWatch(input: CreateWatchedProductInput) {
    return this.request<ApiResponse<WatchedProduct>>('/instance/advisories/watches', {
      method: 'POST',
      body: JSON.stringify(input),
    })
  }

  deleteWatch(id: string) {
    return this.request<void>(`/instance/advisories/watches/${id}`, { method: 'DELETE' })
  }

  listOrgMembers(provider: string, slug: string) {
    return this.request<PaginatedResponse<OrgMember>>(`/orgs/${provider}/${slug}/members?per_page=100`)
  }

  updateOrgMemberRole(provider: string, slug: string, userID: string, role: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/members/${userID}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role }),
    })
  }

  removeOrgMember(provider: string, slug: string, userID: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/members/${userID}`, { method: 'DELETE' })
  }

  // Integrations: config is redacted for non-admins by the server.
  listIntegrations(provider: string, slug: string) {
    return this.request<PaginatedResponse<OrgIntegration>>(`/orgs/${provider}/${slug}/integrations?per_page=100`)
  }

  createIntegration(
    provider: string,
    slug: string,
    body: { name: string; integration_type: string; config: Record<string, unknown>; enabled: boolean },
  ) {
    return this.request<ApiResponse<OrgIntegration>>(`/orgs/${provider}/${slug}/integrations`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  updateIntegration(
    provider: string,
    slug: string,
    integrationID: string,
    body: { name: string; config: Record<string, unknown>; enabled: boolean },
  ) {
    return this.request<ApiResponse<OrgIntegration>>(`/orgs/${provider}/${slug}/integrations/${integrationID}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    })
  }

  deleteIntegration(provider: string, slug: string, integrationID: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/integrations/${integrationID}`, { method: 'DELETE' })
  }

  replayIntegration(provider: string, slug: string, integrationID: string) {
    return this.request<ApiResponse<IntegrationReplayResult>>(
      `/orgs/${provider}/${slug}/integrations/${integrationID}/replay`,
      { method: 'POST', body: JSON.stringify({}) },
    )
  }

  listNotificationRules(provider: string, slug: string) {
    return this.request<PaginatedResponse<NotificationRule>>(`/orgs/${provider}/${slug}/notification-rules?per_page=100`)
  }

  createNotificationRule(
    provider: string,
    slug: string,
    body: {
      name: string
      event_type: string
      conditions: Record<string, unknown>
      destination_type: string
      destination_config: Record<string, unknown>
      enabled: boolean
    },
  ) {
    return this.request<ApiResponse<NotificationRule>>(`/orgs/${provider}/${slug}/notification-rules`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  updateNotificationRule(
    provider: string,
    slug: string,
    ruleID: string,
    body: {
      name: string
      event_type: string
      conditions: Record<string, unknown>
      destination_type: string
      destination_config: Record<string, unknown>
      enabled: boolean
    },
  ) {
    return this.request<ApiResponse<NotificationRule>>(`/orgs/${provider}/${slug}/notification-rules/${ruleID}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    })
  }

  deleteNotificationRule(provider: string, slug: string, ruleID: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/notification-rules/${ruleID}`, { method: 'DELETE' })
  }

  // DB-backed quality gates: the fallback when a repo has no .hibou.yml.
  listQualityGates(provider: string, slug: string) {
    return this.request<PaginatedResponse<QualityGate>>(`/orgs/${provider}/${slug}/quality-gates?per_page=100`)
  }

  createQualityGate(provider: string, slug: string, body: QualityGateInput) {
    return this.request<ApiResponse<QualityGate>>(`/orgs/${provider}/${slug}/quality-gates`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  updateQualityGate(provider: string, slug: string, gateID: string, body: QualityGateInput) {
    return this.request<ApiResponse<QualityGate>>(`/orgs/${provider}/${slug}/quality-gates/${gateID}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    })
  }

  deleteQualityGate(provider: string, slug: string, gateID: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/quality-gates/${gateID}`, { method: 'DELETE' })
  }

  deleteOrg(provider: string, slug: string) {
    return this.request<void>(`/orgs/${provider}/${slug}`, { method: 'DELETE' })
  }

  removeRepo(provider: string, slug: string, repoSlug: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/repos/${repoSlug}`, { method: 'DELETE' })
  }

  listRepos(provider: string, slug: string) {
    return this.request<PaginatedResponse<Repository>>(`/orgs/${provider}/${slug}/repos`)
  }

  enrollRepo(
    provider: string,
    slug: string,
    body: { name: string; slug: string; provider_id: string; default_branch?: string },
  ) {
    return this.request<ApiResponse<Repository>>(`/orgs/${provider}/${slug}/repos`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  syncRepos(provider: string, slug: string) {
    return this.request<ApiResponse<SyncReposResponse>>(`/orgs/${provider}/${slug}/repos/sync`, {
      method: 'POST',
    })
  }

  getRepo(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<Repository>>(`/orgs/${provider}/${slug}/repos/${repoSlug}`)
  }

  updateRepo(provider: string, slug: string, repoSlug: string, body: { name?: string; default_branch?: string }) {
    return this.request<ApiResponse<Repository>>(`/orgs/${provider}/${slug}/repos/${repoSlug}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    })
  }

  getRepoConfig(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<RepoConfig>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/config`)
  }

  getEffectiveRepoConfig(provider: string, slug: string, repoSlug: string, branch?: string) {
    const query = branch ? `?branch=${encodeURIComponent(branch)}` : ''
    return this.request<ApiResponse<EffectiveConfig>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/config/effective${query}`,
    )
  }

  onboardRepo(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<{ number: number; html_url: string; title: string }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/onboard`,
      { method: 'POST' },
    )
  }

  getOnboardingStatus(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<{ pull_request: { number: number; html_url: string; title: string } | null }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/onboard`,
    )
  }

  getOrgSettings(provider: string, slug: string) {
    return this.request<ApiResponse<OrgSettings>>(`/orgs/${provider}/${slug}/settings`)
  }

  updateOrgSettings(provider: string, slug: string, body: OrgSettings) {
    return this.request<ApiResponse<OrgSettings>>(`/orgs/${provider}/${slug}/settings`, {
      method: 'PUT',
      body: JSON.stringify(body),
    })
  }

  listClients(provider: string, slug: string, params?: { page?: number; per_page?: number }) {
    const query = new URLSearchParams()
    if (params?.page) {
      query.set('page', String(params.page))
    }
    if (params?.per_page) {
      query.set('per_page', String(params.per_page))
    }

    const qs = query.toString()
    return this.request<PaginatedResponse<Client>>(`/orgs/${provider}/${slug}/clients${qs ? `?${qs}` : ''}`)
  }

  createClient(
    provider: string,
    slug: string,
    body: {
      name: string
      slug: string
      labels?: Record<string, string>
      client_type?: string
      contact_email?: string
      contact_name?: string
      metadata?: Record<string, unknown>
      notification_prefs?: Record<string, unknown>
    },
  ) {
    return this.request<ApiResponse<Client>>(`/orgs/${provider}/${slug}/clients`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  getClient(provider: string, slug: string, clientSlug: string) {
    return this.request<ApiResponse<Client>>(`/orgs/${provider}/${slug}/clients/${clientSlug}`)
  }

  listClientLabelKeys(provider: string, slug: string) {
    return this.request<ApiResponse<string[]>>(`/orgs/${provider}/${slug}/clients/label-keys`)
  }

  updateClient(
    provider: string,
    slug: string,
    clientSlug: string,
    body: {
      name: string
      labels?: Record<string, string>
      client_type?: string
      contact_email?: string
      contact_name?: string
      metadata?: Record<string, unknown>
      notification_prefs?: Record<string, unknown>
    },
  ) {
    return this.request<ApiResponse<Client>>(`/orgs/${provider}/${slug}/clients/${clientSlug}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    })
  }

  deleteClient(provider: string, slug: string, clientSlug: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/clients/${clientSlug}`, { method: 'DELETE' })
  }

  listClientDeployments(
    provider: string,
    slug: string,
    clientSlug: string,
    params?: { page?: number; per_page?: number },
  ) {
    const query = new URLSearchParams()
    if (params?.page) {
      query.set('page', String(params.page))
    }
    if (params?.per_page) {
      query.set('per_page', String(params.per_page))
    }

    const qs = query.toString()
    return this.request<PaginatedResponse<Deployment>>(
      `/orgs/${provider}/${slug}/clients/${clientSlug}/deployments${qs ? `?${qs}` : ''}`,
    )
  }

  createDeployment(
    provider: string,
    slug: string,
    clientSlug: string,
    body: {
      release_id: string
      environment?: string
      status?: string
      deployed_at?: string
      deployed_by?: string
      rollback_target_id?: string
      notes?: string
    },
  ) {
    return this.request<ApiResponse<Deployment>>(`/orgs/${provider}/${slug}/clients/${clientSlug}/deployments`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  getClientImpact(provider: string, slug: string, clientSlug: string) {
    return this.request<ApiResponse<ClientImpact>>(`/orgs/${provider}/${slug}/clients/${clientSlug}/impact`)
  }

  listReleases(
    provider: string,
    slug: string,
    repoSlug: string,
    params?: { page?: number; per_page?: number; q?: string; client?: string; vulnerable?: boolean },
  ) {
    const query = new URLSearchParams()
    if (params?.page) {
      query.set('page', String(params.page))
    }
    if (params?.per_page) {
      query.set('per_page', String(params.per_page))
    }
    if (params?.q) {
      query.set('q', params.q)
    }
    if (params?.client) {
      query.set('client', params.client)
    }
    if (params?.vulnerable) {
      query.set('vulnerable', 'true')
    }

    const qs = query.toString()
    return this.request<PaginatedResponse<ReleaseWithRisk>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/releases${qs ? `?${qs}` : ''}`,
    )
  }

  resolveReleaseDivergence(
    provider: string,
    slug: string,
    repoSlug: string,
    releaseId: string,
    action: 'adopt' | 'keep',
  ) {
    return this.request<ApiResponse<Release>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/releases/${releaseId}/divergence`,
      { method: 'POST', body: JSON.stringify({ action }) },
    )
  }

  addReleaseClient(
    provider: string,
    slug: string,
    repoSlug: string,
    releaseId: string,
    body: { client_slug: string; environment?: string; notes?: string },
  ) {
    return this.request<ApiResponse<Deployment>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/releases/${releaseId}/clients`,
      { method: 'POST', body: JSON.stringify(body) },
    )
  }

  removeReleaseClient(provider: string, slug: string, repoSlug: string, releaseId: string, deploymentId: string) {
    return this.request<ApiResponse<Deployment>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/releases/${releaseId}/clients/${deploymentId}`,
      { method: 'DELETE' },
    )
  }

  search(
    provider: string,
    slug: string,
    params: { q: string; type?: string; severity?: string; page?: number; per_page?: number },
  ) {
    const query = new URLSearchParams({ q: params.q })
    if (params.type) {
      query.set('type', params.type)
    }
    if (params.severity) {
      query.set('severity', params.severity)
    }
    if (params.page) {
      query.set('page', String(params.page))
    }
    if (params.per_page) {
      query.set('per_page', String(params.per_page))
    }

    return this.request<ApiResponse<SearchResponse>>(`/orgs/${provider}/${slug}/search?${query.toString()}`)
  }

  listAuditLogs(
    provider: string,
    slug: string,
    params?: { action?: string; resource_type?: string; repo?: string; page?: number; per_page?: number },
  ) {
    const query = new URLSearchParams()

    if (params?.action) {
      query.set('action', params.action)
    }
    if (params?.resource_type) {
      query.set('resource_type', params.resource_type)
    }
    if (params?.repo) {
      query.set('repo', params.repo)
    }
    if (params?.page) {
      query.set('page', String(params.page))
    }
    if (params?.per_page) {
      query.set('per_page', String(params.per_page))
    }

    const qs = query.toString()
    return this.request<PaginatedResponse<AuditLogEntry>>(
      `/orgs/${provider}/${slug}/audit-logs${qs ? `?${qs}` : ''}`,
    )
  }

  listRefs(provider: string, slug: string, repoSlug: string) {
    return this.request<PaginatedResponse<Ref>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/refs?per_page=200`,
    )
  }

  listRefsEnhanced(provider: string, slug: string, repoSlug: string) {
    return this.request<PaginatedResponse<EnhancedRef>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/refs/enhanced?per_page=200`,
    )
  }

  listSnapshots(
    provider: string,
    slug: string,
    repoSlug: string,
    params?: { ref?: string; page?: number; per_page?: number },
  ) {
    const query = new URLSearchParams()

    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.page) {
      query.set('page', String(params.page))
    }
    if (params?.per_page) {
      query.set('per_page', String(params.per_page))
    }

    const qs = query.toString()
    return this.request<PaginatedResponse<Snapshot>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/snapshots${qs ? `?${qs}` : ''}`,
    )
  }

  listSnapshotFiles(provider: string, slug: string, repoSlug: string, snapshotId: string) {
    return this.request<ApiResponse<SnapshotFile[]>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/snapshots/${snapshotId}/files`,
    )
  }

  getScannerCatalog() {
    return this.request<ApiResponse<ScannerCatalog>>('/scanner-catalog')
  }

  getRepoApplicability(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<{ applicability: RepoApplicability | null }>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/applicability`)
  }

  refreshRepoApplicability(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<{ applicability: RepoApplicability | null }>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/applicability/refresh`, { method: 'POST' })
  }

  previewScanPlan(provider: string, slug: string, repoSlug: string, runner: { os: string; arch: string }) {
    return this.request<ApiResponse<{ plan: ScanPlan }>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/scan-plans`, {
      method: 'POST',
      body: JSON.stringify({ runner, dry_run: true }),
    })
  }

  listScopeOverrides(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<RepoScopeOverride[]>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/scope-overrides`)
  }

  createScopeOverride(provider: string, slug: string, repoSlug: string, body: { kind: RepoScopeOverride['kind']; path: string; reason: string }) {
    return this.request<ApiResponse<RepoScopeOverride>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/scope-overrides`, { method: 'POST', body: JSON.stringify(body) })
  }

  deleteScopeOverride(provider: string, slug: string, repoSlug: string, id: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/repos/${repoSlug}/scope-overrides?id=${encodeURIComponent(id)}`, { method: 'DELETE' })
  }

  getRepoScannerSettings(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<{ decisions: ScannerDecision[]; requirements: ScannerRequirement[]; exceptions: CoverageException[] }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/scanner-settings`,
    )
  }

  setRepoScannerSetting(provider: string, slug: string, repoSlug: string, scannerID: string, mode: ScannerDecision['repo_mode']) {
    return this.request<ApiResponse<{ decisions: ScannerDecision[]; requirements: ScannerRequirement[]; exceptions: CoverageException[] }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/scanner-settings`,
      { method: 'PUT', body: JSON.stringify({ scanner_id: scannerID, mode }) },
    )
  }

  requestCoverageException(provider: string, slug: string, repoSlug: string, body: { requirement_id: string; reason: string; expires_in_days: number; scope?: string }) {
    return this.request<ApiResponse<CoverageException>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/coverage-exceptions`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
  }

  getScannerRequirements(provider: string, slug: string) {
    return this.request<ApiResponse<{ requirements: ScannerRequirement[]; pending_exceptions: CoverageException[] }>>(`/orgs/${provider}/${slug}/scanner-requirements`)
  }

  setScannerRequirement(provider: string, slug: string, body: Pick<ScannerRequirement, 'language' | 'capability' | 'scanner_ids' | 'freshness_days' | 'enforcement'>) {
    return this.request<ApiResponse<ScannerRequirement>>(`/orgs/${provider}/${slug}/scanner-requirements`, { method: 'PUT', body: JSON.stringify(body) })
  }

  deleteScannerRequirement(provider: string, slug: string, id: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/scanner-requirements?id=${encodeURIComponent(id)}`, { method: 'DELETE' })
  }

  decideCoverageException(provider: string, slug: string, id: string, approve: boolean) {
    return this.request<ApiResponse<CoverageException>>(`/orgs/${provider}/${slug}/coverage-exceptions/${id}/decision`, {
      method: 'POST',
      body: JSON.stringify({ approve }),
    })
  }

  getOrgScanCoverage(provider: string, slug: string, filter: { state?: string; scanner?: string; required?: boolean; page?: number }) {
    const query = new URLSearchParams()
    if (filter.state) query.set('state', filter.state)
    if (filter.scanner) query.set('scanner', filter.scanner)
    if (filter.required) query.set('required', 'true')
    if (filter.page) query.set('page', String(filter.page))
    return this.request<ApiResponse<{ cells: ScanCoverageCell[]; summary: Array<{ state: string; required: boolean; cells: number }>; page: number; per_page: number }>>(
      `/orgs/${provider}/${slug}/scan-coverage?${query.toString()}`,
    )
  }

  orgScanCoverageCsvUrl(provider: string, slug: string, filter: { state?: string; scanner?: string; required?: boolean }) {
    const query = new URLSearchParams({ format: 'csv' })
    if (filter.state) query.set('state', filter.state)
    if (filter.scanner) query.set('scanner', filter.scanner)
    if (filter.required) query.set('required', 'true')
    return `${API_BASE}/orgs/${provider}/${slug}/scan-coverage?${query.toString()}`
  }

  bulkScannerSetting(provider: string, slug: string, body: { scanner_id: string; mode: 'enabled' | 'disabled'; dry_run: boolean }) {
    return this.request<ApiResponse<{ changes: Array<{ repo_id: string; repo_slug: string; from: string }>; kept: Array<{ repo_id: string; repo_slug: string; from: string }>; applied: boolean }>>(
      `/orgs/${provider}/${slug}/scanner-settings/bulk`,
      { method: 'POST', body: JSON.stringify(body) },
    )
  }

  refreshOrgScanCoverage(provider: string, slug: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/scan-coverage/refresh`, { method: 'POST' })
  }

  getToolCatalog(provider: string, slug: string) {
    return this.request<ApiResponse<ToolCatalog>>(`/orgs/${provider}/${slug}/tool-catalog`)
  }

  setProducerPolicy(provider: string, slug: string, body: { producer: string; policy: ProducerPolicyKind; threshold: number }) {
    return this.request<ApiResponse<ProducerPolicy>>(`/orgs/${provider}/${slug}/producer-policies`, {
      method: 'PUT',
      body: JSON.stringify(body),
    })
  }

  resetProducerPolicy(provider: string, slug: string, producer: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/producer-policies?producer=${encodeURIComponent(producer)}`, { method: 'DELETE' })
  }

  getSnapshotProducerRuns(provider: string, slug: string, repoSlug: string, snapshotId: string) {
    return this.request<ApiResponse<SnapshotProducerRuns>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/snapshots/${snapshotId}/producer-runs`,
    )
  }

  // Absolute path to download all of a snapshot's files as a zip. The browser
  // navigates here directly to start the download.
  snapshotArchiveUrl(provider: string, slug: string, repoSlug: string, snapshotId: string) {
    return `${API_BASE}/orgs/${provider}/${slug}/repos/${repoSlug}/snapshots/${snapshotId}/files.zip`
  }

  compareRefs(
    provider: string,
    slug: string,
    repoSlug: string,
    base: string,
    head: string,
    opts?: { baseSnapshot?: string; headSnapshot?: string },
  ) {
    const query = new URLSearchParams({ base, head })
    if (opts?.baseSnapshot) {
      query.set('base_snapshot', opts.baseSnapshot)
    }
    if (opts?.headSnapshot) {
      query.set('head_snapshot', opts.headSnapshot)
    }

    return this.request<ApiResponse<CompareResult>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/compare?${query.toString()}`,
    )
  }

  getPRGate(provider: string, slug: string, repoSlug: string, pr: string | number) {
    return this.request<ApiResponse<PRGate>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/pulls/${pr}/gate`,
    )
  }


  /** Tools: compare two local SBOM files, no repository involved. */
  compareLocalSBOMs(body: CompareSBOMsRequest) {
    return this.request<ApiResponse<SBOMDiff>>('/tools/sbom/compare', { method: 'POST', body: JSON.stringify(body) })
  }

  compareSBOMs(provider: string, slug: string, repoSlug: string, body: CompareSBOMsRequest) {
    return this.request<ApiResponse<SBOMDiff>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/sbom/compare`,
      { method: 'POST', body: JSON.stringify(body) },
    )
  }

  getTrends(
    provider: string,
    slug: string,
    repoSlug: string,
    params?: { ref?: string; limit?: number; since?: string },
  ) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.since) {
      query.set('since', params.since)
    }
    if (params?.limit) {
      query.set('limit', String(params.limit))
    }

    const qs = query.toString()
    return this.request<ApiResponse<TrendPoint[]>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/trends${qs ? `?${qs}` : ''}`,
    )
  }

  listRefVulnerabilities(
    provider: string,
    slug: string,
    repoSlug: string,
    params?: {
      ref?: string
      snapshot?: string
      type?: string
      severity?: string
      status?: string
      scanner?: string
      tool?: string
      language?: string
      file?: string
      search?: string
      acceptance?: string
      /** Server-side known-exploited facet (also available as `exploited:true` in q). */
      exploited?: boolean
      risk_only?: boolean
      // Full boolean filterquery (AND/OR/parentheses); when set the server
      // uses it exclusively and the discrete params above are ignored.
      q?: string
      sort?: string
      page?: number
      per_page?: number
    },
  ) {
    const query = new URLSearchParams()

    if (params?.q) {
      query.set('q', params.q)
    }

    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.snapshot) {
      query.set('snapshot', params.snapshot)
    }
    if (params?.type) {
      query.set('type', params.type)
    }
    if (params?.severity) {
      query.set('severity', params.severity)
    }
    if (params?.scanner) {
      query.set('scanner', params.scanner)
    }
    if (params?.tool) {
      query.set('tool', params.tool)
    }
    if (params?.exploited !== undefined) {
      query.set('exploited', String(params.exploited))
    }
    if (params?.risk_only) {
      query.set('risk_only', 'true')
    }
    if (params?.status) {
      query.set('status', params.status)
    }
    if (params?.language) {
      query.set('language', params.language)
    }
    if (params?.file) {
      query.set('file', params.file)
    }
    if (params?.search) {
      query.set('search', params.search)
    }
    if (params?.acceptance) {
      query.set('acceptance', params.acceptance)
    }
    if (params?.sort) {
      query.set('sort', params.sort)
    }
    if (params?.page) {
      query.set('page', String(params.page))
    }
    if (params?.per_page) {
      query.set('per_page', String(params.per_page))
    }

    const qs = query.toString()
    return this.request<PaginatedResponse<Vulnerability>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities${qs ? `?${qs}` : ''}`,
    )
  }

  // Per-option result counts for each filter dimension, respecting the other
  // active filters. Pagination/sort params are intentionally omitted.
  listRefVulnerabilityFacets(
    provider: string,
    slug: string,
    repoSlug: string,
    params?: {
      ref?: string
      snapshot?: string
      type?: string
      severity?: string
      status?: string
      tool?: string
      language?: string
      file?: string
      search?: string
      acceptance?: string
      // The bar's server-side query; exclusive of the discrete params, like
      // the list it facets.
      q?: string
    },
  ) {
    const query = new URLSearchParams()
    for (const key of ['ref', 'snapshot', 'type', 'severity', 'status', 'tool', 'language', 'file', 'search', 'acceptance', 'q'] as const) {
      const value = params?.[key]
      if (value) {
        query.set(key, value)
      }
    }

    const qs = query.toString()
    return this.request<ApiResponse<VulnerabilityFacets>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities/facets${qs ? `?${qs}` : ''}`,
    )
  }

  // ADR-037: every CWE in the ref's findings, scoped by the bar's q.
  listRefCWEs(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string; q?: string }) {
    const query = new URLSearchParams()
    for (const key of ['ref', 'snapshot', 'q'] as const) {
      const value = params?.[key]
      if (value) query.set(key, value)
    }
    const qs = query.toString()
    return this.request<ApiResponse<CWEUsageReport>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/cwes${qs ? `?${qs}` : ''}`,
    )
  }

  // Replaces the CWEs declared on a manual finding (409 for scanner findings).
  setFindingCWEs(provider: string, slug: string, repoSlug: string, fingerprint: string, cwes: string[]) {
    return this.request<ApiResponse<Vulnerability>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/findings/${encodeURIComponent(fingerprint)}/cwes`,
      { method: 'PUT', body: JSON.stringify({ cwes }) },
    )
  }

  getFindingDetail(provider: string, slug: string, repoSlug: string, fingerprint: string) {
    return this.request<ApiResponse<FindingDetail>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/findings/${encodeURIComponent(fingerprint)}`,
    )
  }

  // The finding's own history. Unlike listAuditLogs (org admins only) this is
  // readable by anyone who can read the repository's findings: the server
  // restricts it to this fingerprint and to finding actions.
  getFindingHistory(provider: string, slug: string, repoSlug: string, fingerprint: string) {
    return this.request<ApiResponse<FindingHistory>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/findings/${encodeURIComponent(fingerprint)}/history`,
    )
  }

  // Deduplicated scan-rule catalog for the resolved snapshot. Fetch once and
  // join to findings locally by (tool, rule_id) instead of embedding rule text
  // in every vulnerability row.
  listRefRules(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.snapshot) {
      query.set('snapshot', params.snapshot)
    }
    const qs = query.toString()
    return this.request<ApiResponse<ScanRule[]>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities/rules${qs ? `?${qs}` : ''}`,
    )
  }

  listRefComponents(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.snapshot) {
      query.set('snapshot', params.snapshot)
    }

    const qs = query.toString()
    return this.request<ApiResponse<ComponentWithVulns[]>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/components${qs ? `?${qs}` : ''}`,
    )
  }

  // "Select all matching the current filter": returns fingerprints for the same
  // filter set the list endpoint uses, capped to the batch-triage limit.
  listRefFindingFingerprints(provider: string, slug: string, repoSlug: string, params: Record<string, string>) {
    const query = new URLSearchParams(params)
    const qs = query.toString()
    return this.request<ApiResponse<{ fingerprints: string[]; truncated: boolean; total: number }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities/fingerprints${qs ? `?${qs}` : ''}`,
    )
  }

  // Batch triage: one decision + one reason across many fingerprints. The UI
  // routes single-finding actions through here too, so there is one validated
  // path rather than two that can drift.
  batchFindingAcceptance(provider: string, slug: string, repoSlug: string, body: { fingerprints: string[]; status: string; reason_kind?: AcceptanceReasonKind; reason?: string; labels?: string[]; expires_at?: string }) {
    return this.request<ApiResponse<{ status: string; applied: number; skipped: number }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities/acceptance`,
      { method: 'PUT', body: JSON.stringify(body) },
    )
  }

  setFindingAcceptance(provider: string, slug: string, repoSlug: string, vulnID: string, body: { status: string; reason_kind?: AcceptanceReasonKind; reason?: string; labels?: string[]; vex_justification?: VexJustification; expires_at?: string }) {
    return this.request<ApiResponse<FindingAcceptance | { status: string }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities/${vulnID}/acceptance`,
      { method: 'PUT', body: JSON.stringify(body) },
    )
  }

  // ADR-026: contest an in-source suppression — the finding counts as open
  // until the directive is removed or the dispute withdrawn.
  // ADR-034 §4: decisions on manual and agent findings.
  reassertFinding(provider: string, slug: string, repoSlug: string, fingerprint: string) {
    return this.request<ApiResponse<{ fingerprint: string; assertion: FindingAssertion }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/findings/${encodeURIComponent(fingerprint)}/reassert`,
      { method: 'POST' },
    )
  }

  closeAssertion(provider: string, slug: string, repoSlug: string, fingerprint: string, action: 'resolve' | 'retract', reason: string) {
    return this.request<ApiResponse<{ fingerprint: string; assertion: FindingAssertion }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/findings/${encodeURIComponent(fingerprint)}/${action}`,
      { method: 'POST', body: JSON.stringify({ reason }) },
    )
  }

  setFindingDispute(provider: string, slug: string, repoSlug: string, vulnID: string, reason: string) {
    return this.request<ApiResponse<FindingDispute>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities/${vulnID}/dispute`,
      { method: 'PUT', body: JSON.stringify({ reason }) },
    )
  }

  deleteFindingDispute(provider: string, slug: string, repoSlug: string, vulnID: string) {
    return this.request<ApiResponse<{ status: string }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities/${vulnID}/dispute`,
      { method: 'DELETE' },
    )
  }

  // Secrets never auto-resolve (ADR-023): resolution is a human attestation
  // that the credential was revoked and rotated.
  attestSecretRevocation(provider: string, slug: string, repoSlug: string, vulnID: string, comment: string) {
    return this.request<ApiResponse<Vulnerability>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities/${vulnID}/revocation`,
      { method: 'POST', body: JSON.stringify({ comment }) },
    )
  }

  listFindingAcceptances(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<FindingAcceptance[]>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/finding-acceptances`,
    )
  }

  triggerOrgComponentScan(provider: string, slug: string) {
    return this.request<ApiResponse<{ scans: Array<{ repo: string; scan_id: string }>; failed?: string[]; providers: string[] }>>(
      `/orgs/${provider}/${slug}/components/scan`,
      { method: 'POST' },
    )
  }

  triggerSecretScan(provider: string, slug: string, repoSlug: string, params?: { ref?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    const qs = query.toString()
    return this.request<ApiResponse<{ job_id: string; ref: string; mode: string; status: string }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/secrets/scan${qs ? `?${qs}` : ''}`,
      { method: 'POST' },
    )
  }

  listSecretScanJobs(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<SecretScanJob[]>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/secrets/jobs`,
    )
  }

  /** Latest built-in dependency extraction for a ref (ADR-045). */
  getDependencyShipping(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) query.set('ref', params.ref)
    if (params?.snapshot) query.set('snapshot', params.snapshot)
    const qs = query.toString() ? `?${query.toString()}` : ''
    return this.request<ApiResponse<ShippingInfo>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/dependencies/shipping${qs}`)
  }

  addNotShippedEntries(provider: string, slug: string, repoSlug: string, entries: Array<{ pattern: string; reason: string }>) {
    return this.request<ApiResponse<NotShippedEntry[]>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/dependencies/not-shipped`, {
      method: 'POST',
      body: JSON.stringify({ entries }),
    })
  }

  deleteNotShippedEntry(provider: string, slug: string, repoSlug: string, entryID: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/repos/${repoSlug}/dependencies/not-shipped/${entryID}`, { method: 'DELETE' })
  }

  listOrgNotShipped(provider: string, slug: string) {
    return this.request<ApiResponse<NotShippedEntry[]>>(`/orgs/${provider}/${slug}/dependencies/not-shipped`)
  }

  addOrgNotShippedEntries(provider: string, slug: string, entries: Array<{ pattern: string; reason: string }>) {
    return this.request<ApiResponse<NotShippedEntry[]>>(`/orgs/${provider}/${slug}/dependencies/not-shipped`, {
      method: 'POST',
      body: JSON.stringify({ entries }),
    })
  }

  deleteOrgNotShippedEntry(provider: string, slug: string, entryID: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/dependencies/not-shipped/${entryID}`, { method: 'DELETE' })
  }

  getDependencyExtraction(provider: string, slug: string, repoSlug: string, ref?: string) {
    const qs = ref ? `?ref=${encodeURIComponent(ref)}` : ''
    return this.request<ApiResponse<DepExtractionStatus>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/dependencies/extraction${qs}`)
  }

  triggerDependencyExtraction(provider: string, slug: string, repoSlug: string, ref?: string) {
    const qs = ref ? `?ref=${encodeURIComponent(ref)}` : ''
    return this.request<ApiResponse<DepExtractionJob>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/dependencies/extract${qs}`, { method: 'POST' })
  }

  getReleaseSources(provider: string, slug: string, repoSlug: string, releaseID: string) {
    return this.request<ApiResponse<ReleaseSources>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/releases/${releaseID}/sources`)
  }

  revokeReleaseSource(provider: string, slug: string, repoSlug: string, releaseID: string, sourceID: string, reason: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/repos/${repoSlug}/releases/${releaseID}/sources/${sourceID}/revoke`, { method: 'POST', body: JSON.stringify({ reason }) })
  }

  restoreReleaseSource(provider: string, slug: string, repoSlug: string, releaseID: string, sourceID: string) {
    return this.request<void>(`/orgs/${provider}/${slug}/repos/${repoSlug}/releases/${releaseID}/sources/${sourceID}/restore`, { method: 'POST', body: JSON.stringify({}) })
  }

  extractReleaseDependencies(provider: string, slug: string, repoSlug: string, releaseID: string) {
    return this.request<ApiResponse<DepExtractionJob>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/releases/${releaseID}/extract`, { method: 'POST' })
  }

  extractAllReleases(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<{ queued: number; skipped: number }>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/releases/extract-all`, { method: 'POST' })
  }

  triggerComponentScan(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.snapshot) {
      query.set('snapshot', params.snapshot)
    }
    const qs = query.toString()
    return this.request<ApiResponse<{ scan_id: string; providers: string[] }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/components/scan${qs ? `?${qs}` : ''}`,
      { method: 'POST' },
    )
  }

  getRefSummary(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.snapshot) {
      query.set('snapshot', params.snapshot)
    }

    const qs = query.toString()
    return this.request<ApiResponse<RefSummary>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/summary${qs ? `?${qs}` : ''}`,
    )
  }

  getCoverageSource(provider: string, slug: string, repoSlug: string, snapshotID: string, path: string) {
    const query = new URLSearchParams({ path })
    return this.request<ApiResponse<CoverageSource>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/snapshots/${snapshotID}/coverage-source?${query.toString()}`,
    )
  }

  getCoverage(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string; since?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.snapshot) {
      query.set('snapshot', params.snapshot)
    }
    if (params?.since) {
      query.set('since', params.since)
    }
    const qs = query.toString()
    return this.request<ApiResponse<CoverageReport | null>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/coverage${qs ? `?${qs}` : ''}`,
    )
  }

  getComponentGraph(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.snapshot) {
      query.set('snapshot', params.snapshot)
    }
    const qs = query.toString()
    return this.request<ApiResponse<ComponentGraph>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/components/graph${qs ? `?${qs}` : ''}`,
    )
  }

  getTests(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.snapshot) {
      query.set('snapshot', params.snapshot)
    }
    const qs = query.toString()
    return this.request<ApiResponse<TestReport | null>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/tests${qs ? `?${qs}` : ''}`,
    )
  }

  getOrgDashboard(provider: string, slug: string) {
    return this.request<ApiResponse<OrgDashboard>>(`/orgs/${provider}/${slug}/dashboard`)
  }

  // ADR-037: the CWE list across the org's current snapshots.
  listOrgCWEs(provider: string, slug: string, params?: { q?: string }) {
    const qs = params?.q ? `?${new URLSearchParams({ q: params.q }).toString()}` : ''
    return this.request<ApiResponse<CWEUsageReport>>(`/orgs/${provider}/${slug}/cwes${qs}`)
  }

  // Embedded MITRE catalog: resolve titles for ids (hover, chips) or search
  // by id/title (completion). Reference data, cacheable per catalog version.
  lookupCWEs(ids: number[]) {
    return this.request<ApiResponse<CWECatalogResponse>>(`/cwe?ids=${ids.join(',')}`)
  }

  searchCWEs(q: string, limit = 20) {
    return this.request<ApiResponse<CWECatalogResponse>>(`/cwe?${new URLSearchParams({ q, limit: String(limit) }).toString()}`)
  }

  // MITRE's broad roots (pillars): where a cwe-tree: query starts.
  listCWEsByAbstraction(abstractions: string[]) {
    return this.request<ApiResponse<CWECatalogResponse>>(`/cwe?abstraction=${abstractions.join(',')}`)
  }

  listCWESets() {
    return this.request<ApiResponse<CWESetsResponse>>('/cwe/sets')
  }

  listOrgVulnerabilities(
    provider: string,
    slug: string,
    params?: {
      type?: string
      severity?: string
      status?: string
      tool?: string
      search?: string
      acceptance?: string
      q?: string
      sort?: string
      exploited?: boolean
      risk_only?: boolean
      page?: number
      per_page?: number
    },
  ) {
    const query = new URLSearchParams()
    if (params?.exploited !== undefined) {
      query.set('exploited', String(params.exploited))
    }
    if (params?.risk_only) {
      query.set('risk_only', 'true')
    }
    for (const key of ['type', 'severity', 'status', 'acceptance', 'tool', 'search', 'q', 'sort'] as const) {
      const value = params?.[key]
      if (value) {
        query.set(key, value)
      }
    }
    if (params?.page) {
      query.set('page', String(params.page))
    }
    if (params?.per_page) {
      query.set('per_page', String(params.per_page))
    }

    const qs = query.toString()
    return this.request<PaginatedResponse<OrgVulnerability>>(
      `/orgs/${provider}/${slug}/vulnerabilities${qs ? `?${qs}` : ''}`,
    )
  }

  listOrgComponents(provider: string, slug: string) {
    return this.request<ApiResponse<OrgComponent[]>>(`/orgs/${provider}/${slug}/components`)
  }

  getOrgLicenses(provider: string, slug: string) {
    return this.request<ApiResponse<OrgLicenseOverview>>(`/orgs/${provider}/${slug}/licenses`)
  }

  // Reads every repository's .hibou.yaml from the forge, one fetch per repo, so
  // this must stay behind an explicit user action rather than a page load.
  // includeRepos triggers a per-repository forge read to find overrides — one
  // request per repository — so it is opt-in and never used for a plain policy
  // read.
  getOrgLicensePolicy(provider: string, slug: string, includeRepos = false) {
    const query = includeRepos ? '?include_repos=true' : ''
    return this.request<ApiResponse<OrgLicensePolicyOverview>>(
      `/orgs/${provider}/${slug}/licenses/policy${query}`,
    )
  }

  // Returns the written policy without the repository fan-out, so a save needs
  // no follow-up read of the compliance list.
  // Previews a policy without saving it, so an admin is not adopting a legal
  // stance blind.
  simulateOrgLicensePolicy(provider: string, slug: string, body: OrgLicensePolicyInput) {
    return this.request<ApiResponse<OrgLicenseSimulation>>(
      `/orgs/${provider}/${slug}/licenses/simulate`,
      { method: 'POST', body: JSON.stringify(body) },
    )
  }

  updateOrgLicensePolicy(provider: string, slug: string, body: OrgLicensePolicyInput) {
    return this.request<ApiResponse<OrgLicensePolicyOverview>>(
      `/orgs/${provider}/${slug}/licenses/policy`,
      { method: 'PUT', body: JSON.stringify(body) },
    )
  }

  listOrgLicenseComponents(provider: string, slug: string, params?: OrgLicenseComponentQuery) {
    const query = new URLSearchParams()
    if (params?.license) query.set('license', params.license)
    if (params?.category) query.set('category', params.category)
    if (params?.repo) query.set('repo', params.repo)
    if (params?.undeclared) query.set('undeclared', 'true')
    if (params?.page) query.set('page', String(params.page))
    if (params?.per_page) query.set('per_page', String(params.per_page))
    const qs = query.toString()
    return this.request<PaginatedResponse<OrgLicenseComponent>>(
      `/orgs/${provider}/${slug}/licenses/components${qs ? `?${qs}` : ''}`,
    )
  }

  getUnreadNotificationCount() {
    return this.request<ApiResponse<{ count: number }>>('/notifications/unread-count')
  }

  listNotifications(params?: { status?: string; page?: number; per_page?: number }) {
    const query = new URLSearchParams()
    if (params?.status) {
      query.set('status', params.status)
    }
    if (params?.page) {
      query.set('page', String(params.page))
    }
    if (params?.per_page) {
      query.set('per_page', String(params.per_page))
    }

    const qs = query.toString()
    return this.request<PaginatedResponse<Notification>>(`/notifications${qs ? `?${qs}` : ''}`)
  }

  markNotificationRead(id: string) {
    return this.request<ApiResponse<Notification>>(`/notifications/${id}/read`, { method: 'POST' })
  }

  markAllNotificationsRead() {
    return this.request<ApiResponse<{ updated: number }>>('/notifications/read-all', { method: 'POST' })
  }

  getServerVersion() {
    return this.request<ApiResponse<ServerVersion>>('/version')
  }

  // Public: enabled banners only, shown on every page including login.
  getActiveBanners() {
    return this.request<ApiResponse<AnnouncementBanner[]>>('/instance/banners')
  }

  // Instance admin only: the current admin email list, resolved live from its
  // managed source (Secret-mounted file or env).
  listInstanceAdmins() {
    return this.request<ApiResponse<string[]>>('/instance/settings/admins')
  }

  // Instance admin only: audit logs across the whole instance — every org plus
  // instance-level (org-less) events. scope: 'instance' limits to the latter.
  listInstanceAuditLogs(params?: { action?: string; resource_type?: string; scope?: string; page?: number; per_page?: number }) {
    const query = new URLSearchParams()
    if (params?.action) {
      query.set('action', params.action)
    }
    if (params?.resource_type) {
      query.set('resource_type', params.resource_type)
    }
    if (params?.scope) {
      query.set('scope', params.scope)
    }
    if (params?.page) {
      query.set('page', String(params.page))
    }
    if (params?.per_page) {
      query.set('per_page', String(params.per_page))
    }
    const suffix = query.size > 0 ? `?${query.toString()}` : ''
    return this.request<PaginatedResponse<InstanceAuditLogEntry>>(`/instance/audit-logs${suffix}`)
  }

  // Instance admin only: queue counters per job kind plus the worker fleet.
  // Instance admin only: latest storage usage sample (ADR-039).
  getInstanceStorage() {
    return this.request<ApiResponse<InstanceStorage>>('/instance/storage')
  }

  getInstanceJobsOverview() {
    return this.request<ApiResponse<InstanceJobsOverview>>('/instance/jobs/overview')
  }

  // Instance admin only: job runs overlapping the window, newest first.
  getInstanceJobsTimeline(window: InstanceJobsWindow) {
    return this.request<ApiResponse<InstanceJobsTimeline>>(`/instance/jobs/timeline?window=${window}`)
  }

  // Instance admin only: bucketed throughput/latency stats plus the
  // trailing-7-day baseline used for degradation badges.
  getInstanceJobsStats(window: InstanceJobsWindow) {
    return this.request<ApiResponse<InstanceJobsStats>>(`/instance/jobs/stats?window=${window}`)
  }

  // Instance admin only: the full banner list, enabled or not.
  getBannerSettings() {
    return this.request<ApiResponse<AnnouncementBanner[]>>('/instance/settings/banners')
  }

  updateBannerSettings(banners: AnnouncementBanner[]) {
    return this.request<ApiResponse<AnnouncementBanner[]>>('/instance/settings/banners', {
      method: 'PUT',
      body: JSON.stringify(banners),
    })
  }

  // Absolute path to download the CLI binary for a platform. The browser
  // navigates here directly so the user initiates the download themselves.
  cliDownloadUrl(os: CliOS, arch: CliArch) {
    return `${API_BASE}/bin/${os}/${arch}`
  }
}

export const api = new ApiClient()

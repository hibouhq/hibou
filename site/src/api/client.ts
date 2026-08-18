const API_BASE = '/api/v1'

export interface User {
  id: string
  email: string
  display_name: string
  avatar_url?: string
  provider: string
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
export const NOTIFICATION_EVENT_TYPES = [
  'vulnerabilities.found',
  'gate.failed',
  'gate.passed',
  'scan.completed',
  'scan.failed',
  'scan.stale',
  'secret.discovered',
  'token.expiring',
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
  low: number
  info: number
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

export interface OrgSettings {
  vex_auto_propagate: boolean
  vex_reachability_analysis: boolean
  default_tlp_label: string
}

// Effective .hibou.yml configuration (or its DB-backed fallback) as the
// server resolved it for the default branch.
export interface RepoConfigGate {
  branches: string[]
  weaknesses?: { enforcement?: string; max_critical?: number | null; max_high?: number | null; max_medium?: number | null }
  vulnerabilities?: { enabled?: boolean | null; max_critical?: number | null; max_high?: number | null; max_medium?: number | null; max_new_total?: number | null }
  licenses?: { deny_categories?: string[]; deny?: string[]; allow?: string[]; deny_unknown?: boolean | null }
  secrets?: { max_new?: number | null }
  coverage?: { min_coverage?: number | null; grace?: number | null; diff_minimum?: number | null }
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

export interface Vulnerability {
  id: string
  type: string
  snapshot_id: string
  title: string
  description: string
  primary_identifier_kind?: string
  primary_identifier_value?: string
  severity: string
  original_severity?: string
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
  owasp_top_10?: string
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
  fixed_in_prs?: Array<{ fingerprint: string; ref_name: string; number?: string; title?: string }>
  solution?: string
  // Provenance (ADR-020): who produced this finding. 'scanner' is an ingested
  // tool report, 'human' a person, 'agent' an API token acting for an agent.
  origin?: FindingOrigin
  origin_api_key_id?: string
  origin_token_name?: string
  origin_owner_type?: string
  origin_owner_id?: string
  // Server-side acceptance projection (ADR-023); absent = open.
  acceptance?: FindingAcceptance
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
  repos: { mode: 'all' | 'list'; slugs?: string[] }
  permissions: Partial<Record<TokenCapability, TokenAccessLevel>>
}

export type ApiKeyApprovalStatus = 'pending' | 'approved' | 'rejected'

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
export interface FindingAdvisory {
  canonical_id: string
  title?: string
  description?: string
  severity?: string
  cvss_score?: string
  cvss_vector?: string
  cwes?: string[]
  fixed_versions?: string[]
  references?: string[]
  aliases?: string[]
}

// One entry of a finding's timeline. `scan` events are what the scanners
// observed across snapshots; `activity` events are decisions a human or a token
// recorded — the audit log, narrowed to this one finding.
export interface FindingHistoryEvent {
  source: 'scan' | 'activity'
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

export interface FindingDetail {
  finding: Vulnerability
  advisory?: FindingAdvisory
  acceptance?: FindingAcceptance
  vex?: Array<{ status: string; justification?: string; source: string; statement?: string }>
  occurrences: Array<{ ref_name: string; ref_type: string; commit_sha: string; snapshot_at: string; status: string }>
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
  cwe_ids: string[]
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
}

export interface Advisory {
  id: string
  canonical_id: string
  title: string
  severity: string
  cvss_score?: number
  is_malware: boolean
  malware_type?: string
  // Optional enriched fields — populated once the backend exposes them
  // (see TODO-BACKEND-deps-nodata.md). Rendered with graceful fallbacks.
  cwe?: string
  cwe_name?: string
  summary?: string
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

export interface RefSummary {
  vulnerabilities: SeverityCounts
  components_total: number
  coverage_line_rate?: number | null
  tests_total?: number | null
  snapshot_date?: string
  snapshot_status?: string
}

export interface DeltaResult {
  new_vulnerabilities: Vulnerability[]
  resolved_vulnerabilities: Vulnerability[]
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
  }
  coverage_diff: CoverageDiff | null
  patch_coverage?: PatchCoverage | null
  test_diff: TestDiff | null
  gate?: {
    passed: boolean
    configured: boolean
    reasons: string[]
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
  vuln_critical: number
  vuln_high: number
  vuln_medium: number
  vuln_low: number
  vuln_info: number
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
  components_total: number
  last_scanned?: string
  outdated: boolean
}

export interface OrgDashboard {
  repos: RepoDashboardEntry[]
  totals: {
    vulnerabilities: SeverityCounts
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

  logout() {
    return fetch(`${API_BASE}/auth/logout`, { method: 'POST' })
  }

  listApiKeys() {
    return this.request<ApiResponse<ApiKey[]>>('/users/me/api-keys')
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

  onboardRepo(provider: string, slug: string, repoSlug: string) {
    return this.request<ApiResponse<{ number: number; html_url: string; title: string }>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/onboard`,
      { method: 'POST' },
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
      sort?: string
      page?: number
      per_page?: number
    },
  ) {
    const query = new URLSearchParams()

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
    },
  ) {
    const query = new URLSearchParams()
    for (const key of ['ref', 'snapshot', 'type', 'severity', 'status', 'tool', 'language', 'file', 'search', 'acceptance'] as const) {
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

  listOrgVulnerabilities(
    provider: string,
    slug: string,
    params?: {
      type?: string
      severity?: string
      status?: string
      tool?: string
      search?: string
      sort?: string
      page?: number
      per_page?: number
    },
  ) {
    const query = new URLSearchParams()
    for (const key of ['type', 'severity', 'status', 'tool', 'search', 'sort'] as const) {
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

  // Absolute path to download the CLI binary for a platform. The browser
  // navigates here directly so the user initiates the download themselves.
  cliDownloadUrl(os: CliOS, arch: CliArch) {
    return `${API_BASE}/bin/${os}/${arch}`
  }
}

export const api = new ApiClient()

const API_BASE = '/api/v1'

export interface User {
  id: string
  email: string
  display_name: string
  avatar_url?: string
  provider: string
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
  published_at?: string
  created_at: string
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
  primary_identifier?: { type: string; value: string }
  severity: string
  original_severity?: string
  status: string
  dismissal_reason?: string
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
  secret_type?: string
  has_remediation?: boolean
  solution?: string
  metadata?: Record<string, unknown>
  created_at: string
  updated_at: string
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

export interface ComponentEntry {
  name: string
  version: string
  ecosystem: string
  purl: string
  vuln_count: number
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
}

export interface CoverageDiff {
  base: CoverageDiffTotals | null
  head: CoverageDiffTotals | null
  line_rate_delta: number | null
  branch_rate_delta: number | null
  files: CoverageFileDelta[]
  unchanged_files: number
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
  }
  head: {
    ref_name: string
    snapshot_id: string
    commit_sha: string
    date: string
  }
  delta: DeltaResult
  component_diff: {
    added: ComponentEntry[]
    removed: ComponentEntry[]
    unchanged: number
  }
  coverage_diff: CoverageDiff | null
  test_diff: TestDiff | null
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

export interface CoverageReport {
  line_rate: number | null
  branch_rate: number | null
  lines_valid: number
  lines_covered: number
  branches_valid: number
  branches_covered: number
  format: string
  files: CoverageFile[]
  reports?: CoverageReport[]
}

export interface CoverageFile {
  file_path: string
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

export interface PRSummary {
  ref: EnhancedRef
  pr_snapshot_id?: string
  target_snapshot_id?: string
  delta?: DeltaResult
  gate?: {
    passed: boolean
    reasons: string[]
  } | null
  summary: RefSummary
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
    return this.request<PaginatedResponse<Release>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/releases${qs ? `?${qs}` : ''}`,
    )
  }

  createRelease(
    provider: string,
    slug: string,
    repoSlug: string,
    body: {
      version: string
      ref: string
      snapshot_id?: string
      build_metadata?: Record<string, unknown>
      artifact_ids?: unknown[]
      provenance?: Record<string, unknown>
      published_at?: string
    },
  ) {
    return this.request<ApiResponse<Release>>(`/orgs/${provider}/${slug}/repos/${repoSlug}/releases`, {
      method: 'POST',
      body: JSON.stringify(body),
    })
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
    params?: { action?: string; resource_type?: string; page?: number; per_page?: number },
  ) {
    const query = new URLSearchParams()

    if (params?.action) {
      query.set('action', params.action)
    }
    if (params?.resource_type) {
      query.set('resource_type', params.resource_type)
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

  getPRSummary(provider: string, slug: string, repoSlug: string, number: string | number) {
    return this.request<ApiResponse<PRSummary>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/pr/${number}`,
    )
  }

  compareRefs(
    provider: string,
    slug: string,
    repoSlug: string,
    base: string,
    head: string,
  ) {
    const query = new URLSearchParams({ base, head })

    return this.request<ApiResponse<CompareResult>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/compare?${query.toString()}`,
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
    return this.request<TrendPoint[]>(
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
    },
  ) {
    const query = new URLSearchParams()
    for (const key of ['ref', 'snapshot', 'type', 'severity', 'status', 'tool', 'language', 'file', 'search'] as const) {
      const value = params?.[key]
      if (value) {
        query.set(key, value)
      }
    }

    const qs = query.toString()
    return this.request<VulnerabilityFacets>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/vulnerabilities/facets${qs ? `?${qs}` : ''}`,
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

  getCoverage(provider: string, slug: string, repoSlug: string, params?: { ref?: string; snapshot?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.snapshot) {
      query.set('snapshot', params.snapshot)
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

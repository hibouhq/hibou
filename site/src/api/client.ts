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
}

export interface Team {
  id: string
  name: string
  slug: string
  org_id: string
}

export interface Repository {
  id: string
  name: string
  slug: string
  org_id: string
  provider: string
  provider_id?: string
  default_branch: string
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
  type: 'vulnerability' | 'component' | 'finding' | 'client'
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

export interface EnhancedRef {
  id: string
  repo_id: string
  name: string
  ref_type: string
  provider_id?: string
  merge_target_ref_id?: string
  merge_target_ref_name?: string
  pr_state?: string
  pr_title?: string
  pr_source_branch?: string
  pr_merged_at?: string
  pr_closed_at?: string
  latest_commit_sha?: string
  latest_snapshot_id?: string
  latest_snapshot_status?: string
  latest_snapshot_date?: string
}

export interface Snapshot {
  id: string
  ref_id: string
  commit_sha: string
  label?: string
  status: string
  created_at: string
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface Finding {
  id: string
  snapshot_id: string
  tool: string
  rule_id: string
  severity: string
  status: string
  file_path: string
  start_line?: number
  end_line?: number
  message: string
  metadata?: Record<string, unknown>
  created_at: string
}

export interface Advisory {
  id: string
  canonical_id: string
  title: string
  severity: string
  cvss_score?: number
  is_malware: boolean
  malware_type?: string
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
}

export interface ComponentEntry {
  name: string
  version: string
  ecosystem: string
  purl: string
  vuln_count: number
}

export interface RefSummary {
  findings: SeverityCounts
  vulns: SeverityCounts
  components_total: number
  snapshot_date?: string
  snapshot_status?: string
}

export interface DeltaVuln {
  advisory_id: string
  canonical_id: string
  severity: string
  component_name: string
}

export interface DeltaFinding {
  fingerprint: string
  tool: string
  rule_id: string
  severity: string
  file_path: string
  message: string
}

export interface DeltaResult {
  new_vulns: DeltaVuln[]
  resolved_vulns: DeltaVuln[]
  unchanged_vulns: number
  new_findings: DeltaFinding[]
  resolved_findings: DeltaFinding[]
  unchanged_findings: number
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
}

export interface TrendPoint {
  snapshot_id: string
  date: string
  commit_sha: string
  findings_critical: number
  findings_high: number
  findings_medium: number
  findings_low: number
  findings_info: number
  vulns_critical: number
  vulns_high: number
  vulns_medium: number
  vulns_low: number
  vulns_info: number
  components_total: number
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
  repo_id: string
  repo_name: string
  repo_slug: string
  provider: string
  findings: SeverityCounts
  vulns: SeverityCounts
  components_total: number
  last_scan?: string
}

export interface OrgDashboard {
  repos: RepoDashboardEntry[]
  totals: {
    findings: SeverityCounts
    vulns: SeverityCounts
    components_total: number
  }
}

export function forgeCommitUrl(forgeUrl: string | undefined, providerID: string | undefined, sha: string): string | null {
  if (!forgeUrl || !providerID) return null
  return `${forgeUrl}/${providerID}/commit/${sha}`
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

  getOrg(provider: string, slug: string) {
    return this.request<ApiResponse<Organization>>(`/orgs/${provider}/${slug}`)
  }

  listTeams(provider: string, slug: string) {
    return this.request<PaginatedResponse<Team>>(`/orgs/${provider}/${slug}/teams`)
  }

  listRepos(provider: string, slug: string) {
    return this.request<PaginatedResponse<Repository>>(`/orgs/${provider}/${slug}/repos`)
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

    return this.request<CompareResult>(
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

  listRefFindings(
    provider: string,
    slug: string,
    repoSlug: string,
    params?: { ref?: string; severity?: string; tool?: string; status?: string; page?: number; per_page?: number },
  ) {
    const query = new URLSearchParams()

    if (params?.ref) {
      query.set('ref', params.ref)
    }
    if (params?.severity) {
      query.set('severity', params.severity)
    }
    if (params?.tool) {
      query.set('tool', params.tool)
    }
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
    return this.request<PaginatedResponse<Finding>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/findings${qs ? `?${qs}` : ''}`,
    )
  }

  listRefComponents(provider: string, slug: string, repoSlug: string, params?: { ref?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }

    const qs = query.toString()
    return this.request<ApiResponse<ComponentWithVulns[]>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/components${qs ? `?${qs}` : ''}`,
    )
  }

  getRefSummary(provider: string, slug: string, repoSlug: string, params?: { ref?: string }) {
    const query = new URLSearchParams()
    if (params?.ref) {
      query.set('ref', params.ref)
    }

    const qs = query.toString()
    return this.request<ApiResponse<RefSummary>>(
      `/orgs/${provider}/${slug}/repos/${repoSlug}/summary${qs ? `?${qs}` : ''}`,
    )
  }

  getOrgDashboard(provider: string, slug: string) {
    return this.request<ApiResponse<OrgDashboard>>(`/orgs/${provider}/${slug}/dashboard`)
  }

  getUnreadNotificationCount() {
    return this.request<ApiResponse<{ count: number }>>('/notifications/unread-count')
  }
}

export const api = new ApiClient()

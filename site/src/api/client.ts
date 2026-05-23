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
  default_branch: string
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

  getOrg(slug: string) {
    return this.request<ApiResponse<Organization>>(`/orgs/${slug}`)
  }

  listTeams(orgSlug: string) {
    return this.request<PaginatedResponse<Team>>(`/orgs/${orgSlug}/teams`)
  }

  listRepos(orgSlug: string) {
    return this.request<PaginatedResponse<Repository>>(`/orgs/${orgSlug}/repos`)
  }

  getRepo(orgSlug: string, repoSlug: string) {
    return this.request<ApiResponse<Repository>>(`/orgs/${orgSlug}/repos/${repoSlug}`)
  }
}

export const api = new ApiClient()
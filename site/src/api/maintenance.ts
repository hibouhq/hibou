import { apiRequest } from './client'

export interface MaintenanceMapping {
  id: string
  tag_pattern: string
  target_template: string
}
export interface MaintenanceSettings {
  allow_creation: boolean
  mappings: MaintenanceMapping[]
}
export interface MaintenanceSettingsResponse {
  settings: MaintenanceSettings
  can_configure: boolean
  branch_pr_consent: boolean
  creation_available?: boolean
  creation_reason?: string
}
export interface MaintenanceSource {
  release_id: string
  release_version: string
  tag: string
  sha: string
}
export interface MaintenanceSuggestion {
  mapping: MaintenanceMapping
  target_branch?: string
  can_create: boolean
  reason?: string
  evidence?: {
    source_tag: string
    source_sha: string
    tag_sha: string
    tag_confirmed: boolean
    target_branch: string
    exists: boolean
    head_sha?: string
    source_ancestor: boolean
  }
}
export interface MaintenanceSuggestions {
  source: MaintenanceSource
  suggestions: MaintenanceSuggestion[]
  reason: string
  creation_reason: string
}
export interface MaintenanceCreated {
  target_branch: string
  source_tag: string
  source_sha: string
  created: boolean
  reconciled: boolean
}
async function request<T>(path: string, options?: RequestInit): Promise<T> {
  return (await apiRequest<{ data: T }>(path, options)).data
}
export const maintenanceApi = {
  settings: (base: string) => request<MaintenanceSettingsResponse>(`${base}/maintenance-settings`),
  save: (base: string, settings: MaintenanceSettings) => request<MaintenanceSettingsResponse>(`${base}/maintenance-settings`, { method: 'PUT', body: JSON.stringify(settings) }),
  suggestions: (base: string, release: string) => request<MaintenanceSuggestions>(`${base}/maintenance-targets?release_id=${encodeURIComponent(release)}`),
  create: (base: string, source: MaintenanceSource, suggestion: MaintenanceSuggestion) =>
    request<MaintenanceCreated>(`${base}/maintenance-targets`, {
      method: 'POST',
      body: JSON.stringify({
        release_id: source.release_id, mapping_id: suggestion.mapping.id,
        target_branch: suggestion.target_branch, source_tag: source.tag, source_sha: source.sha,
      }),
    }),
}

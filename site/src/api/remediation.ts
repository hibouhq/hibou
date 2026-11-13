import { apiRequest } from './client'

export interface VersionTarget {
  name: string
  mode: 'exact' | 'gossip'
  version: string
  allow_prerelease?: boolean
}
export interface RemediationUnit {
  id: string
  manager: string
  manifest: string
  lockfile: string
  vulns: string[]
  upgrade_level: 'patch' | 'minor' | 'major'
  direct_packages?: { name: string; version: string; recommended_version?: string }[]
}
export interface RemediationModule {
  manifest: string
  unit?: RemediationUnit
  unavailable?: string
}
export interface RemediationJob {
  id: string
  base_sha: string
  source_ref: string
  target_branch: string
  revision: number
  state: 'queued_prepare' | 'preparing' | 'awaiting_selection' | 'queued_generate' | 'generating' | 'ready' | 'failed' | 'cancelled' | 'expired'
  expires_at: string
  error?: string
  result: {
    unavailable?: string
    modules?: RemediationModule[]
    artifact?: {
      sha256: string
      changes: { path: string; before_sha256: string; after_sha256: string }[]
      units: { id: string; updates: { name: string; from: string; to: string }[] }[]
      verification: { dependency_files_consistent: boolean; selected_vulns_addressed: boolean; no_introduced_vulns: boolean }[]
    }
  }
}
export interface RemediationCapabilities {
  available: boolean
  reason: string
  profile: string
  can_generate: boolean
  generation_reason: string
  can_consent: boolean
  publication_available: boolean
  publication_reason: string
  maintenance_creation_reason: string
  limits: string[]
}
export interface RemediationSelection {
  id: string
  upgrade_level: string
  version_targets: VersionTarget[]
}
export function remediationPath(provider: string, org: string, repo: string): string {
  return `/orgs/${encodeURIComponent(provider)}/${encodeURIComponent(org)}/repos/${encodeURIComponent(repo)}/remediation`
}
export function isRemediationPending(state: RemediationJob['state']): boolean {
  return ['queued_prepare', 'preparing', 'queued_generate', 'generating'].includes(state)
}
export function isRemediationVerified(job: RemediationJob): boolean {
  const artifact = job.result.artifact
  return job.state === 'ready' && !!artifact && artifact.changes.length > 0 &&
    artifact.verification.length > 0 && artifact.verification.length === artifact.units.length &&
    artifact.verification.every(v => v.dependency_files_consistent && v.selected_vulns_addressed && v.no_introduced_vulns)
}
async function remediationRequest<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await apiRequest<{ data: T }>(path, options)
  return response.data
}
export const remediationApi = {
  capabilities: (base: string) => remediationRequest<RemediationCapabilities>(`${base}/capabilities`),
  prepare: (base: string, input: { release_id?: string; target_branch?: string; maintenance_target: boolean; expected_head_sha?: string }) =>
    remediationRequest<RemediationJob>(`${base}/prepare`, { method: 'POST', body: JSON.stringify(input) }),
  get: (base: string, id: string) => remediationRequest<RemediationJob>(`${base}/${encodeURIComponent(id)}`),
  generate: (base: string, job: RemediationJob, units: RemediationSelection[]) =>
    remediationRequest<RemediationJob>(`${base}/${job.id}/generate`, { method: 'POST', body: JSON.stringify({ revision: job.revision, units }) }),
  cancel: (base: string, id: string) =>
    remediationRequest<{ state: string }>(`${base}/${id}/cancel`, { method: 'POST', body: '{}' }),
  publish: (base: string, job: RemediationJob) =>
    remediationRequest<{ number: number; html_url: string }>(`${base}/${job.id}/publish`, { method: 'POST', body: JSON.stringify({ revision: job.revision }) }),
  consent: (base: string, enabled: boolean) =>
    remediationRequest<{ enabled: boolean }>(`${base}/consent`, { method: 'PUT', body: JSON.stringify({ enabled }) }),
}

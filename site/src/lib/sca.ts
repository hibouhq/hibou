import { ApiError, type RepoLifecycleStatus, type ScaCoverage, type ScaEnableResult } from '@/api/client'

export const MAX_SCA_SELECTION = 50

export function scaState(sca?: ScaCoverage): ScaCoverage['state'] | 'unknown' {
  return sca?.state ?? 'unknown'
}

export function scaPending(sca?: ScaCoverage): boolean {
  return !!sca && ['queued', 'extracting', 'matching'].includes(sca.state)
}

export function scaAssessed(sca?: ScaCoverage): boolean {
  return sca?.state === 'complete' || sca?.state === 'partial'
}

export function hasInventory(sca?: ScaCoverage, components = 0): boolean {
  return sca?.has_inventory === true || sca?.previous_results === true || components > 0
    || ['complete', 'partial', 'inventory_ready'].includes(sca?.state ?? '')
}

export function hasReportedFindings(sca?: ScaCoverage, findings = 0): boolean {
  return sca?.state === 'reported' || findings > 0
}

export function inventoryKnownCount(count: number, sca?: ScaCoverage): number | 'Not reported' {
  return count > 0 || hasInventory(sca, count) ? count : 'Not reported'
}

function inventorySources(sca?: ScaCoverage): NonNullable<ScaCoverage['inventory_sources']> {
  const order: NonNullable<ScaCoverage['inventory_sources']> = ['repository', 'cli', 'sbom', 'unknown']
  return order.filter(source => sca?.inventory_sources?.includes(source))
}

export function inventorySource(sca?: ScaCoverage, components = 0): string {
  const labels = {
    repository: 'Repository files',
    cli: 'Hibou CLI',
    sbom: 'SBOM',
    mixed: 'Mixed sources',
    unknown: 'Source unknown',
    none: 'No inventory',
  }
  const sources = inventorySources(sca)
  if (sources.length) return sources.map(source => labels[source]).join(' + ')
  const source = sca?.inventory_source
  if (!sca) return labels.unknown
  if (!source || (source === 'none' && hasInventory(sca, components))) {
    return hasInventory(sca, components) ? labels.unknown : labels.none
  }
  return labels[source] ?? labels.unknown
}

export function inventorySourceTitle(sca?: ScaCoverage, components = 0): string {
  if (!sca) return 'This server does not supply inventory metadata. Existing counts are retained; provenance, freshness and analysis capability are unknown.'
  const descriptions = {
    repository: 'Supported dependency files read from repository content; not a guarantee of build-complete or shipped inventory.',
    cli: 'Inventory reported by the Hibou dependency producer (hibou-deps); technique and build completeness depend on its evidence.',
    sbom: 'Inventory supplied in an SBOM; upload origin alone does not establish technique, completeness or shipped scope.',
    mixed: 'Inventory combines multiple sources; completeness depends on the underlying evidence.',
    unknown: 'Inventory is available, but its source is not recorded. No SBOM or extraction technique is assumed.',
    none: 'No dependency inventory is recorded.',
  }
  const sources = inventorySources(sca)
  if (sources.length) return [
    ...sources.map(source => descriptions[source]),
    'These sources describe the same inventory evidence snapshot; their combination does not establish completeness.',
  ].join('\n')
  const source = sca?.inventory_source
  const key = !source || (source === 'none' && hasInventory(sca, components))
    ? hasInventory(sca, components) ? 'unknown' : 'none'
    : source
  return descriptions[key] ?? descriptions.unknown
}

export function scaKnownCount(count: number, sca?: ScaCoverage, reportedFindings = 0): number | 'Not assessed' | 'Not reported' {
  return count > 0 || reportedFindings > 0 || scaAssessed(sca) ? count : sca ? 'Not assessed' : 'Not reported'
}

export function scaLabel(sca?: ScaCoverage, enrolled = true, components = 0, findings = 0): string {
  if (!sca || sca.state === 'not_assessed' || sca.state === 'not_monitored') {
    if (hasInventory(sca, components)) return 'Inventory available'
    if (hasReportedFindings(sca, findings)) return 'Findings reported'
  }
  if (!sca) return 'Status unavailable'
  if (sca.state === 'complete' && sca.has_inventory === true && components === 0 && findings === 0) return 'No dependencies found'
  if (!enrolled && sca.state === 'not_assessed') return 'Not monitored'
  const labels: Record<ScaCoverage['state'], string> = {
    not_monitored: 'Not monitored',
    not_assessed: 'Not assessed',
    queued: 'Queued',
    extracting: 'Extracting',
    matching: 'Matching advisories',
    complete: 'Advisories checked',
    partial: 'Partial analysis',
    reported: 'Findings reported',
    inventory_ready: 'Ready to scan',
    outdated: 'Update available',
    unsupported: 'No supported dependency files',
    failed: 'Analysis failed',
    disabled: 'Disabled — contact the server operator',
  }
  return labels[sca.state] ?? 'Status unavailable'
}

export function scaAction(enrolled: boolean, sca?: ScaCoverage, components = 0, findings = 0): string | null {
  if (!enrolled) {
    return sca?.enabled === true && ['not_monitored', 'not_assessed'].includes(sca.state) ? 'Enable SCA' : null
  }
  if (!needsDependencyExtraction(sca, components, findings)) return null
  if (sca?.state === 'outdated') return 'Update inventory'
  return sca?.state === 'failed' ? 'Retry' : 'Extract dependencies'
}

export function needsDependencyExtraction(sca?: ScaCoverage, components = 0, findings = 0): boolean {
  if (sca?.enabled !== true || sca.has_inventory !== false) return false
  if (sca.state === 'outdated') return true
  if (sca.state === 'failed' && sca.previous_results === true) return true
  return !hasInventory(sca, components) && !hasReportedFindings(sca, findings)
    && ['not_monitored', 'not_assessed', 'failed'].includes(sca.state)
}

export function canEnableSca(status?: RepoLifecycleStatus, sca?: ScaCoverage): boolean {
  return status !== 'archived' && status !== 'deleted' && sca?.enabled === true && sca.state !== 'disabled' && !scaPending(sca)
}

export function scaErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : 'Could not request dependency analysis'
  if (error instanceof ApiError ? error.status === 404 && !error.structured : /^HTTP\s*404$/i.test(message)) {
    return 'Dependency analysis endpoint unavailable. Refresh the page; if this continues, ask the operator to update the server and UI to matching versions.'
  }
  return /disabled|not enabled/i.test(message)
    ? `${message}. Ask the server operator to enable dependency inventory.`
    : message
}

export function scaSelectionValid(ids: string[]): boolean {
  return ids.length > 0 && ids.length <= MAX_SCA_SELECTION && new Set(ids).size === ids.length && ids.every(Boolean)
}

export function scaResultCoverage(result: ScaEnableResult, previous?: ScaCoverage): ScaCoverage | undefined {
  if (result.status === 'failed') return previous
  if (!result.job_id) return previous
  return { ...previous, integration: previous?.integration === 'ci_integrated' ? 'ci_integrated' : 'monitored', enabled: true, on_push: previous?.on_push ?? false, state: 'queued', job_id: result.job_id }
}

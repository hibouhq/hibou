import type { OfflineBundleStatus, ProducerCoverage } from '@/api/client'

// Display helpers for the scan coverage panel (ADR-034 §2).

export function shortSha(sha?: string) {
  return sha ? sha.slice(0, 7) : '—'
}

export function dotClass(producer: ProducerCoverage) {
  if (producer.status === 'missing' || producer.outcome === 'partial') {
    return 'bg-warning'
  }
  if (producer.outcome === 'failed') {
    return 'bg-danger'
  }
  if (producer.status === 'pending') {
    return 'bg-gray-500'
  }
  return 'bg-emerald-400'
}

export function stateLabel(producer: ProducerCoverage) {
  switch (producer.status) {
    case 'missing':
      return 'Missing'
    case 'pending':
      return 'Running'
  }
  const outcome = producer.outcome === 'completed' ? 'Ran' : producer.outcome === 'partial' ? 'Partial' : 'Failed'
  return producer.status === 'new' ? `${outcome} · new` : outcome
}

export function detailLine(producer: ProducerCoverage) {
  const parts: string[] = []
  if (producer.version) {
    parts.push(producer.previous_version && producer.previous_version !== producer.version
      ? `${producer.previous_version} → ${producer.version}`
      : producer.version)
  }
  if (producer.scope === 'partial') {
    parts.push(producer.scope_paths.length > 0 ? `partial (${producer.scope_paths.length} paths)` : 'partial')
  } else if (producer.scope === 'full') {
    // An undeclared scope is hibou's assumption, not evidence (ADR-034 §2).
    parts.push(producer.scope_declared ? 'full' : 'full (assumed)')
  }
  parts.push(`${producer.finding_count} ${producer.finding_count === 1 ? 'result' : 'results'}`)
  return parts.join(' · ')
}

export function reasonLabel(reason: string) {
  switch (reason) {
    case 'timeout':
      return 'timed out'
    case 'too_large':
      return 'too large'
    case 'parse_error':
      return 'parse error'
    case 'resource_limit':
      return 'out of resources'
    default:
      return 'skipped'
  }
}

// Org scanner coverage states (ADR-035 §6).
const COVERAGE_STATE_LABELS: Record<string, string> = {
  covered: 'Covered',
  pending: 'Pending',
  missing: 'Never ran',
  missing_setup: 'Setup missing',
  disabled: 'Disabled',
  prerequisite_blocked: 'Prerequisite blocked',
  failed: 'Failed',
  partial: 'Partial',
  stale: 'Stale',
  unsupported: 'Unsupported',
  exempt: 'Exempt',
  not_applicable: 'Not applicable',
  unknown: 'Unknown',
  unverified: 'Unverified',
}

export function coverageStateLabel(state: string) {
  return COVERAGE_STATE_LABELS[state] ?? state
}

export function coverageStateClass(state: string) {
  switch (state) {
    case 'covered':
      return 'bg-emerald-500/15 text-emerald-300'
    case 'pending':
    case 'exempt':
    case 'disabled':
    case 'not_applicable':
      return 'bg-surface-overlay text-gray-400'
    case 'failed':
    case 'missing':
      return 'bg-danger/15 text-danger'
    default:
      return 'bg-amber-500/15 text-amber-300'
  }
}

export interface BundleFreshness {
  ageDays: number | null
  /** Strictest freshness_days among the org's requirements; 0 = no policy. */
  maxDays: number
  stale: boolean
  problems: string[]
}

// The offline bundle judged against the org's freshness policy (ADR-035
// "Offline distribution"): its age against the strictest requirement, and
// whether it was exported for the catalog the server pins.
export function bundleFreshness(bundle: OfflineBundleStatus, freshnessDays: number[], now = Date.now()): BundleFreshness {
  const policies = freshnessDays.filter(days => days > 0)
  const maxDays = policies.length ? Math.min(...policies) : 0
  const problems: string[] = []
  if (bundle.error) problems.push(bundle.error)
  let ageDays: number | null = null
  if (bundle.created_at) {
    ageDays = Math.floor((now - new Date(bundle.created_at).getTime()) / 86_400_000)
    if (maxDays && ageDays > maxDays) problems.push(`older than the ${maxDays}-day freshness the strictest requirement allows`)
  }
  if (!bundle.error && !bundle.matches_catalog) problems.push('exported for another catalog revision: re-export it with this hibou version')
  return { ageDays, maxDays, stale: problems.length > 0, problems }
}

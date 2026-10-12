import type { Vulnerability } from '@/api/client'

// Wording for finding presence (ADR-034 §3). Mirrors presence.ReasonText in
// internal/presence so the PR comment and the UI say the same thing.

export function presenceReasonText(reason?: string): string {
  if (!reason) {
    return 'not re-checked since an earlier build'
  }
  if (reason.startsWith('file_skipped:')) {
    return `the scanner skipped the file (${reason.slice('file_skipped:'.length).replace(/_/g, ' ')})`
  }
  switch (reason) {
    case 'producer_missing':
      return 'the scanner did not run'
    case 'producer_failed':
      return 'the scanner failed'
    case 'producer_pending':
      return 'the scanner had not finished'
    case 'outside_scope':
      return 'the scan covered only part of the code, not this file'
    case 'partial_scope':
      return 'a partial scan did not say what it covered'
    case 'partial_run':
      return 'the scanner reported errors that may have skipped it'
    case 'unchanged':
      return 'it disappeared, but the file did not change'
    case 'unchanged_trace':
      return 'it disappeared, but no file of its data flow changed'
    case 'absent':
      return 'it has not been absent for enough scans to resolve it'
    case 'explicit_policy':
      return "this scanner's findings are only resolved by a decision"
    case 'assertion':
      return 'filed by a person or an agent; only an explicit decision resolves it'
    case 'location_gone':
      return 'filed by a person or an agent; its file is gone, needs review'
    default:
      return reason
  }
}

/** Wording of a recorded resolution reason (ADR-034 §3). */
export function resolutionReasonText(reason?: string, producer?: string, version?: string): string {
  const scanner = producer ? `${producer}${version ? ` ${version}` : ''}` : 'the scanner'
  switch (reason) {
    case 'fixed':
      return `${scanner} re-checked the changed code and no longer reports it`
    case 'file_removed':
      return 'the file was deleted or renamed away'
    case 'producer_changed':
      return `no longer reported by ${scanner} (scanner or rules changed, not a code fix)`
    case 'no_longer_reported':
      return `no longer reported by ${scanner} after repeated absence without a code change`
    case 'producer_retired':
      return `${scanner} was retired from CI by an org admin (a decision, not a code fix)`
    default:
      return ''
  }
}

/** A delta resolution a PR can claim as a fix. */
export function isClaimableFix(finding: Pick<Vulnerability, 'resolution_reason'>): boolean {
  return !finding.resolution_reason || finding.resolution_reason === 'fixed' || finding.resolution_reason === 'file_removed'
}

export function isCarried(finding: Pick<Vulnerability, 'presence'>): boolean {
  return !!finding.presence && finding.presence !== 'reported'
}

/** Carried, and worth a badge: a manual or agent finding is always carried
 * (nothing re-checks it), so only a gone location is news there. */
export function showsPresenceBadge(finding: Pick<Vulnerability, 'presence' | 'presence_reason'>): boolean {
  return isCarried(finding) && finding.presence_reason !== 'assertion'
}

/** Tooltip of the presence badge: what happened and since when. */
export function presenceTitle(finding: Pick<Vulnerability, 'presence' | 'presence_reason' | 'last_seen_commit'>): string {
  const since = finding.last_seen_commit ? ` since ${finding.last_seen_commit.slice(0, 7)}` : ''
  if (finding.presence === 'unconfirmed') {
    return `Unconfirmed${since}: ${presenceReasonText(finding.presence_reason)}. Still counted as open.`
  }
  return `Not re-checked${since}: ${presenceReasonText(finding.presence_reason)}. Still counted as open.`
}

// Pure helpers behind the incident views (ADR-053): action grouping, filing
// steps, the clocks table, timeline detail and rule list editing.

import type { IncidentAction, IncidentDeadline, IncidentRule, IncidentState, Regime } from '@/api/incidents'

export const BUILTIN_REGIMES = ['cra-article-14', 'nis2-article-23', 'internal'] as const

/** Whether a regime carries external obligations (anything but `internal`). */
export function isExternalRegime(regime: string): boolean {
  return regime !== '' && regime !== 'internal'
}

/** Current actions split by whether they block closure; obsolete ones are hidden. */
export function groupActions(actions: IncidentAction[]): { required: IncidentAction[]; optional: IncidentAction[] } {
  const current = actions.filter(action => !action.obsolete)
  return {
    required: current.filter(action => !action.optional),
    optional: current.filter(action => action.optional),
  }
}

/**
 * The regime step a filing action kind records, for the filing draft:
 * srp_early_warning → early_warning. National filings are named
 * national_<code>_<step>, and a code may hold underscores, so the regimes
 * served with the incident are asked first.
 */
export function filingStep(kind: string, regimes: Regime[] = []): string {
  for (const regime of regimes) {
    const step = regime.steps.find(entry => entry.filing === kind)
    if (step) return step.step
  }
  for (const prefix of ['srp_', 'csirt_']) {
    if (kind.startsWith(prefix)) return kind.slice(prefix.length)
  }
  if (kind.startsWith('national_')) {
    const rest = kind.slice('national_'.length)
    const cut = rest.indexOf('_')
    return cut >= 0 ? rest.slice(cut + 1) : rest
  }
  return kind
}

/** Where a filing is made: the regime step's portal, when it has one. */
export function filingPortal(kind: string, regimes: Regime[] = []): { url: string; recipient: string } | null {
  for (const regime of regimes) {
    const step = regime.steps.find(entry => entry.filing === kind)
    if (step?.url) return { url: step.url, recipient: step.recipient || regime.label }
  }
  return null
}

export interface ClockRow {
  step: string
  regulatory: IncidentDeadline[]
  internal: IncidentDeadline | null
}

/** One row per step: the regulatory deadlines next to the internal target of the same step. */
export function clockRows(deadlines: IncidentDeadline[]): ClockRow[] {
  const rows: ClockRow[] = []
  const byStep = new Map<string, ClockRow>()
  const row = (step: string) => {
    let entry = byStep.get(step)
    if (!entry) {
      entry = { step, regulatory: [], internal: null }
      byStep.set(step, entry)
      rows.push(entry)
    }
    return entry
  }
  const sorted = [...deadlines].sort((a, b) => a.due_at.localeCompare(b.due_at))
  for (const deadline of sorted) {
    if (deadline.regime === 'internal') {
      row(deadline.step).internal = deadline
    } else {
      row(deadline.step).regulatory.push(deadline)
    }
  }
  return rows
}

/**
 * A regime step duration as the regulation words it: "24h" → "24 h",
 * "336h" → "14 days", "1mo" → "1 month". Hours up to 72 stay in hours, the
 * unit the texts use; longer windows read as days.
 */
export function windowLabel(after: string): string {
  if (after === '1mo') return '1 month'
  const match = /^(\d+)h$/.exec(after)
  if (!match) return after
  const hours = Number(match[1])
  if (hours <= 72 || hours % 24 !== 0) return `${hours} h`
  const days = hours / 24
  return `${days} day${days === 1 ? '' : 's'}`
}

/** Time elapsed since `start`, capped at `end`: "22h 58m", "3d 2h", "40m". */
export function elapsedText(start: string, end: string, now = Date.now()): string {
  const from = new Date(start).getTime()
  const to = Math.min(now, new Date(end).getTime())
  let minutes = Math.max(0, Math.floor((to - from) / 60000))
  const days = Math.floor(minutes / 1440)
  minutes -= days * 1440
  const hours = Math.floor(minutes / 60)
  minutes -= hours * 60
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${String(minutes).padStart(2, '0')}m`
  return `${minutes}m`
}

/** "early_warning" → "Early warning"; "deadline.due_soon" → "Deadline due soon". */
export function humanize(value: string): string {
  const text = value.replace(/[_.-]+/g, ' ').trim()
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : ''
}

const LEADING_DETAIL_KEYS = ['text', 'reason', 'label', 'status', 'reference']

/** Detail entries of a timeline event, the readable keys first, values flattened to text. */
export function detailEntries(detail: Record<string, unknown> | null | undefined): [string, string][] {
  if (!detail) return []
  const keys = Object.keys(detail).filter(key => {
    const value = detail[key]
    return value !== null && value !== undefined && value !== ''
  })
  const lead = LEADING_DETAIL_KEYS.filter(key => keys.includes(key))
  const rest = keys.filter(key => !LEADING_DETAIL_KEYS.includes(key)).sort()
  return [...lead, ...rest].map(key => [key, displayValue(detail[key])])
}

function displayValue(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value) && value.every(item => typeof item === 'string' || typeof item === 'number')) return value.join(', ')
  // Document lists read as their kinds and short digests; the full digests
  // are on the delivery.
  if (Array.isArray(value) && value.every(item => item && typeof item === 'object' && 'sha256' in item)) {
    return value.map(item => `${String((item as { kind?: unknown }).kind ?? 'document')} ${String((item as { sha256: unknown }).sha256).slice(0, 12)}`).join(', ')
  }
  return JSON.stringify(value)
}

/** Evidence entries of an action, waiver bookkeeping left out (it renders on its own). */
export function evidenceEntries(evidence: Record<string, unknown> | null | undefined): [string, string][] {
  if (!evidence) return []
  return detailEntries(Object.fromEntries(Object.entries(evidence).filter(([key]) => !key.startsWith('waiver_'))))
}

/** A pending waiver proposal recorded on the action's evidence, under four-eyes. */
export function waiverProposal(action: IncidentAction): { by: string; reason: string } | null {
  const evidence = action.evidence ?? {}
  const by = evidence.waiver_proposed_by
  if (action.state !== 'pending' || typeof by !== 'string' || by === '') return null
  return { by, reason: typeof evidence.waiver_reason === 'string' ? evidence.waiver_reason : '' }
}

/** Client ids owed a notice: pending, current client_notice actions. */
export function pendingNoticeClientIds(actions: IncidentAction[]): string[] {
  const ids = actions
    .filter(action => action.kind === 'client_notice' && action.state === 'pending' && !action.obsolete && action.subject_id)
    .map(action => action.subject_id)
  return [...new Set(ids)]
}

/** Whether a decision returned by the API was only proposed (four-eyes): the state did not move. */
export function decisionWasProposed(before: IncidentState, after: { state: IncidentState; proposed_decision: { state?: string } | null }): boolean {
  return after.state === before && !!after.proposed_decision?.state
}

/** "a, b , c" → ["a", "b", "c"]. */
export function splitList(text: string): string[] {
  return text.split(',').map(part => part.trim()).filter(Boolean)
}

/** A rule as sent to the API: empty optional fields dropped, source/locked are server-side. */
export function cleanRule(rule: IncidentRule): IncidentRule {
  const out: IncidentRule = { match: rule.match.trim() }
  if (rule.kind) out.kind = rule.kind
  if (rule.refs && rule.refs.length > 0) out.refs = rule.refs
  if (rule.regimes && rule.regimes.length > 0) out.regimes = rule.regimes
  if (rule.priority) out.priority = rule.priority
  if (rule.due && rule.due.trim()) out.due = rule.due.trim()
  return out
}

/** ISO time → value of an <input type="datetime-local"> in local time. */
export function toLocalInput(iso: string | Date): string {
  const date = typeof iso === 'string' ? new Date(iso) : iso
  if (Number.isNaN(date.getTime())) return ''
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

/** <input type="datetime-local"> value → ISO time, undefined when empty or invalid. */
export function fromLocalInput(value: string): string | undefined {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}

export function errorText(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback
}

export type PillTone = 'danger' | 'warn' | 'ok' | 'info' | 'muted'

const STATUS_TONES: Record<string, PillTone> = {
  // incident states
  signal: 'warn',
  assessing: 'warn',
  reportable: 'danger',
  confirmed: 'danger',
  not_reportable: 'ok',
  dismissed: 'ok',
  closed: 'muted',
  withdrawn: 'muted',
  // scope rows
  pending: 'warn',
  affected: 'danger',
  not_affected: 'ok',
  fixed: 'ok',
  under_investigation: 'warn',
  unknown: 'warn',
  excluded: 'muted',
  not_matched: 'muted',
  present: 'danger',
  absent: 'ok',
  // actions and deliveries
  done: 'ok',
  waived: 'muted',
  pending_approval: 'warn',
  sent: 'info',
  failed: 'danger',
  acknowledged: 'ok',
}

export function statusTone(status: string): PillTone {
  return STATUS_TONES[status] ?? 'muted'
}

export const PILL_CLASSES: Record<PillTone, string> = {
  danger: 'border-danger/40 text-red-300',
  warn: 'border-warn/40 text-amber-300',
  ok: 'border-ok/40 text-green-300',
  info: 'border-sky-500/40 text-sky-300',
  muted: 'border-surface-border text-gray-400',
}

const SIGNAL_SOURCE_LABELS: Record<string, string> = {
  kev: 'KEV',
  euvd: 'EUVD',
  epss: 'EPSS',
  trigger: 'Rule',
  csirt: 'CSIRT',
}

/** "kev" → "KEV", "trigger" → "Rule", others in words. */
export function signalSourceLabel(source: string): string {
  return SIGNAL_SOURCE_LABELS[source] ?? humanize(source)
}

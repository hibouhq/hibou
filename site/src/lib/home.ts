import { nullTime, type HomeAction, type HomeIncident, type IncidentKind, type IncidentPriority } from '@/api/incidents'

export const LAST_VISIT_KEY = 'hibou.home.lastVisit'

const PRIORITY_RANK: Record<IncidentPriority, number> = { P1: 0, P2: 1, P3: 2 }

function priorityRank(priority: string): number {
  return PRIORITY_RANK[priority as IncidentPriority] ?? 3
}

function dueMillis(iso: string | null): number {
  if (!iso) return Number.POSITIVE_INFINITY
  const value = new Date(iso).getTime()
  return Number.isNaN(value) ? Number.POSITIVE_INFINITY : value
}

/** Earliest due first (overdue ones are the earliest), undated last, then priority. */
export function sortByDue<T extends { due_at: HomeAction['due_at']; priority: string }>(rows: readonly T[]): T[] {
  return [...rows].sort((a, b) => {
    const delta = dueMillis(nullTime(a.due_at)) - dueMillis(nullTime(b.due_at))
    if (delta !== 0 && !Number.isNaN(delta)) return delta
    return priorityRank(a.priority) - priorityRank(b.priority)
  })
}

/** Incidents of one kind, or all when kind is empty. */
export function filterByKind(incidents: readonly HomeIncident[], kind: IncidentKind | ''): HomeIncident[] {
  return kind ? incidents.filter((incident) => incident.kind === kind) : [...incidents]
}

/** Count per kind, only the kinds present, in first-seen order. */
export function kindCounts(incidents: readonly HomeIncident[]): { kind: IncidentKind; count: number }[] {
  const counts = new Map<IncidentKind, number>()
  for (const incident of incidents) {
    counts.set(incident.kind, (counts.get(incident.kind) ?? 0) + 1)
  }
  return [...counts].map(([kind, count]) => ({ kind, count }))
}

/** A stored previous visit, if it is a valid instant in the past. */
export function parseLastVisit(raw: string | null, now = Date.now()): string | undefined {
  if (!raw) return undefined
  const value = new Date(raw).getTime()
  if (Number.isNaN(value) || value >= now) return undefined
  return new Date(value).toISOString()
}

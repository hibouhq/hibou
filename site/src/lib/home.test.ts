import { describe, expect, it } from 'vitest'

import type { HomeIncident } from '@/api/incidents'

import { filterByKind, kindCounts, parseLastVisit, sortByDue } from './home'

const due = (iso: string | null) => (iso ? { Time: iso, Valid: true } : { Time: '0001-01-01T00:00:00Z', Valid: false })

describe('sortByDue', () => {
  it('puts overdue first, then nearest due, undated last, priority breaking ties', () => {
    const rows = [
      { id: 'none-p1', due_at: due(null), priority: 'P1' },
      { id: 'later', due_at: due('2026-10-26T00:00:00Z'), priority: 'P1' },
      { id: 'overdue', due_at: due('2026-10-20T00:00:00Z'), priority: 'P3' },
      { id: 'none-p3', due_at: due(null), priority: 'P3' },
      { id: 'soon-p2', due_at: due('2026-10-25T00:00:00Z'), priority: 'P2' },
      { id: 'soon-p1', due_at: due('2026-10-25T00:00:00Z'), priority: 'P1' },
    ]
    expect(sortByDue(rows).map((row) => row.id)).toEqual(['overdue', 'soon-p1', 'soon-p2', 'later', 'none-p1', 'none-p3'])
  })

  it('does not mutate its input', () => {
    const rows = [{ due_at: due('2026-10-26T00:00:00Z'), priority: 'P1' }, { due_at: due('2026-10-20T00:00:00Z'), priority: 'P1' }]
    const copy = [...rows]
    sortByDue(rows)
    expect(rows).toEqual(copy)
  })
})

describe('kind filter', () => {
  const incidents = [
    { kind: 'malware' },
    { kind: 'secret_leak' },
    { kind: 'malware' },
  ] as HomeIncident[]

  it('counts the kinds present', () => {
    expect(kindCounts(incidents)).toEqual([{ kind: 'malware', count: 2 }, { kind: 'secret_leak', count: 1 }])
  })

  it('filters by kind, or keeps all', () => {
    expect(filterByKind(incidents, 'malware')).toHaveLength(2)
    expect(filterByKind(incidents, '')).toHaveLength(3)
  })
})

describe('parseLastVisit', () => {
  const now = new Date('2026-10-24T12:00:00Z').getTime()

  it('accepts a past instant', () => {
    expect(parseLastVisit('2026-10-23T08:00:00.000Z', now)).toBe('2026-10-23T08:00:00.000Z')
  })

  it('rejects missing, invalid and future values', () => {
    expect(parseLastVisit(null, now)).toBeUndefined()
    expect(parseLastVisit('yesterday', now)).toBeUndefined()
    expect(parseLastVisit('2026-10-25T00:00:00Z', now)).toBeUndefined()
  })
})

import { describe, expect, it } from 'vitest'

import type { IncidentAction, IncidentDeadline, Regime } from '@/api/incidents'

import {
  cleanRule,
  clockRows,
  decisionWasProposed,
  detailEntries,
  elapsedText,
  evidenceEntries,
  filingStep,
  fromLocalInput,
  groupActions,
  humanize,
  isExternalRegime,
  pendingNoticeClientIds,
  splitList,
  toLocalInput,
  waiverProposal,
  windowLabel,
} from './incidentView'

function action(overrides: Partial<IncidentAction>): IncidentAction {
  return {
    id: 'a',
    incident_id: 'i',
    kind: 'vex',
    subject_type: 'release',
    subject_id: 'r1',
    label: 'VEX for 1.0',
    automatic: false,
    optional: false,
    obsolete: false,
    due_at: { Time: '', Valid: false },
    state: 'pending',
    assignee_id: null,
    done_at: { Time: '', Valid: false },
    done_by: null,
    evidence: {},
    waived_by: null,
    waived_reason: { String: '', Valid: false },
    created_at: '2026-10-20T00:00:00Z',
    ...overrides,
  }
}

function deadline(regime: string, step: string, due: string): IncidentDeadline {
  return { incident_id: 'i', regime, step, due_at: due, met_at: { Time: '', Valid: false }, reference: '', notified: '' }
}

describe('groupActions', () => {
  it('splits required from optional and hides obsolete actions', () => {
    const groups = groupActions([
      action({ id: '1' }),
      action({ id: '2', optional: true }),
      action({ id: '3', obsolete: true }),
      action({ id: '4', optional: true, obsolete: true }),
    ])
    expect(groups.required.map(entry => entry.id)).toEqual(['1'])
    expect(groups.optional.map(entry => entry.id)).toEqual(['2'])
  })
})

describe('filingStep', () => {
  it('strips the platform prefixes', () => {
    expect(filingStep('srp_early_warning')).toBe('early_warning')
    expect(filingStep('csirt_final_report')).toBe('final_report')
    expect(filingStep('national_fr_initial')).toBe('initial')
  })

  it('asks the regimes first, for national codes holding underscores', () => {
    const regimes: Regime[] = [{
      name: 'national:de_bsi',
      label: 'BSI',
      steps: [{ step: 'first_notice', label: 'First notice', anchor: 'aware', after: '24h', filing: 'national_de_bsi_first_notice' }],
    }]
    expect(filingStep('national_de_bsi_first_notice', regimes)).toBe('first_notice')
  })

  it('returns unknown kinds unchanged', () => {
    expect(filingStep('upstream_notice')).toBe('upstream_notice')
  })
})

describe('clockRows', () => {
  it('pairs regulatory deadlines with the internal target of the same step', () => {
    const rows = clockRows([
      deadline('cra-article-14', 'notification', '2026-10-23T00:00:00Z'),
      deadline('internal', 'early_warning', '2026-10-20T12:00:00Z'),
      deadline('cra-article-14', 'early_warning', '2026-10-21T00:00:00Z'),
      deadline('nis2-article-23', 'early_warning', '2026-10-21T00:00:00Z'),
    ])
    expect(rows.map(row => row.step)).toEqual(['early_warning', 'notification'])
    expect(rows[0].internal?.regime).toBe('internal')
    expect(rows[0].regulatory.map(entry => entry.regime)).toEqual(['cra-article-14', 'nis2-article-23'])
    expect(rows[1].internal).toBeNull()
  })
})

describe('windowLabel', () => {
  it('words step durations like the regulation', () => {
    expect(windowLabel('24h')).toBe('24 h')
    expect(windowLabel('72h')).toBe('72 h')
    expect(windowLabel('336h')).toBe('14 days')
    expect(windowLabel('1mo')).toBe('1 month')
    expect(windowLabel('90m')).toBe('90m')
  })
})

describe('elapsedText', () => {
  const start = '2026-10-23T00:00:00Z'
  const end = '2026-10-24T00:00:00Z'
  it('counts from T0 and stops at the deadline', () => {
    expect(elapsedText(start, end, Date.parse('2026-10-23T22:58:30Z'))).toBe('22h 58m')
    expect(elapsedText(start, end, Date.parse('2026-10-23T00:40:00Z'))).toBe('40m')
    expect(elapsedText(start, end, Date.parse('2026-10-25T06:00:00Z'))).toBe('1d 0h')
  })
})

describe('detailEntries', () => {
  it('puts the readable keys first and flattens values', () => {
    expect(detailEntries({ zeta: 1, reason: 'dup', tags: ['a', 'b'], nested: { x: 1 }, empty: '', label: 'L' })).toEqual([
      ['reason', 'dup'],
      ['label', 'L'],
      ['nested', '{"x":1}'],
      ['tags', 'a, b'],
      ['zeta', '1'],
    ])
  })

  it('handles a missing detail', () => {
    expect(detailEntries(null)).toEqual([])
  })
})

describe('waivers', () => {
  it('reads a pending waiver proposal and keeps it out of the evidence', () => {
    const proposed = action({ evidence: { waiver_proposed_by: 'u1', waiver_reason: 'not shipped', reference: 'X' } })
    expect(waiverProposal(proposed)).toEqual({ by: 'u1', reason: 'not shipped' })
    expect(evidenceEntries(proposed.evidence)).toEqual([['reference', 'X']])
    expect(waiverProposal(action({ state: 'waived', evidence: { waiver_proposed_by: 'u1' } }))).toBeNull()
    expect(waiverProposal(action({}))).toBeNull()
  })
})

describe('pendingNoticeClientIds', () => {
  it('lists each client owed a notice once', () => {
    expect(pendingNoticeClientIds([
      action({ kind: 'client_notice', subject_id: 'c1' }),
      action({ kind: 'client_notice', subject_id: 'c1' }),
      action({ kind: 'client_notice', subject_id: 'c2', state: 'done' }),
      action({ kind: 'client_notice', subject_id: 'c3', obsolete: true }),
      action({ kind: 'vex', subject_id: 'r1' }),
    ])).toEqual(['c1'])
  })
})

describe('decisionWasProposed', () => {
  it('is true when the state stayed and a proposal is recorded', () => {
    expect(decisionWasProposed('assessing', { state: 'assessing', proposed_decision: { state: 'not_reportable' } })).toBe(true)
    expect(decisionWasProposed('assessing', { state: 'not_reportable', proposed_decision: null })).toBe(false)
    expect(decisionWasProposed('assessing', { state: 'assessing', proposed_decision: {} })).toBe(false)
  })
})

describe('rule editing', () => {
  it('splits lists and drops empty rule fields', () => {
    expect(splitList(' default, release/* ,,all')).toEqual(['default', 'release/*', 'all'])
    expect(cleanRule({ match: ' exploited:true ', kind: '', refs: [], regimes: ['internal'], priority: 'P1', due: ' ', source: 'org', locked: true }))
      .toEqual({ match: 'exploited:true', regimes: ['internal'], priority: 'P1' })
  })
})

describe('misc', () => {
  it('humanizes identifiers and tells external regimes apart', () => {
    expect(humanize('early_warning')).toBe('Early warning')
    expect(isExternalRegime('internal')).toBe(false)
    expect(isExternalRegime('national:fr')).toBe(true)
  })

  it('round-trips datetime-local values', () => {
    const local = toLocalInput(new Date(2026, 9, 24, 9, 5))
    expect(local).toBe('2026-10-24T09:05')
    expect(fromLocalInput(local)).toBe(new Date(2026, 9, 24, 9, 5).toISOString())
    expect(fromLocalInput('')).toBeUndefined()
  })
})

describe('detailEntries documents', () => {
  it('renders document lists as kinds and short digests', () => {
    const entries = detailEntries({ documents: [{ kind: 'openvex', sha256: '318c2058f1e0977942263c330dab' }] })
    expect(entries).toEqual([['documents', 'openvex 318c2058f1e0']])
  })
})

import { describe, expect, it } from 'vitest'

import type { FindingAcceptance } from '@/api/client'
import { isAcceptanceActive, reasonPresets, triageDecisionProblem, triageMakesStatement, triageState, type TriageDecisionInput } from './triage'

function acceptance(overrides: Partial<FindingAcceptance> = {}): FindingAcceptance {
  return {
    fingerprint: 'fp',
    reason_kind: 'risk_accepted',
    reason: 'because',
    ...overrides,
  } as FindingAcceptance
}

describe('triageState', () => {
  it('maps the observation status when there is no human decision', () => {
    expect(triageState({ status: 'detected' }).state).toBe('open')
    expect(triageState({ status: 'resolved' }).state).toBe('fixed')
  })

  it('reads scanner-suppressed rows as suppressed, not open', () => {
    const info = triageState({ status: 'suppressed' })
    expect(info.state).toBe('suppressed')
    expect(info.countsAgainstGate).toBe(false)
    expect(info.humanDecision).toBe(false)
  })

  it('reads a disputed suppression as disputed and gating (ADR-026)', () => {
    const info = triageState({ status: 'suppressed' }, null, new Date(), { reason: 'contested' })
    expect(info.state).toBe('disputed')
    expect(info.countsAgainstGate).toBe(true)
    expect(info.humanDecision).toBe(true)
    // A dispute only overrides a suppression — other statuses ignore it.
    expect(triageState({ status: 'detected' }, null, new Date(), { reason: 'contested' }).state).toBe('open')
  })

  it('lets a human decision win over the observation status', () => {
    // The acceptance is fingerprint-keyed and survives snapshots, so it is the
    // durable truth regardless of what the scanner reports.
    expect(triageState({ status: 'detected' }, acceptance()).state).toBe('accepted_risk')
    expect(triageState({ status: 'detected' }, acceptance({ reason_kind: 'false_positive' })).state).toBe('false_positive')
  })

  it('ignores an expired acceptance', () => {
    // Suppression must never outlive its stated window.
    const expired = acceptance({ expires_at: '2020-01-01T00:00:00Z' })
    expect(triageState({ status: 'detected' }, expired).state).toBe('open')
  })

  it('honours an acceptance that has not expired yet', () => {
    const future = acceptance({ expires_at: '2099-01-01T00:00:00Z' })
    expect(triageState({ status: 'detected' }, future).state).toBe('accepted_risk')
  })

  it('treats an unparseable expiry as no expiry rather than silently reopening', () => {
    const bad = acceptance({ expires_at: 'not-a-date' })
    expect(triageState({ status: 'detected' }, bad).state).toBe('accepted_risk')
  })

  it('only open findings count against the gate', () => {
    expect(triageState({ status: 'detected' }).countsAgainstGate).toBe(true)
    expect(triageState({ status: 'detected' }, acceptance()).countsAgainstGate).toBe(false)
    expect(triageState({ status: 'resolved' }).countsAgainstGate).toBe(false)
    expect(triageState({ status: 'suppressed' }).countsAgainstGate).toBe(false)
  })

  it('unknown or empty statuses fall back to open rather than disappearing', () => {
    expect(triageState({ status: '' }).state).toBe('open')
    expect(triageState({ status: 'something-new' }).state).toBe('open')
  })
})

describe('isAcceptanceActive', () => {
  it('is false without an acceptance', () => {
    expect(isAcceptanceActive(null)).toBe(false)
    expect(isAcceptanceActive(undefined)).toBe(false)
  })

  it('is true with no expiry set', () => {
    expect(isAcceptanceActive(acceptance())).toBe(true)
  })

  it('compares against the supplied clock', () => {
    const a = acceptance({ expires_at: '2026-07-28T12:00:00Z' })
    expect(isAcceptanceActive(a, new Date('2026-07-28T11:59:00Z'))).toBe(true)
    expect(isAcceptanceActive(a, new Date('2026-07-28T12:01:00Z'))).toBe(false)
  })
})

describe('triageMakesStatement', () => {
  it('needs a vulnerability identifier on a component', () => {
    expect(triageMakesStatement({ type: 'dependency', advisory_id: 'a' })).toBe(true)
    expect(triageMakesStatement({ type: 'container', advisory_id: 'a' })).toBe(true)
    expect(triageMakesStatement({ type: 'dependency' })).toBe(false)
    expect(triageMakesStatement({ type: 'sast', advisory_id: 'a' })).toBe(false)
    expect(triageMakesStatement({ type: 'secret' })).toBe(false)
    expect(triageMakesStatement(null)).toBe(false)
  })
})

describe('reasonPresets', () => {
  it('offers "not exploitable" as a not-affected preset, never as accepted risk', () => {
    expect(reasonPresets('false_positive', true)).toContain('Not exploitable in this context')
    expect(reasonPresets('risk_accepted', true)).not.toContain('Not exploitable in this context')
    expect(reasonPresets('risk_accepted', false)).not.toContain('Not exploitable in this context')
    expect(reasonPresets('false_positive', false)).toContain('Scanner misidentified the pattern')
  })
})

describe('triageDecisionProblem', () => {
  const base: TriageDecisionInput = {
    kind: 'false_positive',
    statement: true,
    justificationRequired: true,
    justification: '',
    reason: '',
    expiresAt: '',
    expiryRequired: false,
  }

  it('requires the justification of a not-affected statement, not a reason', () => {
    expect(triageDecisionProblem({ ...base, reason: 'detail' })).not.toBe('')
    expect(triageDecisionProblem({ ...base, justification: 'vulnerable_code_not_in_execute_path' })).toBe('')
  })

  it('lets a batch of unknown composition go with a reason alone', () => {
    expect(triageDecisionProblem({ ...base, justificationRequired: false, reason: 'fixture' })).toBe('')
    expect(triageDecisionProblem({ ...base, justificationRequired: false })).not.toBe('')
  })

  it('requires the action statement of an affected decision', () => {
    const affected = { ...base, kind: 'risk_accepted' as const }
    expect(triageDecisionProblem(affected)).toBe('The action statement is required.')
    expect(triageDecisionProblem({ ...affected, reason: 'upgrade next sprint' })).toBe('')
  })

  it('requires an expiry where the caller says so', () => {
    const affected = { ...base, kind: 'risk_accepted' as const, reason: 'waiver', expiryRequired: true }
    expect(triageDecisionProblem(affected)).toBe('An expiry is required.')
    expect(triageDecisionProblem({ ...affected, expiresAt: '2099-01-01' })).toBe('')
  })

  it('keeps the free reason for findings without an identifier', () => {
    const code = { ...base, statement: false, justificationRequired: false }
    expect(triageDecisionProblem(code)).toBe('A reason is required.')
    expect(triageDecisionProblem({ ...code, reason: 'fixture' })).toBe('')
  })
})

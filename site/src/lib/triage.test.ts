import { describe, expect, it } from 'vitest'

import type { FindingAcceptance } from '@/api/client'
import { isAcceptanceActive, triageState } from './triage'

function acceptance(overrides: Partial<FindingAcceptance> = {}): FindingAcceptance {
  return {
    fingerprint: 'fp',
    status: 'accepted',
    reason: 'because',
    ...overrides,
  } as FindingAcceptance
}

describe('triageState', () => {
  it('maps the scanner enum when there is no human decision', () => {
    expect(triageState({ status: 'detected' }).state).toBe('open')
    expect(triageState({ status: 'confirmed' }).state).toBe('confirmed')
    expect(triageState({ status: 'resolved' }).state).toBe('fixed')
  })

  it('reads legacy dismissed rows as accepted risk', () => {
    // Predates the acceptance table; must stay truthful without a migration.
    const info = triageState({ status: 'dismissed' })
    expect(info.state).toBe('accepted_risk')
    expect(info.countsAgainstGate).toBe(false)
  })

  it('lets a human decision win over the scanner enum', () => {
    // The acceptance is fingerprint-keyed and survives snapshots, so it is the
    // durable truth even when the scanner still calls the finding confirmed.
    expect(triageState({ status: 'confirmed' }, acceptance()).state).toBe('accepted_risk')
    expect(triageState({ status: 'detected' }, acceptance({ status: 'false_positive' })).state).toBe('false_positive')
  })

  it('ignores an expired acceptance', () => {
    // Suppression must never outlive its stated window.
    const expired = acceptance({ expires_at: '2020-01-01T00:00:00Z' })
    expect(triageState({ status: 'detected' }, expired).state).toBe('open')
    expect(triageState({ status: 'confirmed' }, expired).state).toBe('confirmed')
  })

  it('honours an acceptance that has not expired yet', () => {
    const future = acceptance({ expires_at: '2099-01-01T00:00:00Z' })
    expect(triageState({ status: 'detected' }, future).state).toBe('accepted_risk')
  })

  it('treats an unparseable expiry as no expiry rather than silently reopening', () => {
    const bad = acceptance({ expires_at: 'not-a-date' })
    expect(triageState({ status: 'detected' }, bad).state).toBe('accepted_risk')
  })

  it('only the suppressed states are exempt from the gate', () => {
    expect(triageState({ status: 'detected' }).countsAgainstGate).toBe(true)
    expect(triageState({ status: 'confirmed' }).countsAgainstGate).toBe(true)
    expect(triageState({ status: 'detected' }, acceptance()).countsAgainstGate).toBe(false)
    expect(triageState({ status: 'resolved' }).countsAgainstGate).toBe(false)
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

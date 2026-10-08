import { describe, expect, it } from 'vitest'

import { sameFilterValues, sameListQueryState, type ListQueryState } from './listQueryState'
import { OPEN_RISK_KEV_QUERY, OPEN_RISK_QUERY } from './openRiskPreset'

const keys = ['type', 'severity', 'status'] as const
const base: ListQueryState = { filters: {}, search: '', q: OPEN_RISK_QUERY, sort: 'severity', order: 'desc', page: 1 }

describe('sameListQueryState', () => {
  it('sees a change between two advanced queries', () => {
    expect(sameListQueryState(keys, base, { ...base, q: OPEN_RISK_KEV_QUERY })).toBe(false)
  })

  it('sees each other part of the state', () => {
    expect(sameListQueryState(keys, base, { ...base })).toBe(true)
    expect(sameListQueryState(keys, base, { ...base, filters: { type: 'sast' } })).toBe(false)
    expect(sameListQueryState(keys, base, { ...base, search: 'openssl' })).toBe(false)
    expect(sameListQueryState(keys, base, { ...base, sort: 'detected' })).toBe(false)
    expect(sameListQueryState(keys, base, { ...base, order: 'asc' })).toBe(false)
    expect(sameListQueryState(keys, base, { ...base, page: 2 })).toBe(false)
  })
})

describe('sameFilterValues', () => {
  it('compares only the given keys and treats missing as empty', () => {
    expect(sameFilterValues(keys, { type: '' }, {})).toBe(true)
    expect(sameFilterValues(keys, { file: 'a' }, {})).toBe(true)
    expect(sameFilterValues(keys, { status: 'detected' }, {})).toBe(false)
  })
})

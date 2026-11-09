import { describe, expect, it } from 'vitest'

import { parseBarQuery } from './filterBarQuery'
import { EXPLOITED_VALUES, RISK_GROUP, riskFilterDefs } from './riskFilters'

const defs = riskFilterDefs()
const byKey = (key: string) => defs.find(filter => filter.key === key)!

describe('riskFilterDefs', () => {
  it('shows the score comparisons under one Risk pill', () => {
    for (const key of ['cvss', 'epss', 'epss-percentile']) {
      expect(byKey(key).hidden).toBeFalsy()
      expect(byKey(key).group).toBe(RISK_GROUP)
    }
  })

  it('keeps fix: and verified: as typed qualifiers', () => {
    expect(byKey('fix').hidden).toBe(true)
    expect(byKey('verified').hidden).toBe(true)
  })

  it('completes and describes fix: and verified:', async () => {
    expect((await byKey('fix').suggestValues!('')).map(item => item.value)).toEqual(['available', 'none'])
    expect((await byKey('fix').suggestValues!('a')).map(item => item.value)).toEqual(['available'])
    expect(byKey('fix').describeValue!('none')?.title).toBe('no fix yet')
    expect((await byKey('verified').suggestValues!('')).map(item => item.value)).toEqual(['true', 'false'])
    expect(byKey('verified').describeValue!('TRUE')?.title).toBe('confirmed live')
    expect(byKey('verified').describeValue!('maybe')).toBeUndefined()
  })

  it('completes incident: as a typed qualifier', async () => {
    expect(byKey('incident').hidden).toBe(true)
    expect(byKey('incident').serverQuery).toBe(true)
    expect((await byKey('incident').suggestValues!('t')).map(item => item.value)).toEqual(['true'])
    expect(byKey('incident').describeValue!('false')?.title).toBe('no incident')
  })

  it('completes exploited: for the views that own its definition', async () => {
    expect((await EXPLOITED_VALUES.suggestValues('f')).map(item => item.value)).toEqual(['false'])
    expect(EXPLOITED_VALUES.describeValue('true')?.title).toBe('known exploited')
  })

  it('sends the new qualifiers server-side and rejects other values', () => {
    expect(parseBarQuery('fix:available verified:true', defs, true).advancedQuery).toBe('fix:available verified:true')
    expect(parseBarQuery('fix:soon', defs, true).issues).toHaveLength(1)
    expect(parseBarQuery('verified:yes', defs, true).issues).toHaveLength(1)
  })
})

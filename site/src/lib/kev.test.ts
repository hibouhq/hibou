import { describe, expect, it } from 'vitest'

import { kevSourceLabel, kevSyncTone } from './kev'

describe('kevSourceLabel', () => {
  it('names the known catalogs', () => {
    expect(kevSourceLabel('cisa')).toBe('CISA KEV')
    expect(kevSourceLabel('euvd')).toBe('ENISA EUVD')
  })

  it('uppercases a source it does not know, so a new backend catalog is never blank', () => {
    expect(kevSourceLabel('vulncheck')).toBe('VULNCHECK')
  })
})

describe('kevSyncTone', () => {
  const now = Date.parse('2026-10-07T12:00:00Z')

  it('is ok within four default intervals (24h) of the last successful sync', () => {
    expect(kevSyncTone({ source: 'cisa', at: '2026-10-07T06:00:00Z' }, undefined, now)).toBe('ok')
  })

  it('is stale after four missed default intervals, or when it never synced', () => {
    expect(kevSyncTone({ source: 'cisa', at: '2026-10-05T06:00:00Z' }, undefined, now)).toBe('stale')
    expect(kevSyncTone({ source: 'euvd' }, undefined, now)).toBe('stale')
  })

  it('judges staleness against the CONFIGURED interval, not a guess', () => {
    // 48h cadence: a two-day-old sync is on schedule, not stale.
    expect(kevSyncTone({ source: 'cisa', at: '2026-10-05T06:00:00Z' }, 48 * 3600, now)).toBe('ok')
    // 1h cadence: six silent hours is six missed passes.
    expect(kevSyncTone({ source: 'cisa', at: '2026-10-07T06:00:00Z' }, 3600, now)).toBe('stale')
  })

  it('reports failing over stale: an error is actionable, staleness is a question', () => {
    expect(kevSyncTone({ source: 'euvd', at: '2026-10-07T06:00:00Z', error: 'page 3 returned status 503' }, undefined, now)).toBe('failing')
  })
})

import { describe, expect, it } from 'vitest'

import { countForMetric, normalizeTrendPoints, trendBounds } from './insights'

describe('repository insights trend adapter', () => {
  it('maps backend-shaped vulns and findings fields into distinct totals', () => {
    const [point] = normalizeTrendPoints([{
      snapshot_id: 'snapshot-1',
      date: '2026-10-01T12:00:00Z',
      commit_sha: 'abc123',
      vulns_critical: 1,
      vulns_high: 2,
      vulns_medium: 3,
      vulns_low: 4,
      vulns_info: 5,
      findings_critical: 6,
      findings_high: 7,
      findings_medium: 8,
      findings_low: 9,
      findings_info: 10,
      components_total: 42,
    }])

    expect(countForMetric(point, 'vulnerabilities')).toBe(15)
    expect(countForMetric(point, 'findings')).toBe(40)
  })

  it('rejects unknown count fields instead of manufacturing a zero observation', () => {
    expect(() => normalizeTrendPoints([{
      snapshot_id: 'snapshot-1',
      date: '2026-10-01T12:00:00Z',
      commit_sha: 'abc123',
      vulns_critical: undefined as unknown as number,
      vulns_high: 0,
      vulns_medium: 0,
      vulns_low: 0,
      vulns_info: 0,
      findings_critical: 0,
      findings_high: 0,
      findings_medium: 0,
      findings_low: 0,
      findings_info: 0,
      components_total: 0,
    }])).toThrow('Observation counts are unavailable or invalid')
  })

  it('sorts irregular timestamps and reports actual observation bounds', () => {
    const points = normalizeTrendPoints([
      { snapshot_id: 'late', date: '2026-10-06T12:00:00Z', commit_sha: 'late', vulns_critical: 0, vulns_high: 0, vulns_medium: 0, vulns_low: 0, vulns_info: 0, findings_critical: 0, findings_high: 0, findings_medium: 0, findings_low: 0, findings_info: 0, components_total: 8 },
      { snapshot_id: 'early', date: '2026-09-01T12:00:00Z', commit_sha: 'early', vulns_critical: 0, vulns_high: 0, vulns_medium: 0, vulns_low: 0, vulns_info: 0, findings_critical: 0, findings_high: 0, findings_medium: 0, findings_low: 0, findings_info: 0, components_total: 6 },
    ])

    expect(points.map((point) => point.snapshot_id)).toEqual(['early', 'late'])
    expect(trendBounds(points)).toEqual({ start: new Date('2026-09-01T12:00:00Z'), end: new Date('2026-10-06T12:00:00Z') })
  })
})
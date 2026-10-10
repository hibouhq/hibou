import { describe, expect, it } from 'vitest'

import type { FindingRating } from '@/api/client'
import { cvssBand, formatEPSS, formatPercentile, ratingsSummary, vectorDifferences } from '@/lib/riskMetrics'

const redhat: FindingRating = { rater: 'redhat', provider: 'trivy', version: 'v3.1', vector: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N', score: 4.7, label: 'low', severity: 'low', used: true }
const julia: FindingRating = { rater: 'julia', provider: 'trivy', version: 'v3.1', vector: 'CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L', score: 4.1, severity: 'medium' }

describe('risk metrics display', () => {
  it('bands scores like FIRST', () => {
    expect([9, 7, 4, 0.1, 0].map(cvssBand)).toEqual(['critical', 'high', 'medium', 'low', 'none'])
  })

  it('formats EPSS and percentiles', () => {
    expect(formatEPSS(0.89398)).toBe('89.4%')
    expect(formatEPSS(0.00043)).toBe('0.043%')
    expect(formatPercentile(0.998)).toBe('99.8th')
    expect(formatPercentile(0.91)).toBe('91st')
    expect(formatPercentile(0.12)).toBe('12th')
  })

  it('names the metrics where two vectors differ', () => {
    expect(vectorDifferences(redhat, julia)).toEqual(['AV:P', 'AC:L', 'C:L', 'I:L', 'A:L'])
    expect(vectorDifferences(redhat, redhat)).toEqual([])
    expect(vectorDifferences(redhat, { ...julia, version: 'v4.0' })).toEqual([])
  })

  it('summarizes who rated what, the used rating marked', () => {
    expect(ratingsSummary([julia, redhat])).toBe('Julia: medium 4.1\n▸ Red Hat: low 4.7')
  })
})

import { describe, expect, it } from 'vitest'

import type { ProducerCoverage } from '@/api/client'
import { bundleFreshness, detailLine, dotClass, stateLabel } from './scanCoverage'

function producer(overrides: Partial<ProducerCoverage>): ProducerCoverage {
  return {
    producer: 'gosec', status: 'ran', outcome: 'completed', scope: 'full', scope_declared: true,
    scope_paths: [], finding_count: 0, skipped_files: [], runs: [], ...overrides,
  }
}

describe('scanCoverage', () => {
  it('flags a missing producer and a partial run as warnings', () => {
    expect(stateLabel(producer({ status: 'missing', outcome: undefined }))).toBe('Missing')
    expect(dotClass(producer({ status: 'missing', outcome: undefined }))).toBe('bg-warning')
    expect(dotClass(producer({ outcome: 'partial' }))).toBe('bg-warning')
    expect(dotClass(producer({ outcome: 'failed' }))).toBe('bg-danger')
    expect(stateLabel(producer({ status: 'new', outcome: 'partial' }))).toBe('Partial · new')
  })

  it('says when a full scope is only assumed and shows version changes', () => {
    expect(detailLine(producer({ scope_declared: false, version: '2.22.0', finding_count: 1 })))
      .toBe('2.22.0 · full (assumed) · 1 result')
    expect(detailLine(producer({ version: '2.22.0', previous_version: '2.21.0', scope: 'partial', scope_paths: ['a', 'b'], finding_count: 3 })))
      .toBe('2.21.0 → 2.22.0 · partial (2 paths) · 3 results')
  })
})

describe('bundleFreshness', () => {
  const now = new Date('2026-10-10T00:00:00Z').getTime()
  it('judges the bundle against the strictest freshness requirement', () => {
    const result = bundleFreshness({ created_at: '2026-09-01T00:00:00Z', matches_catalog: true }, [0, 60, 30], now)
    expect(result.ageDays).toBe(39)
    expect(result.maxDays).toBe(30)
    expect(result.stale).toBe(true)
  })
  it('is fresh without a policy, and stale on a catalog mismatch', () => {
    expect(bundleFreshness({ created_at: '2026-01-01T00:00:00Z', matches_catalog: true }, [0], now).stale).toBe(false)
    expect(bundleFreshness({ created_at: '2026-10-09T00:00:00Z', matches_catalog: false }, [30], now).problems).toHaveLength(1)
  })
  it('reports a missing manifest', () => {
    const result = bundleFreshness({ matches_catalog: false, error: 'no imported bundle manifest' }, [30], now)
    expect(result.problems).toEqual(['no imported bundle manifest'])
  })
})

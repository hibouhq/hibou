import { describe, expect, it } from 'vitest'

import { parseBarQuery } from './filterBarQuery'
import { OPEN_RISK_QUERY, migrateRiskOnlyQuery } from './openRiskPreset'

const filters = [
  { key: 'status', label: 'Status', options: ['detected', 'resolved', 'suppressed'], multi: true, hidden: true, defaultValue: 'detected' },
  { key: 'type', label: 'Type', options: ['dependency', 'sast', 'container', 'malware'], multi: true },
  { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'], multi: true },
  { key: 'acceptance', label: 'Triage', options: ['open', 'accepted', 'risk_accepted', 'false_positive', 'disputed'] },
  { key: 'tool', label: 'Sources', options: ['trivy', 'semgrep'], multi: true },
  { key: 'exploited', label: 'Exploited', options: ['true', 'false'] },
]

describe('migrateRiskOnlyQuery', () => {
  it('replaces legacy scope with a visible query and preserves navigation state', () => {
    expect(migrateRiskOnlyQuery({
      risk_only: 'true',
      ref: 'main',
      snapshot: 'snapshot-123',
      type: 'dependency',
      search: 'openssl',
      sort: 'severity',
      order: 'asc',
      page: '2',
    }, filters)).toEqual({
      ref: 'main',
      snapshot: 'snapshot-123',
      sort: 'severity',
      order: 'asc',
      page: '2',
      q: `(${OPEN_RISK_QUERY}) AND (type:dependency openssl)`,
    })
  })

  it('preserves an existing advanced query inside the visible preset', () => {
    expect(migrateRiskOnlyQuery({
      risk_only: 'true',
      q: '(severity:critical OR severity:high)',
    }, filters)).toEqual({
      q: `(${OPEN_RISK_QUERY}) AND ((severity:critical OR severity:high))`,
    })
  })

  it('keeps an explicit legacy status restriction even when it equals the hidden default', () => {
    expect(migrateRiskOnlyQuery({ risk_only: 'true', status: 'detected' }, filters)).toEqual({
      q: `(${OPEN_RISK_QUERY}) AND (status:detected)`,
    })
  })

  it('does not inject a default status that would drop disputed suppressions', () => {
    expect(migrateRiskOnlyQuery({ risk_only: 'true' }, filters)).toEqual({ q: `(${OPEN_RISK_QUERY})` })
  })

  it('is idempotent once the legacy flag is gone', () => {
    const migrated = migrateRiskOnlyQuery({ risk_only: 'true', type: 'dependency', exploited: 'true' }, filters)
    expect(migrated.risk_only).toBeUndefined()
    expect(migrateRiskOnlyQuery(migrated, filters)).toEqual(migrated)
  })

  it('produces a query the bar accepts without issues', () => {
    const migrated = migrateRiskOnlyQuery({ risk_only: 'true', status: 'detected', severity: 'critical,high', search: 'openssl' }, filters)
    expect(parseBarQuery(String(migrated.q), filters, true).issues).toEqual([])
  })
})

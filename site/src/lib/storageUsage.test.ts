import { describe, expect, it } from 'vitest'

import type { InstanceStorage } from '@/api/client'

import { backendDrift, formatBytes, formatInterval, isBloated, storageChecks } from './storageUsage'

const NOW = Date.parse('2026-10-10T12:00:00Z')

function storage(overrides: Partial<InstanceStorage> = {}): InstanceStorage {
  return {
    enabled: true,
    interval_seconds: 900,
    inventory_enabled: true,
    inventory_interval_seconds: 86400,
    artifact_backend: 'filesystem',
    metrics_exposure: 'dedicated_port',
    sample: {
      postgres: {
        collected_at: '2026-10-10T11:55:00Z', duration_seconds: 0.1, database_bytes: 1e9, tables: [],
        connections_used: 10, connections_max: 100, xid_age: 1_000_000,
      },
      ledger: { collected_at: '2026-10-10T11:55:00Z', duration_seconds: 0.01, kinds: [{ kind: 'sbom', objects: 10, bytes: 100 * 1024 * 1024 }] },
      backend: {
        collected_at: '2026-10-10T06:00:00Z', duration_seconds: 2, objects: 10, bytes: 100 * 1024 * 1024, truncated: false,
        volume_capacity_bytes: 1000, volume_free_bytes: 500,
      },
    },
    ...overrides,
  }
}

describe('formatBytes', () => {
  it('uses binary units with sensible precision', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1536)).toBe('1.50 KB')
    expect(formatBytes(714208959)).toBe('681 MB')
    expect(formatBytes(undefined)).toBe('—')
  })
})

describe('formatInterval', () => {
  it('prints configured intervals the way they were written', () => {
    expect(formatInterval(900)).toBe('15m')
    expect(formatInterval(86400)).toBe('1d')
    expect(formatInterval(5400)).toBe('1h 30m')
  })
})

describe('storageChecks', () => {
  it('is quiet for a healthy instance', () => {
    expect(storageChecks(storage(), NOW)).toEqual([])
  })

  it('flags public metrics even before the first sample', () => {
    const checks = storageChecks(storage({ metrics_exposure: 'public', sample: null }), NOW)
    expect(checks.map(c => c.title)).toEqual(['/metrics is public'])
  })

  it('flags a stale sample, failed sources and database pressure', () => {
    const s = storage()
    s.sample!.postgres = { ...s.sample!.postgres!, collected_at: '2026-10-10T10:00:00Z', xid_age: 1_200_000_000, connections_used: 90, oldest_transaction_seconds: 7200 }
    s.sample!.ledger = { ...s.sample!.ledger!, collected_at: '2026-10-10T10:00:00Z' }
    s.sample!.backend = { ...s.sample!.backend!, error: 'access denied' }
    const checks = storageChecks(s, NOW)
    expect(checks.map(c => c.title)).toEqual([
      'Backend inventory sample failed',
      'Sample is stale',
      'Transaction-ID age is high',
      'Connections near the limit',
      'Long-running transaction',
    ])
    expect(checks.find(c => c.title === 'Transaction-ID age is high')?.level).toBe('danger')
  })

  it('reports orphans and missing objects, not noise', () => {
    const s = storage()
    s.sample!.backend!.bytes += 1024 // 1 KB over: below the threshold
    expect(storageChecks(s, NOW)).toEqual([])
    s.sample!.backend!.bytes += 50 * 1024 * 1024
    expect(storageChecks(s, NOW).map(c => c.title)).toEqual(['Orphaned artifacts'])
    s.sample!.backend!.bytes = 0
    expect(storageChecks(s, NOW).map(c => c.title)).toEqual(['Missing artifacts'])
  })

  it('does not compare a truncated inventory', () => {
    const s = storage()
    s.sample!.backend = { ...s.sample!.backend!, truncated: true, bytes: 1 }
    expect(backendDrift(s)).toBeNull()
  })

  it('flags an almost full volume', () => {
    const s = storage()
    s.sample!.backend!.volume_free_bytes = 30
    expect(storageChecks(s, NOW)).toMatchObject([{ title: 'Artifact volume almost full', level: 'danger' }])
  })
})

describe('isBloated', () => {
  it('needs both volume and share of dead rows', () => {
    const base = { name: 't', table_bytes: 0, index_bytes: 0 }
    expect(isBloated({ ...base, live_rows: 100, dead_rows: 5_000 })).toBe(false)
    expect(isBloated({ ...base, live_rows: 1_000_000, dead_rows: 50_000 })).toBe(false)
    expect(isBloated({ ...base, live_rows: 100_000, dead_rows: 50_000 })).toBe(true)
  })
})

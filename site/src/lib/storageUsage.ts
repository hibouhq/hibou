// ADR-039 storage page helpers: formatting and the health checks behind the
// warning banners. Pure functions so the thresholds are unit-tested.

import type { InstanceStorage, StorageTableUsage } from '@/api/client'

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

// Binary units, labelled the way people read disk sizes: "1.5 GB".
export function formatBytes(bytes: number | undefined) {
  if (bytes === undefined || !Number.isFinite(bytes) || bytes < 0) {
    return '—'
  }
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit++
  }
  const digits = unit === 0 || value >= 100 ? 0 : value >= 10 ? 1 : 2
  return `${value.toFixed(digits)} ${UNITS[unit]}`
}

// Configured intervals are round durations: "15m", "24h", "1h 30m".
export function formatInterval(seconds: number) {
  const units: [number, string][] = [[86400, 'd'], [3600, 'h'], [60, 'm'], [1, 's']]
  const parts: string[] = []
  let rest = Math.round(seconds)
  for (const [size, label] of units) {
    if (rest >= size) {
      parts.push(`${Math.floor(rest / size)}${label}`)
      rest %= size
    }
  }
  return parts.join(' ') || '0s'
}

export function formatCount(n: number) {
  return new Intl.NumberFormat('en', { notation: n >= 100_000 ? 'compact' : 'standard', maximumFractionDigits: 1 }).format(n)
}

export function tableTotal(t: StorageTableUsage) {
  return t.table_bytes + t.index_bytes
}

// Thresholds, named so the page and the tests read the same numbers.
export const XID_AGE_WARN = 200_000_000 // autovacuum_freeze_max_age default
export const XID_AGE_DANGER = 1_000_000_000 // half-way to the 2^31 wraparound stop
export const CONNECTIONS_WARN_RATIO = 0.8
export const VOLUME_FREE_WARN_RATIO = 0.15
export const VOLUME_FREE_DANGER_RATIO = 0.05
export const OLDEST_TX_WARN_SECONDS = 3600
export const DRIFT_MIN_BYTES = 1024 * 1024
export const DRIFT_MIN_RATIO = 0.05
export const BLOAT_MIN_DEAD_ROWS = 10_000
export const BLOAT_DEAD_RATIO = 0.2

// Dead tuples worth an autovacuum look: many in absolute terms and a large
// share of the live ones.
export function isBloated(t: StorageTableUsage) {
  return t.dead_rows >= BLOAT_MIN_DEAD_ROWS && t.dead_rows > t.live_rows * BLOAT_DEAD_RATIO
}

export interface StorageCheck {
  level: 'warn' | 'danger'
  title: string
  detail: string
}

export function ledgerTotals(storage: InstanceStorage) {
  const kinds = storage.sample?.ledger?.kinds ?? []
  return {
    objects: kinds.reduce((sum, k) => sum + k.objects, 0),
    bytes: kinds.reduce((sum, k) => sum + k.bytes, 0),
  }
}

// Bytes in the backend minus bytes the ledger expects: positive means
// orphans, negative means missing objects. Null when not comparable.
export function backendDrift(storage: InstanceStorage) {
  const backend = storage.sample?.backend
  const ledger = storage.sample?.ledger
  if (!backend || backend.error || backend.truncated || !ledger || ledger.error) {
    return null
  }
  return backend.bytes - ledgerTotals(storage).bytes
}

export function storageChecks(storage: InstanceStorage, nowMs: number): StorageCheck[] {
  const checks: StorageCheck[] = []
  const sample = storage.sample
  if (storage.metrics_exposure === 'public') {
    checks.push({
      level: 'warn',
      title: '/metrics is public',
      detail: 'It is served on the application port without a token. Set metrics.port or metrics.bearer_token.',
    })
  }
  if (!sample) {
    return checks
  }

  const sources = [
    ['Postgres', sample.postgres],
    ['Artifact ledger', sample.ledger],
    ['Backend inventory', sample.backend],
  ] as const
  for (const [label, section] of sources) {
    if (section?.error) {
      checks.push({ level: 'danger', title: `${label} sample failed`, detail: section.error })
    }
  }
  const newest = Math.max(...[sample.postgres, sample.ledger].filter(Boolean).map(s => new Date(s!.collected_at).getTime()))
  if (Number.isFinite(newest) && nowMs - newest > 3 * storage.interval_seconds * 1000) {
    checks.push({
      level: 'warn',
      title: 'Sample is stale',
      detail: 'The sampler has not refreshed for over three intervals. Check the server logs for "storage usage".',
    })
  }

  const pg = sample.postgres
  if (pg && !pg.error) {
    if (pg.xid_age >= XID_AGE_WARN) {
      checks.push({
        level: pg.xid_age >= XID_AGE_DANGER ? 'danger' : 'warn',
        title: 'Transaction-ID age is high',
        detail: `${formatCount(pg.xid_age)} transactions since the last freeze. Postgres stops accepting writes near 2.1 billion; check that autovacuum keeps up.`,
      })
    }
    if (pg.connections_max > 0 && pg.connections_used / pg.connections_max >= CONNECTIONS_WARN_RATIO) {
      checks.push({
        level: 'warn',
        title: 'Connections near the limit',
        detail: `${pg.connections_used} of ${pg.connections_max} connections in use.`,
      })
    }
    if ((pg.oldest_transaction_seconds ?? 0) >= OLDEST_TX_WARN_SECONDS) {
      checks.push({
        level: 'warn',
        title: 'Long-running transaction',
        detail: 'A transaction has been open for over an hour; it keeps vacuum from reclaiming dead rows.',
      })
    }
  }

  const backend = sample.backend
  if (backend && !backend.error && backend.volume_capacity_bytes && backend.volume_free_bytes !== undefined) {
    const free = backend.volume_free_bytes / backend.volume_capacity_bytes
    if (free < VOLUME_FREE_WARN_RATIO) {
      checks.push({
        level: free < VOLUME_FREE_DANGER_RATIO ? 'danger' : 'warn',
        title: 'Artifact volume almost full',
        detail: `${formatBytes(backend.volume_free_bytes)} free of ${formatBytes(backend.volume_capacity_bytes)}.`,
      })
    }
  }

  const drift = backendDrift(storage)
  if (drift !== null) {
    const expected = ledgerTotals(storage).bytes
    if (Math.abs(drift) >= Math.max(DRIFT_MIN_BYTES, expected * DRIFT_MIN_RATIO)) {
      checks.push(drift > 0
        ? { level: 'warn', title: 'Orphaned artifacts', detail: `The backend holds ${formatBytes(drift)} more than hibou recorded: objects left by failed deletes or uploads.` }
        : { level: 'warn', title: 'Missing artifacts', detail: `The backend holds ${formatBytes(-drift)} less than hibou recorded: objects deleted or a misconfigured path.` })
    }
  }
  return checks
}
